package com.ant.emichaosbg

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.*
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.abs

/**
 * CELLULAR SECURITY POSTURE + ROOTLESS IMSI-CATCHER HEURISTICS.
 *
 * Ports the parts of PrivacyCell, AIMSICD and SnoopSnitch that can be done WITHOUT root, and
 * is explicit about the parts that cannot.
 *
 * WHAT THE ORIGINALS NEED, AND WHY THIS IS A LESSER FORM.
 *   - SnoopSnitch reads the Qualcomm DIAG interface to see the actual baseband message flow:
 *     cipher/integrity algorithm actually negotiated, silent-SMS/paging behaviour, IMSI
 *     paging. That needs root AND a Qualcomm chipset AND a diag-capable ROM. There is no
 *     rootless substitute — no public Android API exposes the negotiated cipher.
 *   - AIMSICD declares ACCESS_SUPERUSER, but its most useful detections are derived from the
 *     cell lists any app can read. Those are ported here in full.
 *   - PrivacyCell is READ_PHONE_STATE only and is ported completely.
 *
 * So: the RAT-level security posture and the cell-behaviour heuristics are real here. The
 * baseband-level cipher inspection is not, and the readout says so rather than implying a
 * confidence it cannot have.
 *
 * EVERY CHECK IS A HEURISTIC AND IS WORDED AS ONE. Legitimate networks produce every pattern
 * below: rural macro cells genuinely have no neighbours, tracking-area boundaries genuinely
 * cause TAC changes while stationary, femtocells and repeaters genuinely out-signal macro
 * cells, and 2G fallback genuinely happens where there is no other coverage. A single flag is
 * a reason to look, never a conclusion. That is why they are scored rather than asserted.
 *
 * SAFETY, unchanged: nothing here transmits, forces a band, or touches radio configuration.
 * Automatic band or RAT switching is deliberately absent — dropping a phone off 2G at the
 * wrong moment can cost an emergency call, which is a worse outcome than being surveilled.
 * Everything reports.
 */
class CellSecurity(private val ctx: Context, private val log: SecureLog) {

    private data class Seen(val cid: Long, val area: Int, val gen: Int, val dbm: Int, val t: Long)

    private var last: Seen? = null
    private var lastNeighbourCount = -1
    private var noNeighbourRuns = 0
    private val areaHistory = ArrayList<Int>()
    private val raised = HashMap<String, Long>()
    private val COALESCE_MS = 5 * 60_000L
    private var lastReport: JSONObject? = null

    private fun flag(sev: Int, key: String, what: String) {
        val now = System.currentTimeMillis()
        val prev = raised[key]
        if (prev != null && now - prev < COALESCE_MS) return
        raised[key] = now
        try { log.append(sev, what, "cell-sec", "native") } catch (_: Throwable) {}
    }

    @Synchronized
    fun scan(): String {
        val o = JSONObject()
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.READ_PHONE_STATE)
            != PackageManager.PERMISSION_GRANTED) {
            return o.put("ok", false).put("reason", "READ_PHONE_STATE not granted").toString()
        }
        val base = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            ?: return o.put("ok", false).put("reason", "no TelephonyManager").toString()

        /* MULTI-SIM AND eSIM. The default TelephonyManager reports ONE subscription — whichever
           the platform considers default for data. On a phone with a physical SIM and an eSIM,
           or two eSIM profiles, that means an entire second radio was invisible here: a
           downgrade or a catcher on the other subscription would not have been seen at all.
           eSIMs make that the common case rather than an edge one.

           So every active subscription is enumerated and reported, and the SECURITY VERDICT is
           taken from the WEAKEST of them. If either radio is sitting on 2G you are reachable
           over 2G, and reporting the better one would be a comfortable lie. */
        val sims = JSONArray()
        var weakestGen = Int.MAX_VALUE
        var weakestTm: TelephonyManager = base
        try {
            val sm = ctx.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE)
                as? android.telephony.SubscriptionManager
            @Suppress("MissingPermission")
            val subs = sm?.activeSubscriptionInfoList ?: emptyList()
            for (si in subs) {
                val stm = try { base.createForSubscriptionId(si.subscriptionId) } catch (_: Throwable) { null }
                    ?: continue
                val gen = try { ratOf(stm) } catch (_: Throwable) { 0 }
                val embedded = try { si.isEmbedded } catch (_: Throwable) { false }
                sims.put(JSONObject()
                    .put("slot", si.simSlotIndex)
                    .put("subId", si.subscriptionId)
                    .put("carrier", si.carrierName?.toString() ?: "")
                    .put("embedded", embedded)          // true = eSIM profile
                    .put("gen", gen)
                    .put("kind", if (embedded) "eSIM" else "physical"))
                if (gen in 1 until weakestGen) { weakestGen = gen; weakestTm = stm }
            }
        } catch (_: SecurityException) {
        } catch (_: Throwable) {}
        o.put("sims", sims)
        o.put("simCount", sims.length())
        o.put("esimCount", (0 until sims.length()).count { sims.optJSONObject(it)?.optBoolean("embedded") == true })
        if (sims.length() > 1) o.put("multiSimNote",
            "This device has ${sims.length()} active subscriptions. The verdict below describes " +
            "the WEAKEST of them, because you are reachable over whichever radio is least " +
            "protected — reporting the better one would be a comfortable lie.")

        // Analyse the weakest subscription; falls back to the default when enumeration is
        // unavailable (no permission, or a single-SIM device).
        val tm = weakestTm
        val cells = try { tm.allCellInfo ?: emptyList() } catch (_: SecurityException) { emptyList() }
            catch (_: Throwable) { emptyList() }
        o.put("cellCount", cells.size)

        var regGen = 0; var regCid = -1L; var regArea = -1; var regDbm = Int.MIN_VALUE
        var regDesc = "unknown"
        val neighbours = ArrayList<Int>()          // dBm of non-registered cells
        val list = JSONArray()

        for (c in cells) {
            val reg = c.isRegistered
            var gen = 0; var cid = -1L; var area = -1; var dbm = Int.MIN_VALUE; var kind = "?"
            when (c) {
                is CellInfoGsm -> { gen = 2; kind = "GSM"
                    cid = c.cellIdentity.cid.toLong(); area = c.cellIdentity.lac; dbm = c.cellSignalStrength.dbm }
                is CellInfoWcdma -> { gen = 3; kind = "WCDMA"
                    cid = c.cellIdentity.cid.toLong(); area = c.cellIdentity.lac; dbm = c.cellSignalStrength.dbm }
                is CellInfoLte -> { gen = 4; kind = "LTE"
                    cid = c.cellIdentity.ci.toLong(); area = c.cellIdentity.tac; dbm = c.cellSignalStrength.dbm }
                else -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && c is CellInfoNr) {
                        gen = 5; kind = "NR"
                        val id = c.cellIdentity as? CellIdentityNr
                        cid = id?.nci ?: -1L; area = id?.tac ?: -1
                        dbm = c.cellSignalStrength.dbm
                    }
                }
            }
            if (gen == 0) continue
            list.put(JSONObject().put("kind", kind).put("gen", gen).put("registered", reg)
                .put("cid", cid).put("area", area).put("dbm", dbm))
            if (reg) { regGen = gen; regCid = cid; regArea = area; regDbm = dbm; regDesc = kind }
            else if (dbm != Int.MIN_VALUE && dbm > -200) neighbours.add(dbm)
        }
        o.put("cells", list)
        o.put("registered", JSONObject().put("gen", regGen).put("kind", regDesc)
            .put("cid", regCid).put("area", regArea).put("dbm", regDbm))
        o.put("neighbourCount", neighbours.size)

        // ---- 1. PrivacyCell: is this connection meaningfully encrypted? -------------------
        // Reported from the RAT, which is the honest limit of a rootless check: Android
        // exposes no API for the cipher actually negotiated, so this describes what the
        // GENERATION can offer, not what the baseband agreed to.
        val sec = when (regGen) {
            2 -> "insecure"
            3 -> "weak"
            4 -> "ok"
            5 -> "ok"
            else -> "unknown"
        }
        o.put("security", sec)
        o.put("securityNote", when (regGen) {
            2 -> "2G. GSM encryption is A5/1 (broken in practice) or A5/0 (none at all), and 2G " +
                 "does not authenticate the network to the phone — the handset cannot tell a real " +
                 "tower from a fake one. Calls and SMS on this connection should be treated as " +
                 "interceptable."
            3 -> "3G. Mutual authentication exists, but KASUMI/A5/3 is weakened and 3G is commonly " +
                 "the fallback a downgrade attack aims for once 4G is jammed."
            4 -> "4G/LTE. Mutual authentication and modern ciphers. Note that IMSI catchers can " +
                 "still force a downgrade from here, which is what the downgrade check watches for."
            5 -> "5G. Strongest available; on non-standalone deployments the control plane is still " +
                 "anchored on LTE, so the LTE caveats apply to signalling."
            else -> "No registered cell — airplane mode, no coverage, or the radio is between cells."
        })
        if (regGen == 2) flag(3, "gen2",
            "Connected on 2G. GSM encryption is A5/1 (broken) or A5/0 (none), and 2G does not " +
            "authenticate the network to the handset — the phone cannot tell a real tower from a " +
            "fake one. Treat calls and SMS on this connection as interceptable. Not switched " +
            "automatically: forcing a band change can cost an emergency call.")

        // ---- 2. AIMSICD: neighbour-cell disappearance ------------------------------------
        // A real macro cell hands the phone a neighbour list so it can hand over. Many IMSI
        // catchers present none, because they have no network behind them to hand over to.
        // Rural single-cell coverage produces the same reading, hence "runs" rather than a
        // single sample, and hence severity 2 rather than 3.
        if (regGen > 0) {
            if (neighbours.isEmpty()) noNeighbourRuns++ else noNeighbourRuns = 0
            if (noNeighbourRuns >= 3) flag(2, "no-neighbours",
                "The serving cell has reported no neighbouring cells on $noNeighbourRuns " +
                "consecutive checks. Real macro cells advertise neighbours so the phone can hand " +
                "over; a cell with none may have no network behind it. Rural single-cell coverage " +
                "and indoor femtocells look identical, so this is a prompt to look, not a verdict.")
        }
        o.put("noNeighbourRuns", noNeighbourRuns)

        // ---- 3. AIMSICD: serving cell far stronger than every neighbour -------------------
        // Cell selection follows signal strength, so a catcher has to out-shout the real
        // network to capture handsets. A serving cell dominating the neighbour distribution by
        // a wide margin is the observable side of that.
        if (regDbm != Int.MIN_VALUE && neighbours.size >= 2) {
            val best = neighbours.max()
            val margin = regDbm - best
            o.put("dominanceDb", margin)
            if (margin >= 25) flag(2, "dominant-cell",
                "The serving cell is ${margin}dB stronger than the best neighbouring cell. Handsets " +
                "pick the loudest tower, so a device trying to capture phones has to dominate the " +
                "real network — this is what that looks like from the handset. A femtocell, a " +
                "repeater, or simply standing at the foot of a mast produce the same reading.")
        }

        // ---- 4. AIMSICD: area code churn -------------------------------------------------
        // LAC/TAC identifies a tracking area. It changing repeatedly while the cell identity
        // does not, or oscillating between a small set of values, is inconsistent with normal
        // mobility and is a documented catcher signature.
        val prev = last
        if (prev != null && regCid > 0 && regArea > 0) {
            if (regCid == prev.cid && regArea != prev.area) flag(3, "area-flip",
                "The tracking area code changed from ${prev.area} to $regArea while the cell " +
                "identity stayed the same ($regCid). A cell does not normally change which " +
                "tracking area it belongs to. This is one of the signatures an IMSI catcher " +
                "produces when it clones a cell identity but not its area.")
            if (regArea != prev.area) {
                areaHistory.add(regArea)
                if (areaHistory.size > 12) areaHistory.removeAt(0)
                val distinct = areaHistory.toSet().size
                if (areaHistory.size >= 8 && distinct <= 2) flag(2, "area-churn",
                    "The tracking area has flipped between only $distinct values across " +
                    "${areaHistory.size} changes. Oscillating between two areas is not what normal " +
                    "movement looks like; it is what a device competing with a real cell for the " +
                    "handset looks like. Standing on a tracking-area boundary does it too.")
            }
            // Generation downgrade on the same operator is the classic catcher move: force the
            // phone off 4G so the weaker 2G/3G security applies.
            if (regGen in 1..3 && prev.gen >= 4) flag(3, "downgrade",
                "The connection dropped from ${prev.gen}G to ${regGen}G. Forcing a handset down to " +
                "a generation with weaker or absent network authentication is the standard way an " +
                "interception device gets a phone onto equipment it controls. Poor coverage causes " +
                "the same drop, so check whether you have simply moved somewhere with less signal.")
        }
        if (regGen > 0) last = Seen(regCid, regArea, regGen, regDbm, System.currentTimeMillis())

        // ---- What a rootless check CANNOT see. Stated, not implied. -----------------------
        o.put("limits", JSONArray(listOf(
            "The cipher actually negotiated with the tower is not exposed by any public Android " +
            "API. Only the generation's capability is reported here, not what the baseband agreed.",
            "Silent SMS and paging-level behaviour need baseband diagnostics (Qualcomm DIAG), " +
            "which requires root and a diag-capable ROM.",
            "Every check above is a heuristic with legitimate causes. Treat a flag as a reason to " +
            "look, not as a detection."
        )))
        o.put("checkedAt", System.currentTimeMillis())
        lastReport = o
        return o.toString()
    }

    /** Registered-cell generation for ONE subscription, so each SIM is judged on its own radio. */
    private fun ratOf(tm: TelephonyManager): Int {
        val cells = try { tm.allCellInfo ?: emptyList() } catch (_: Throwable) { emptyList() }
        for (c in cells) {
            if (!c.isRegistered) continue
            return when {
                c is CellInfoGsm -> 2
                c is CellInfoWcdma -> 3
                c is CellInfoLte -> 4
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && c is CellInfoNr -> 5
                else -> 0
            }
        }
        return 0
    }

    fun cached(): String = (lastReport ?: JSONObject().put("ok", false).put("reason", "not yet run")).toString()
}
