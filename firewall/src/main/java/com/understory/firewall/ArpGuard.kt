package com.understory.firewall

import android.content.Context
import android.net.ConnectivityManager
import android.net.RouteInfo
import android.net.wifi.WifiManager
import com.understory.elevation.Elevation
import com.understory.elevation.NotElevated
import com.understory.security.Diagnostics
import org.json.JSONObject
import java.net.Inet4Address

/**
 * ARP-spoof DETECTION (design-v2/firewall.md companion-first, observe + warn).
 *
 * Reads the kernel neighbor / ARP table via the OPTIONAL Shizuku shell and looks
 * for the classic man-in-the-middle tells: the default gateway's MAC changing out
 * from under a saved baseline, one MAC bound to several IPs (ARP duplication), or a
 * bogus (zero / broadcast / multicast) gateway MAC.
 *
 * HONESTY / DOCTRINE (hard):
 *  - This DETECTS and WARNS. It CANNOT prevent ARP spoofing — Android gives a
 *    normal app no way to pin an ARP entry or drop a forged frame. Never claim
 *    prevention anywhere.
 *  - Reading the neighbor table needs the optional Shizuku grant: on Android 10+
 *    a normal app cannot read `/proc/net/arp` or `ip neigh`. Without the grant we
 *    return [ScanResult.NeedsElevation] — never throw to the UI, never a dead
 *    control, never a false "all clear".
 *  - The gateway IP is found ROOTLESSLY (ConnectivityManager LinkProperties, or
 *    DhcpInfo as a fallback) so we know which neighbor row is the gateway even
 *    before any shell runs.
 *  - The IP→MAC baseline lives in the app's private SharedPreferences and never
 *    leaves the device. We never touch the VPN slot and start nothing.
 */
object ArpGuard {

    // -----------------------------------------------------------------
    // Model
    // -----------------------------------------------------------------

    /** One neighbor-table entry. [mac] is lower-cased colon-hex, or "" if absent. */
    data class Neighbor(
        val ip: String,
        val mac: String,
        val dev: String,
        val state: String,
    )

    /** Severity band for a finding (higher = worse), mirroring the audit scale. */
    enum class Severity(val rank: Int) { MEDIUM(50), HIGH(80) }

    /**
     * One thing worth surfacing about the current neighbor table. [key] dedups a
     * standing finding across background runs so it alerts once, not every pass.
     */
    data class Finding(
        val key: String,
        val title: String,
        val detail: String,
        val severity: Severity,
    )

    /**
     * A single scan outcome. A closed set so the UI can `when`-branch and render
     * honest states — a missing grant is [NeedsElevation], never an exception.
     */
    sealed interface ScanResult {
        /** No Shizuku shell granted — the neighbor table is unreadable rootlessly. */
        data object NeedsElevation : ScanResult

        /**
         * The scan ran. [neighbors] is the parsed table; [findings] are the
         * regressions/anomalies, most-severe first; [gatewayIp] is the detected
         * default gateway (may be null if it couldn't be resolved rootlessly);
         * [source] names which table we read ("ip neigh" | "/proc/net/arp").
         */
        data class Ok(
            val neighbors: List<Neighbor>,
            val findings: List<Finding>,
            val gatewayIp: String?,
            val source: String,
        ) : ScanResult

        /** A granted shell was attempted but the read failed. [message] is a short cause. */
        data class Failed(val message: String) : ScanResult
    }

    // -----------------------------------------------------------------
    // Scan
    // -----------------------------------------------------------------

    /**
     * Read + analyse the neighbor table. Fail-closed on elevation: if
     * [Elevation.canRunShell] is false we return [ScanResult.NeedsElevation]
     * WITHOUT running (and without throwing). Never throws to the caller.
     *
     * Read strategy: `ip neigh show` first (the modern table, includes IPv6). If
     * that comes back empty or non-zero we fall back to parsing `/proc/net/arp`.
     */
    suspend fun scan(ctx: Context): ScanResult {
        if (!Elevation.canRunShell(ctx)) return ScanResult.NeedsElevation

        val gatewayIp = defaultGatewayIp(ctx)

        // Primary: `ip neigh show`.
        val primary = runShellCatching(ctx, listOf("ip", "neigh", "show"))
        var neighbors: List<Neighbor>
        var source: String
        when (primary) {
            is ShellRead.Error -> return ScanResult.Failed(primary.message)
            is ShellRead.Ok -> {
                neighbors = if (primary.exit == 0) parseIpNeigh(primary.out) else emptyList()
                source = "ip neigh"
            }
        }

        // Fallback: /proc/net/arp when `ip neigh` was empty or non-zero.
        if (neighbors.isEmpty()) {
            when (val arp = runShellCatching(ctx, listOf("cat", "/proc/net/arp"))) {
                is ShellRead.Error -> {
                    // Only surface a failure if BOTH reads failed; if primary was a
                    // clean empty table, report an honest empty scan instead.
                    if (primary is ShellRead.Ok && primary.exit == 0) {
                        return ScanResult.Ok(emptyList(), emptyList(), gatewayIp, "ip neigh")
                    }
                    return ScanResult.Failed(arp.message)
                }
                is ShellRead.Ok -> {
                    if (arp.exit == 0) {
                        neighbors = parseProcArp(arp.out)
                        source = "/proc/net/arp"
                    }
                }
            }
        }

        val findings = analyze(ctx, neighbors, gatewayIp)
        Diagnostics.log(
            "firewall.ArpGuard",
            "scan via $source: ${neighbors.size} neighbor(s), ${findings.size} finding(s)",
        )
        return ScanResult.Ok(neighbors, findings, gatewayIp, source)
    }

    private sealed interface ShellRead {
        data class Ok(val exit: Int, val out: String) : ShellRead
        data class Error(val message: String) : ShellRead
    }

    /** Run a shell command, translating throwables (incl. [NotElevated]) to a value. */
    private suspend fun runShellCatching(ctx: Context, cmd: List<String>): ShellRead =
        try {
            val r = Elevation.runShell(ctx, cmd)
            // Some tables print to stderr on partial reads; prefer stdout, fall back.
            ShellRead.Ok(r.exit, r.out.ifBlank { r.err })
        } catch (e: NotElevated) {
            // Shouldn't happen — we gated on canRunShell — but degrade honestly.
            ShellRead.Error(e.message ?: "not elevated")
        } catch (t: Throwable) {
            Diagnostics.error(
                "firewall.ArpGuard",
                "shell ${cmd.joinToString(" ")} threw ${t.javaClass.simpleName}: ${t.message}",
            )
            ShellRead.Error(t.message ?: t.javaClass.simpleName)
        }

    // -----------------------------------------------------------------
    // Parsing
    // -----------------------------------------------------------------

    /**
     * Parse `ip neigh show` lines, e.g.
     *   `192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`
     *   `fe80::1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff STALE`
     *   `10.0.0.5 dev wlan0  FAILED`   (no lladdr — kept with empty mac)
     * Tokens after the IP are `key value` pairs plus a trailing state word.
     */
    internal fun parseIpNeigh(raw: String): List<Neighbor> {
        val out = mutableListOf<Neighbor>()
        for (line in raw.lineSequence()) {
            val toks = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (toks.isEmpty()) continue
            val ip = toks[0]
            if (!looksLikeIp(ip)) continue
            var dev = ""
            var mac = ""
            var state = ""
            var i = 1
            while (i < toks.size) {
                when (toks[i]) {
                    "dev" -> { dev = toks.getOrElse(i + 1) { "" }; i += 2 }
                    "lladdr" -> { mac = toks.getOrElse(i + 1) { "" }.lowercase(); i += 2 }
                    "router", "proxy" -> i += 1 // flags, ignore
                    else -> {
                        // Bare word: the connection state (REACHABLE/STALE/…).
                        if (toks[i].uppercase() == toks[i]) state = toks[i]
                        i += 1
                    }
                }
            }
            out += Neighbor(ip = ip, mac = mac, dev = dev, state = state.ifBlank { "UNKNOWN" })
        }
        return out
    }

    /**
     * Parse `/proc/net/arp`, whose columns are:
     *   `IP address  HW type  Flags  HW address  Mask  Device`
     * The first line is a header and is skipped. Flags 0x0 means incomplete →
     * empty MAC. `00:00:00:00:00:00` is likewise treated as no MAC.
     */
    internal fun parseProcArp(raw: String): List<Neighbor> {
        val out = mutableListOf<Neighbor>()
        raw.lineSequence().drop(1).forEach { line ->
            val toks = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (toks.size < 6) return@forEach
            val ip = toks[0]
            if (!looksLikeIp(ip)) return@forEach
            val flags = toks[2]
            val hw = toks[3].lowercase()
            val dev = toks[5]
            val mac = if (flags == "0x0" || hw == "00:00:00:00:00:00") "" else hw
            val state = if (mac.isBlank()) "INCOMPLETE" else "REACHABLE"
            out += Neighbor(ip = ip, mac = mac, dev = dev, state = state)
        }
        return out
    }

    private fun looksLikeIp(s: String): Boolean =
        s.contains('.') && s.count { it == '.' } == 3 || s.contains(':')

    // -----------------------------------------------------------------
    // Analysis → findings
    // -----------------------------------------------------------------

    /**
     * Turn a parsed table into findings, most-severe first. Compares the gateway
     * row against the saved baseline (if any) and scans the whole table for a MAC
     * bound to multiple IPs.
     */
    internal fun analyze(ctx: Context, neighbors: List<Neighbor>, gatewayIp: String?): List<Finding> {
        val findings = mutableListOf<Finding>()

        // Gateway row (first neighbor whose IP == the resolved gateway, with a MAC).
        val gwRow = gatewayIp?.let { g -> neighbors.firstOrNull { it.ip == g && it.mac.isNotBlank() } }

        if (gwRow != null) {
            // (1) Gateway MAC changed vs the saved baseline — classic MITM.
            val baseMac = getBaselineMac(ctx, gwRow.ip)
            if (baseMac != null && !baseMac.equals(gwRow.mac, ignoreCase = true)) {
                findings += Finding(
                    key = "gw-changed:${gwRow.ip}",
                    title = "Gateway MAC changed",
                    detail = "The router at ${gwRow.ip} now answers from ${gwRow.mac}, not the " +
                        "$baseMac you recorded. On a network you trust this can mean someone is " +
                        "impersonating the gateway (a man-in-the-middle).",
                    severity = Severity.HIGH,
                )
            }

            // (3) Bogus gateway MAC (all-zero / broadcast / multicast).
            macAnomaly(gwRow.mac)?.let { why ->
                findings += Finding(
                    key = "gw-bogus:${gwRow.ip}",
                    title = "Gateway MAC looks wrong",
                    detail = "The gateway ${gwRow.ip} maps to ${gwRow.mac} ($why). A real router " +
                        "uses a normal unicast address; this pattern can indicate a spoofed entry.",
                    severity = Severity.MEDIUM,
                )
            }
        }

        // (2) Same MAC bound to 2+ IPs — ARP duplication / spoofing.
        neighbors.asSequence()
            .filter { it.mac.isNotBlank() && macAnomaly(it.mac) == null }
            .groupBy { it.mac }
            .filter { (_, rows) -> rows.map { it.ip }.distinct().size >= 2 }
            .forEach { (mac, rows) ->
                val ips = rows.map { it.ip }.distinct().sorted()
                findings += Finding(
                    key = "dup-mac:$mac",
                    title = "One device, many addresses",
                    detail = "$mac is claiming ${ips.size} IPs (${ips.joinToString(", ")}). One MAC " +
                        "answering for several addresses is a hallmark of ARP spoofing.",
                    severity = Severity.HIGH,
                )
            }

        return findings.sortedByDescending { it.severity.rank }
    }

    /** Why a MAC is bogus, or null if it looks like a normal unicast address. */
    private fun macAnomaly(mac: String): String? {
        val m = mac.lowercase()
        if (m.isBlank()) return null
        if (m == "00:00:00:00:00:00") return "all-zero"
        if (m == "ff:ff:ff:ff:ff:ff") return "broadcast"
        // Multicast bit = least-significant bit of the first octet.
        val firstOctet = m.substringBefore(':').toIntOrNull(16)
        if (firstOctet != null && (firstOctet and 0x01) == 1) return "multicast"
        return null
    }

    // -----------------------------------------------------------------
    // Rootless default-gateway resolution
    // -----------------------------------------------------------------

    /**
     * The active network's default-gateway IPv4, resolved rootlessly. Prefers the
     * ConnectivityManager LinkProperties route whose destination is a wildcard
     * (0.0.0.0/0); falls back to WifiManager's DhcpInfo.gateway. Null if neither
     * yields one. Never throws.
     */
    fun defaultGatewayIp(ctx: Context): String? {
        // Primary: LinkProperties default route (wildcard destination) on the
        // active network. isDefaultRoute is true exactly when the destination
        // prefix length is 0 (i.e. 0.0.0.0/0), so it covers the wildcard case.
        runCatching {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            val net = cm?.activeNetwork
            val lp = net?.let { cm.getLinkProperties(it) }
            lp?.routes?.forEach { route: RouteInfo ->
                val gw = route.gateway
                val isWildcard = route.isDefaultRoute || (route.destination?.prefixLength == 0)
                if (isWildcard && gw is Inet4Address && !gw.isAnyLocalAddress) {
                    return gw.hostAddress
                }
            }
        }.onFailure {
            Diagnostics.error("firewall.ArpGuard", "LinkProperties gateway read threw: ${it.message}")
        }

        // Fallback: DhcpInfo.gateway (little-endian int) via WifiManager.
        runCatching {
            @Suppress("DEPRECATION")
            val wifi = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            @Suppress("DEPRECATION")
            val gwInt = wifi?.dhcpInfo?.gateway ?: 0
            if (gwInt != 0) return intToIpv4(gwInt)
        }.onFailure {
            Diagnostics.error("firewall.ArpGuard", "DhcpInfo gateway read threw: ${it.message}")
        }
        return null
    }

    /** DhcpInfo integers are little-endian host order. */
    private fun intToIpv4(v: Int): String =
        "${v and 0xFF}.${(v shr 8) and 0xFF}.${(v shr 16) and 0xFF}.${(v shr 24) and 0xFF}"

    // -----------------------------------------------------------------
    // Baseline persistence (private SharedPreferences; never leaves the device)
    // -----------------------------------------------------------------

    private const val PREF = "arp_guard"
    private const val K_BASELINE = "gateway_baseline"   // JSON: { ip: mac }
    private const val K_NOTIFIED = "notified_keys"       // dedup across bg runs

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    /** The recorded MAC for a gateway IP, or null if no baseline is set for it. */
    fun getBaselineMac(ctx: Context, gatewayIp: String): String? = runCatching {
        val raw = prefs(ctx).getString(K_BASELINE, null) ?: return null
        JSONObject(raw).optString(gatewayIp).ifBlank { null }
    }.getOrNull()

    /** True when any gateway baseline is on record. */
    fun hasBaseline(ctx: Context): Boolean =
        !prefs(ctx).getString(K_BASELINE, null).isNullOrBlank()

    /**
     * Record the CURRENT gateway IP→MAC pair as the trusted baseline. Reads the
     * table once via a scan; a no-shell or gateway-less scan records nothing and
     * returns a plain reason. Callers run this off the main thread.
     */
    suspend fun setBaseline(ctx: Context): Outcome {
        if (!Elevation.canRunShell(ctx)) return Outcome.NeedsElevation
        return when (val r = scan(ctx)) {
            is ScanResult.NeedsElevation -> Outcome.NeedsElevation
            is ScanResult.Failed -> Outcome.Failed(r.message)
            is ScanResult.Ok -> {
                val gw = r.gatewayIp
                val row = gw?.let { g -> r.neighbors.firstOrNull { it.ip == g && it.mac.isNotBlank() } }
                if (gw == null || row == null) {
                    Outcome.Failed("Couldn't read the gateway's MAC to record a baseline.")
                } else {
                    val obj = runCatching {
                        prefs(ctx).getString(K_BASELINE, null)?.let { JSONObject(it) }
                    }.getOrNull() ?: JSONObject()
                    obj.put(gw, row.mac)
                    prefs(ctx).edit()
                        .putString(K_BASELINE, obj.toString())
                        .remove(K_NOTIFIED) // a new baseline clears stale dedup memory
                        .apply()
                    Diagnostics.log("firewall.ArpGuard", "baseline set: $gw -> ${row.mac}")
                    Outcome.Ok("Recorded ${row.mac} as the trusted MAC for $gw.")
                }
            }
        }
    }

    /** Forget every recorded gateway baseline and the dedup memory. */
    fun clearBaseline(ctx: Context) {
        prefs(ctx).edit().remove(K_BASELINE).remove(K_NOTIFIED).apply()
        Diagnostics.log("firewall.ArpGuard", "baseline cleared")
    }

    /** Result of the [setBaseline] convenience — a small closed set for the UI. */
    sealed interface Outcome {
        data class Ok(val detail: String) : Outcome
        data object NeedsElevation : Outcome
        data class Failed(val message: String) : Outcome
    }

    // -----------------------------------------------------------------
    // Dedup memory for the background watch
    // -----------------------------------------------------------------

    internal fun getNotifiedKeys(ctx: Context): Set<String> =
        prefs(ctx).getStringSet(K_NOTIFIED, emptySet())?.toSet() ?: emptySet()

    internal fun setNotifiedKeys(ctx: Context, keys: Set<String>) {
        prefs(ctx).edit().putStringSet(K_NOTIFIED, keys).apply()
    }
}
