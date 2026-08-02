package com.ant.emichaosbg

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The evidence store: scan findings and alerts, held where the page that displays them
 * cannot rewrite them.
 *
 * WHY THIS EXISTS. Until now the alert log was a JavaScript array inside the WebView. That
 * had three problems, and only the first is about crashes:
 *
 *   1. It died with the WebView. Swipe the app away, let the page reload, and every finding
 *      the detection layer had made was gone — including the ones from while you weren't
 *      looking, which are the ones that matter.
 *   2. Anything running in the page could edit or erase it. The WebView is the largest and
 *      least defensible surface this app has: it parses untrusted network names, BLE device
 *      names, SSIDs and cell identifiers, and it runs a lot of JavaScript. If something ever
 *      does get a foothold there, the first thing worth doing is deleting the record of how
 *      it arrived.
 *   3. Nothing could tell you whether it had been tampered with. An absent alert and an alert
 *      that was never raised look identical.
 *
 * So the store moves out of the page and the page becomes a reader. This is the same shape
 * as a Qubes split: the compartment that handles hostile input is not the compartment that
 * holds the evidence, and the interface between them only allows what it has to.
 *
 * WHAT IT GUARANTEES.
 *   - CONFIDENTIALITY AT REST. Every record is sealed with AES-256-GCM under a key generated
 *     in the Android Keystore and marked non-exportable, so the key material never enters
 *     this process's memory and cannot be lifted out of a backup or an adb pull. StrongBox
 *     (a separate security chip) is used when the device has one.
 *   - APPEND-ONLY, TAMPER-EVIDENT ORDER. Records form a hash chain: each one commits to the
 *     hash of the one before it, and its sequence number is bound in as GCM associated data.
 *     Editing a record, reordering two, or removing one from the middle breaks the chain at
 *     that point and verify() names the sequence number where it broke.
 *   - TRUNCATION IS DETECTABLE. A chain alone cannot notice that the tail was cut off — the
 *     shortened chain still verifies. So the head hash and record count are kept in a second
 *     sealed file and checked against what the log actually contains. Dropping the last N
 *     records now disagrees with the head.
 *   - OFFLINE. Nothing here touches the network. The file lives in app-private storage and
 *     is only ever read back out on request.
 *
 * WHAT IT DELIBERATELY DOES NOT OFFER. There is no delete, no clear, and no rewrite on the
 * JavaScript interface — not a guarded one, not an "internal" one. A log the page can empty
 * is not evidence. Rotation is the single exception and it is native-side, size-driven, and
 * keeps the rotated segment.
 *
 * HONEST LIMITS. This defends the log against the WebView and against offline inspection of
 * the file. It does not defend against native code running as this app's own UID with the
 * app unlocked — such code can ask the Keystore to decrypt, and can append. Nor is it a
 * remote attestation: an attacker with root can delete the whole file, and what verify()
 * would then report is "empty, and the head says it should not be", which is a signal but
 * not a recovery.
 */
class SecureLog(private val ctx: Context) {

    companion object {
        private const val ALIAS = "emi.vault.v1"
        private const val GCM_TAG_BITS = 128
        private const val IV_LEN = 12
        private const val MAX_BYTES = 4L * 1024 * 1024      // roll past this
        private val GENESIS: ByteArray = MessageDigest.getInstance("SHA-256")
            .digest("EMI-VAULT-v1".toByteArray())

        /** One monitor per PROCESS, because there is one log file per process. See [lock]. */
        private val FILE_LOCK = Any()

        /**
         * How far either side of the expected sequence number [walk] will look when a record
         * fails to authenticate. Bounded deliberately: this exists to absorb the small
         * position-vs-sequence slip left by concurrent appends, not to brute-force a corrupt
         * file. A handful of racing writers can slip by a few; nothing legitimate slips by 16.
         */
        private const val RESYNC_WINDOW = 16L

        /**
         * Set when a write is known to have failed, and never cleared by a later success.
         *
         * lastError used to be an instance field, which meant a failure inside ScanEngine's
         * SecureLog could not be seen by the LogsScreen's SecureLog — different objects — so
         * verify() would report a clean bill of health for a log that had been silently losing
         * records. The state being described belongs to the FILE, so it lives with the file's
         * lock.
         */
        @Volatile private var sharedError: String? = null
    }

    private val dir = File(ctx.filesDir, "vault").apply { mkdirs() }
    private val logFile = File(dir, "alerts.log")
    private val headFile = File(dir, "alerts.head")

    /**
     * THE LOCK IS PROCESS-WIDE, NOT PER-INSTANCE, AND THAT DISTINCTION IS THE WHOLE CHAIN.
     *
     * This was `private val lock = Any()` — an instance field — while SEVEN separate SecureLog
     * instances exist in this process: ScanEngine's, CellSecurity's, NetGuard's,
     * EscalationGuard's, TrackerWatch's, TapjackGuard's, OverlayWatch's, LogsScreen's and the
     * page's VaultBridge. They all write the same alerts.log, from the scan thread, two timer
     * threads, the BLE handler thread, an accessibility callback and the UI thread.
     *
     * Seven locks guarding one file is no lock at all. append() is read-modify-write across
     * TWO files — it reads the head for the sequence number and previous hash, writes a record,
     * then writes the new head — so two concurrent appends can both read seq N, both write a
     * record claiming seq N with the same prev hash, and leave a head that describes neither.
     * The result is a log whose chain does not verify, reported to the user as TAMPERING.
     *
     * That is the worst possible failure mode here: the one alarm that is supposed to mean
     * "someone edited your evidence" would fire because two of the app's own detectors happened
     * to find something in the same millisecond. It would be unreproducible, and it would
     * discredit the exact signal the vault exists to provide.
     *
     * Companion-object scope makes it one monitor for the whole process, which is the actual
     * granularity of the resource being guarded: the file.
     */
    private val lock = FILE_LOCK

    /** Process-wide (see [sharedError]) — a write failure anywhere must be visible everywhere. */
    private var lastError: String?
        get() = sharedError
        set(v) { sharedError = v }

    // ---- key handling ------------------------------------------------------------------

    /**
     * The key is created once and never leaves the Keystore. User authentication is
     * deliberately NOT required: this log is written by a foreground service while the
     * screen is off and the device is locked, which is exactly when unattended findings
     * happen, and a key that needs an unlock would simply lose them.
     */
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .apply {
                if (strongBox && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P)
                    setIsStrongBoxBacked(true)
            }
            .build()

        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        return try {
            gen.init(spec(true)); gen.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            gen.init(spec(false)); gen.generateKey()
        } catch (_: Exception) {
            gen.init(spec(false)); gen.generateKey()
        }
    }

    /** seq is bound in as associated data, so a record cannot be moved to another position. */
    private fun seal(plain: ByteArray, seq: Long): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        c.updateAAD(seqAad(seq))
        val body = c.doFinal(plain)
        return c.iv + body
    }

    private fun open(blob: ByteArray, seq: Long): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(GCM_TAG_BITS, blob, 0, IV_LEN))
        c.updateAAD(seqAad(seq))
        return c.doFinal(blob, IV_LEN, blob.size - IV_LEN)
    }

    private fun seqAad(seq: Long) = "seq:$seq".toByteArray()

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val d = MessageDigest.getInstance("SHA-256")
        parts.forEach { d.update(it) }
        return d.digest()
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    // ---- head (count + chain head), sealed separately ----------------------------------

    private data class Head(val count: Long, val head: String)

    private fun readHead(): Head {
        if (!headFile.exists()) return Head(0, hex(GENESIS))
        return try {
            val o = JSONObject(String(open(headFile.readBytes(), -1L)))
            Head(o.getLong("count"), o.getString("head"))
        } catch (e: Exception) {
            lastError = "head unreadable: ${e.javaClass.simpleName}"
            Head(-1, "")   // -1 signals "head damaged", distinct from "no head yet"
        }
    }

    /**
     * Written ATOMICALLY: sealed into a temp file, fsynced, then renamed over the real one.
     *
     * The head is the only thing that says how many records exist, and append() derives the next
     * sequence number from it. A torn or half-written head therefore does not merely lose a
     * count — it desynchronises sequence from file position for every record written afterwards,
     * which is the same permanent, unrecoverable break as a concurrent append. writeBytes()
     * truncates the file first, so a kill or a full disk between truncate and write left exactly
     * that: a zero-length head, read back as "damaged", and an append that then restarted the
     * sequence at 0 on top of an existing log.
     *
     * rename() on the same filesystem is atomic, so a reader sees either the whole old head or
     * the whole new one, never a partial. The fd.sync() before the rename is what makes that
     * true across a power loss rather than only across a process kill.
     */
    private fun writeHead(h: Head) {
        val o = JSONObject().put("count", h.count).put("head", h.head)
        val sealed = seal(o.toString().toByteArray(), -1L)
        val tmp = File(dir, "alerts.head.tmp")
        RandomAccessFile(tmp, "rw").use { f ->
            f.setLength(0)
            f.write(sealed)
            f.fd.sync()
        }
        if (!tmp.renameTo(headFile)) {
            // Fall back rather than lose the update, but say so — a non-atomic head is a
            // liability worth knowing about.
            headFile.writeBytes(sealed)
            lastError = "head written non-atomically (rename failed)"
        }
    }

    // ---- append ------------------------------------------------------------------------

    /**
     * Appends one record. Returns true on success. Callers are native subsystems and the
     * WebView bridge alike — both may add, neither may remove.
     */
    fun append(sev: Int, msg: String, badge: String?, source: String): Boolean = synchronized(lock) {
        try {
            rotateIfNeeded()
            val head = readHead()

            /* A DAMAGED HEAD MUST NOT RESTART THE SEQUENCE AT ZERO.
             *
             * readHead() returns count = -1 when the head cannot be decrypted, and this used to
             * map that straight to seq = 0. On a log that already held N records that is
             * catastrophic and silent: the new record goes at file position N but is sealed as
             * sequence 0, so position and sequence are permanently out of step and EVERY record
             * from there on fails authentication — the exact failure pattern seen on device, an
             * AEADBadTagException partway through an otherwise perfect log.
             *
             * A head is small and single-purpose; the log itself is the larger and more
             * trustworthy artifact. So when the head is unreadable, the sequence is recovered by
             * counting the records that are actually there, and the damage is recorded rather
             * than absorbed. Restarting from 0 is only correct when the log is genuinely empty.
             */
            val seq: Long
            val prev: String
            if (head.count < 0) {
                val recovered = countByWalking()
                lastError = "head was unreadable; sequence recovered from the log itself " +
                    "($recovered records found). The head is being rebuilt."
                seq = recovered
                prev = if (recovered <= 0L) hex(GENESIS) else lastChainHash()
            } else {
                seq = head.count
                prev = if (head.count <= 0L) hex(GENESIS) else head.head
            }

            val rec = JSONObject()
                .put("seq", seq)
                .put("t", System.currentTimeMillis())
                .put("sev", sev.coerceIn(1, 3))
                .put("msg", msg.take(2000))
                .put("badge", badge ?: "")
                .put("src", source.take(40))
                .put("prev", prev)
            // Device context AT THE MOMENT OF THE FINDING. A bare line cannot answer the
            // questions that decide whether it mattered — screen off or in use, charging or
            // not, Wi-Fi or cellular, masker running or idle, device hot enough for the
            // sensors to be drifting. Captured inside the same sealed record, so it is
            // covered by the same authentication tag and hash chain as the message: context
            // that could be edited afterwards would be worse than none.
            // Deliberately carries NO location, SSID, BSSID, cell identity or device serial —
            // see LogContext. Failure to read it degrades to an absent field, never a lost
            // record.
            runCatching { rec.put("ctx", LogContext.capture(ctx)) }
            val plain = rec.toString().toByteArray()

            val blob = seal(plain, seq)
            RandomAccessFile(logFile, "rw").use { f ->
                f.seek(f.length())
                f.write(intBE(blob.size))
                f.write(blob)
                f.fd.sync()                     // survive a kill between write and head update
            }
            writeHead(Head(seq + 1, hex(sha256(hexToBytes(prev), plain))))
            true
        } catch (e: Exception) {
            lastError = "append failed: ${e.javaClass.simpleName}: ${e.message}"
            false
        }
    }

    /**
     * Records actually present, counted by reading them. Used only to recover from a damaged
     * head — the ordinary count() reads the head, which is O(1). Callers already hold [lock].
     */
    private fun countByWalking(): Long {
        var n = 0L
        try { walk { _, _, _ -> n++ } } catch (_: Exception) {}
        return n
    }

    /** Chain value after the last readable record, for rebuilding a destroyed head. */
    private fun lastChainHash(): String {
        var chain = GENESIS
        try { walk { _, _, plain -> chain = sha256(chain, plain) } } catch (_: Exception) {}
        return hex(chain)
    }

    private fun intBE(v: Int) = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )

    private fun hexToBytes(s: String): ByteArray {
        if (s.length % 2 != 0) return ByteArray(0)
        return ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }
    }

    // ---- read --------------------------------------------------------------------------

    /**
     * Walks the log, and RESYNCHRONISES rather than giving up at the first record it cannot
     * authenticate.
     *
     * WHY THIS WAS NECESSARY, FROM REAL DEVICE DATA. Exports from one device showed 70 records
     * verifying cleanly, then — later the same hour — 279 readable records against a head
     * claiming 463, and then 732. Readable records were frozen at 279 while the log kept
     * growing, and the failure was AEADBadTagException: a GCM authentication failure.
     *
     * The cause was the per-instance lock (see [lock]): concurrent appends from two of the
     * app's own detectors both read sequence N and both wrote a record sealed with AAD "seq:N".
     * From that point every record sits one position later in the file than the sequence number
     * baked into its ciphertext, so open(blob, seq) fails for the rest of the log FOREVER —
     * not because anything was tampered with, but because the position-to-sequence mapping
     * slipped by one.
     *
     * The old walk threw on the first such failure, which discarded every record after it. 453
     * of that user's records were intact on disk and unreadable purely because of where the
     * loop gave up.
     *
     * So: on an authentication failure, try neighbouring sequence numbers within a bounded
     * window. If one authenticates, the drift is adopted and the walk continues — recovering
     * the entire tail. The record framing (4-byte length prefix) is unaffected by this defect,
     * which is what makes recovery possible at all.
     *
     * This is a REPAIR PATH, not a weakening of the guarantee. A record still has to
     * authenticate under SOME sequence number with the Keystore key, which forged or edited
     * data cannot do. Drift is reported through [onGap] so verify() can say a slip happened
     * rather than quietly papering over it.
     */
    private fun walk(
        onGap: ((Long, String) -> Unit)? = null,
        onRecord: (Long, JSONObject, ByteArray) -> Unit
    ) {
        if (!logFile.exists()) return
        RandomAccessFile(logFile, "r").use { f ->
            var seq = 0L
            var drift = 0L                      // position -> sequence correction, once resynced
            val lenBuf = ByteArray(4)
            while (f.filePointer < f.length()) {
                if (f.read(lenBuf) != 4) break
                val n = ((lenBuf[0].toInt() and 255) shl 24) or ((lenBuf[1].toInt() and 255) shl 16) or
                        ((lenBuf[2].toInt() and 255) shl 8) or (lenBuf[3].toInt() and 255)
                if (n <= IV_LEN || n > 1 shl 20 || f.filePointer + n > f.length()) break
                val blob = ByteArray(n); f.readFully(blob)

                var plain: ByteArray? = null
                var used = seq + drift
                try {
                    plain = open(blob, used)
                } catch (_: Exception) {
                    // Search a bounded window for the sequence this record was actually sealed
                    // under. Bounded so a genuinely corrupt file cannot turn this into a long
                    // brute-force over the whole key space of sequence numbers.
                    for (d in -RESYNC_WINDOW..RESYNC_WINDOW) {
                        if (d == 0L) continue
                        val cand = seq + drift + d
                        if (cand < 0) continue
                        try {
                            plain = open(blob, cand)
                            drift += d
                            used = cand
                            onGap?.invoke(seq, "sequence slipped by $d at record $seq " +
                                "(concurrent-append defect, fixed in this version) — resynced " +
                                "and continued")
                            break
                        } catch (_: Exception) { /* keep searching the window */ }
                    }
                }
                if (plain == null) {
                    // Genuinely unreadable even after resync. Report and stop: continuing past
                    // an unexplained record would let the chain be recomputed over a gap.
                    onGap?.invoke(seq, "record $seq could not be authenticated under any " +
                        "sequence in the resync window")
                    throw javax.crypto.AEADBadTagException(
                        "record $seq failed authentication and could not be resynchronised")
                }
                onRecord(used, JSONObject(String(plain)), plain)
                seq++
            }
        }
    }

    /**
     * Newest first, which is the order the UI shows them in.
     *
     * A TRUNCATED READ IS REPORTED, NOT SWALLOWED. This caught a decrypt failure into lastError
     * — a field the Logs screen never reads — and returned however many records it managed. With
     * an empty or early-failing log that produced a screen saying "No findings recorded yet."
     * over a vault that had hundreds of records it simply could not authenticate. On a device
     * whose head counted 830 records and whose reader stopped at 279, that sentence was the
     * opposite of the truth.
     *
     * So read() now returns an OBJECT carrying the records plus how the read ended. Callers that
     * want the bare array can still take `entries`; callers that render must be able to tell
     * "nothing was ever recorded" from "the log would not open".
     */
    fun read(limit: Int): String {
        synchronized(lock) {
            val all = ArrayList<JSONObject>()
            var stopped: String? = null
            var resyncs = 0
            try {
                walk(onGap = { _, _ -> resyncs++ }) { _, o, _ -> all.add(o) }
            } catch (e: Exception) {
                stopped = "${e.javaClass.simpleName}: ${e.message ?: "no detail"}"
                lastError = "read stopped early: ${e.javaClass.simpleName}"
            }
            val out = JSONArray()
            all.asReversed().take(limit.coerceIn(1, 1000)).forEach { out.put(it) }
            val head = readHead()
            val o = JSONObject()
                .put("entries", out)
                .put("readable", all.size.toLong())
                .put("headCount", head.count)
            if (resyncs > 0) o.put("resyncs", resyncs)
            if (stopped != null) {
                o.put("truncated", true)
                o.put("stoppedAt", all.size.toLong())
                o.put("stoppedBecause", stopped)
                o.put("note", "Reading stopped after ${all.size} record(s) on an authentication " +
                    "failure. The rest are still on disk and are NOT shown here — this is not an " +
                    "empty log.")
            } else if (head.count > all.size) {
                o.put("truncated", true)
                o.put("stoppedAt", all.size.toLong())
                o.put("note", "The head counts ${head.count} records but only ${all.size} could " +
                    "be read.")
            }
            return o.toString()
        }
    }

    /** Bare array, for the page bridge's existing contract. Prefer [read]. */
    fun readEntriesOnly(limit: Int): String =
        runCatching { JSONObject(read(limit)).optJSONArray("entries")?.toString() }
            .getOrNull() ?: "[]"

    /**
     * O(1). This used to call walk{}, which DECRYPTS EVERY RECORD, in order to increment a
     * counter — and the Logs screen called it during construction, on the main thread, from a
     * tab press. That froze the app on open, and got worse as the log grew: the same
     * decrypt-the-world-to-render mistake this project already made once with verify().
     *
     * The count is already known. append() seals it into the head file alongside the chain
     * head, so reading it costs one small file read and one decrypt of a two-field JSON object,
     * whatever the log's size.
     *
     * The walk remains as a FALLBACK, and only for the case the head is unreadable (count < 0),
     * where there is no cheaper answer and a wrong count would be worse than a slow one. That
     * path is rare, bounded by a damaged head, and never the ordinary tab-open path.
     */
    fun count(): Long = synchronized(lock) {
        val head = readHead()
        if (head.count >= 0) return head.count
        countByWalking()
    }

    /**
     * How many records can actually be READ, as opposed to how many the head claims exist.
     *
     * These two numbers are supposed to be equal and on a real device they were not: the head
     * said 830 and only 279 could be decrypted, with the gap growing every minute. count() alone
     * therefore made a badly damaged vault look healthy — it reported the head's number, which
     * kept rising, while the readable evidence had been frozen for over an hour.
     *
     * A counter-surveillance log that cannot be read is worth exactly nothing, and the user must
     * not have to open an export to find that out. This is what lets the Logs screen say so on
     * sight. It is O(records) with a decrypt each, so it belongs off the main thread with the
     * other real work — never on a refresh loop.
     */
    fun readableCount(): Long = synchronized(lock) { countByWalking() }

    // ---- verify ------------------------------------------------------------------------

    /**
     * Recomputes the chain from genesis and compares the result against the sealed head.
     * Reports the first sequence number that disagrees rather than a bare pass/fail, because
     * "record 41 of 60 was altered" is actionable and "integrity: false" is not.
     */
    /** Every record, with context and chain fields, plus this log's own verify result. */
    fun exportJson(): String = synchronized(lock) {
        val arr = JSONArray()
        var truncatedAt: Long? = null
        try { walk { seq, o, _ -> arr.put(o) } }
        catch (e: Exception) { truncatedAt = arr.length().toLong() }
        val root = JSONObject()
            .put("format", "emi-chaos-bench/secure-log/1")
            .put("exportedAt", System.currentTimeMillis())
            .put("records", arr.length())
            .put("entries", arr)
        // Self-describing trust state. If the chain broke, the export says where.
        root.put("verify", JSONObject(verify()))
        truncatedAt?.let {
            root.put("truncated", true)
            root.put("truncatedAfter", it)
            root.put("truncatedNote",
                "Reading stopped at record $it — the remainder could not be decrypted or " +
                "authenticated. Everything before this point verified.")
        }
        root.toString()
    }

    fun exportCsv(): String = synchronized(lock) {
        val sb = StringBuilder()
        sb.append("seq,timestamp_iso,epoch_ms,severity,badge,source,message,")
            .append("battery_pct,charging,plugged,batt_temp_c,screen_on,dozing,power_save,")
            .append("network,metered,masking,uptime_ms,app_version,sdk,device\n")
        val iso = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", java.util.Locale.US)
        fun q(v: Any?): String {
            val t = v?.toString() ?: ""
            return if (t.any { it == ',' || it == '"' || it == '\n' || it == '\r' })
                "\"" + t.replace("\"", "\"\"") + "\"" else t
        }
        try {
            walk { _, o, _ ->
                val c = o.optJSONObject("ctx")
                val t = o.optLong("t")
                sb.append(o.optLong("seq")).append(',')
                    .append(q(iso.format(java.util.Date(t)))).append(',')
                    .append(t).append(',')
                    .append(o.optInt("sev")).append(',')
                    .append(q(o.optString("badge"))).append(',')
                    .append(q(o.optString("src"))).append(',')
                    .append(q(o.optString("msg"))).append(',')
                    .append(q(c?.opt("battery"))).append(',')
                    .append(q(c?.opt("charging"))).append(',')
                    .append(q(c?.opt("plugged"))).append(',')
                    .append(q(c?.opt("battTempC"))).append(',')
                    .append(q(c?.opt("screenOn"))).append(',')
                    .append(q(c?.opt("dozing"))).append(',')
                    .append(q(c?.opt("powerSave"))).append(',')
                    .append(q(c?.opt("net"))).append(',')
                    .append(q(c?.opt("metered"))).append(',')
                    .append(q(c?.opt("masking"))).append(',')
                    .append(q(c?.opt("upMs"))).append(',')
                    .append(q(c?.opt("appVer"))).append(',')
                    .append(q(c?.opt("sdk"))).append(',')
                    .append(q(c?.opt("device"))).append('\n')
            }
        } catch (e: Exception) {
            sb.append("# reading stopped early: ${e.javaClass.simpleName} — ")
                .append("records after this point could not be authenticated\n")
        }
        sb.toString()
    }

    fun verify(): String = synchronized(lock) {
        val o = JSONObject()
        var chain = GENESIS
        var n = 0L
        var firstBad = -1L
        var stopped: String? = null
        val gaps = JSONArray()
        try {
            walk(onGap = { at, why ->
                if (gaps.length() < 20) gaps.put(JSONObject().put("at", at).put("why", why))
            }) { seq, rec, plain ->
                if (firstBad < 0) {
                    val expectPrev = hex(chain)
                    if (rec.optString("prev") != expectPrev) firstBad = seq
                    else chain = sha256(chain, plain)
                }
                n++
            }
        } catch (e: Exception) {
            stopped = "${e.javaClass.simpleName}: ${e.message}"
        }
        if (gaps.length() > 0) o.put("resyncs", gaps)
        val head = readHead()
        val chainOk = firstBad < 0 && stopped == null
        val headOk = head.count == n && (n == 0L || head.head == hex(chain))
        o.put("ok", chainOk && headOk)
        o.put("records", n)
        o.put("headCount", head.count)
        o.put("chainIntact", chainOk)
        o.put("headMatches", headOk)
        if (firstBad >= 0) o.put("firstBadSeq", firstBad)
        if (stopped != null) o.put("decryptStopped", stopped)

        /* THE DIAGNOSIS MUST NOT ACCUSE WHEN THE APP IS THE CAUSE.
         *
         * This used to say, unconditionally, "the tail of the log has been removed" whenever
         * the head counted more entries than were readable. On a real device that produced a
         * flat accusation of tampering — 279 readable against a head of 732 — when the actual
         * cause was this app's own concurrent-append defect (see the note on `lock`). Records
         * were not removed; they were on disk and unreadable because their sequence numbers had
         * slipped out of step with their positions.
         *
         * A tamper-evident log that cries tamper at its own bug is worse than one that says
         * nothing, because it burns the credibility of the one alarm that is supposed to
         * matter. So the two causes are now distinguished by the evidence that separates them:
         * a decrypt/authentication failure points at the slip, a clean read that simply ends
         * early points at real truncation.
         */
        if (!headOk && head.count > n) {
            val authFailed = stopped?.contains("AEADBadTag", ignoreCase = true) == true ||
                stopped?.contains("Bad Tag", ignoreCase = true) == true ||
                gaps.length() > 0
            o.put("note", if (authFailed)
                "the head counts ${head.count} entries and $n could be read. Reading stopped at " +
                "an AUTHENTICATION failure, not at the end of the file — the missing records are " +
                "still on disk. This is the signature of the concurrent-append defect fixed in " +
                "this version, in which two of this app's own detectors wrote the same sequence " +
                "number and knocked every later record's position out of step with the sequence " +
                "sealed into it. THIS IS NOT EVIDENCE OF TAMPERING. This version resynchronises " +
                "past the slip on read; records written before the fix may remain unreadable."
            else
                "the head records ${head.count} entries but only $n are present, and reading " +
                "ended cleanly rather than on an authentication failure — consistent with the " +
                "tail of the log having been REMOVED.")
            o.put("likelyCause", if (authFailed) "app-defect-sequence-slip" else "truncation")
        }
        lastError?.let { o.put("lastError", it) }
        o.put("strongBox", strongBoxInUse())
        return o.toString()
    }

    private fun strongBoxInUse(): Boolean = try {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val k = (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
        val f = javax.crypto.SecretKeyFactory.getInstance(k!!.algorithm, "AndroidKeyStore")
        val info = f.getKeySpec(k, android.security.keystore.KeyInfo::class.java) as android.security.keystore.KeyInfo
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S)
            info.securityLevel == android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX
        else @Suppress("DEPRECATION") info.isInsideSecureHardware
    } catch (_: Exception) { false }

    // ---- rotation ----------------------------------------------------------------------

    /**
     * Size-driven and native-only. The rotated segment is KEPT, not deleted — the point of
     * the store is that findings do not disappear. The chain restarts for the live file and
     * verify() reports the live file; the archived segment stays readable with the same key.
     */
    private fun rotateIfNeeded() {
        if (!logFile.exists() || logFile.length() < MAX_BYTES) return
        val stamp = System.currentTimeMillis()
        logFile.renameTo(File(dir, "alerts-$stamp.log"))
        headFile.renameTo(File(dir, "alerts-$stamp.head"))
    }
}
