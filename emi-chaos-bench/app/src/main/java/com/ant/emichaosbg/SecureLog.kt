package com.ant.emichaosbg

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.webkit.JavascriptInterface
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
    }

    private val dir = File(ctx.filesDir, "vault").apply { mkdirs() }
    private val logFile = File(dir, "alerts.log")
    private val headFile = File(dir, "alerts.head")
    private val lock = Any()

    @Volatile private var lastError: String? = null

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

    private fun writeHead(h: Head) {
        val o = JSONObject().put("count", h.count).put("head", h.head)
        headFile.writeBytes(seal(o.toString().toByteArray(), -1L))
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
            val seq = if (head.count < 0) 0L else head.count
            val prev = if (head.count <= 0) hex(GENESIS) else head.head

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

    private fun intBE(v: Int) = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )

    private fun hexToBytes(s: String): ByteArray {
        if (s.length % 2 != 0) return ByteArray(0)
        return ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }
    }

    // ---- read --------------------------------------------------------------------------

    private fun walk(onRecord: (Long, JSONObject, ByteArray) -> Unit) {
        if (!logFile.exists()) return
        RandomAccessFile(logFile, "r").use { f ->
            var seq = 0L
            val lenBuf = ByteArray(4)
            while (f.filePointer < f.length()) {
                if (f.read(lenBuf) != 4) break
                val n = ((lenBuf[0].toInt() and 255) shl 24) or ((lenBuf[1].toInt() and 255) shl 16) or
                        ((lenBuf[2].toInt() and 255) shl 8) or (lenBuf[3].toInt() and 255)
                if (n <= IV_LEN || n > 1 shl 20 || f.filePointer + n > f.length()) break
                val blob = ByteArray(n); f.readFully(blob)
                val plain = open(blob, seq)          // throws if edited or repositioned
                onRecord(seq, JSONObject(String(plain)), plain)
                seq++
            }
        }
    }

    /** Newest first, which is the order the UI shows them in. */
    fun read(limit: Int): String {
        synchronized(lock) {
            val all = ArrayList<JSONObject>()
            try { walk { _, o, _ -> all.add(o) } }
            catch (e: Exception) { lastError = "read stopped early: ${e.javaClass.simpleName}" }
            val out = JSONArray()
            all.asReversed().take(limit.coerceIn(1, 1000)).forEach { out.put(it) }
            return out.toString()
        }
    }

    fun count(): Long = synchronized(lock) {
        var n = 0L
        try { walk { _, _, _ -> n++ } } catch (_: Exception) {}
        n
    }

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
        try {
            walk { seq, rec, plain ->
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
        if (!headOk && head.count > n)
            o.put("note", "the head records ${head.count} entries but only $n are present — " +
                "the tail of the log has been removed")
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

/**
 * The page's view of the store. Deliberately four methods: append, read, count, verify.
 *
 * There is no delete and no clear here, and that is the whole point — see SecureLog's note.
 * Everything crossing this boundary is treated as untrusted input from the WebView
 * compartment and is clamped or truncated on the native side rather than trusted to be
 * well-formed.
 */
class VaultBridge(ctx: Context) {
    private val log = SecureLog(ctx)

    @JavascriptInterface
    fun append(sev: Int, msg: String?, badge: String?): Boolean {
        if (msg.isNullOrBlank()) return false
        return log.append(sev, msg, badge, "webview")
    }

    @JavascriptInterface
    fun read(limit: Int): String = log.read(limit)

    @JavascriptInterface
    fun count(): String = JSONObject().put("count", log.count()).toString()

    @JavascriptInterface
    fun verify(): String = log.verify()

    /**
     * Full detail export. read() is capped and shaped for on-screen display; this is the
     * whole record set including the per-entry device context and the hash-chain fields, for
     * getting evidence off the device or auditing it elsewhere.
     *
     * The verification result is embedded in the export itself rather than left to be checked
     * separately: an exported log that does not say whether its own chain verified is a
     * document that cannot be trusted by whoever receives it.
     */
    @JavascriptInterface
    fun exportJson(): String = log.exportJson()

    /** Spreadsheet-shaped, one row per finding, context flattened into columns. */
    @JavascriptInterface
    fun exportCsv(): String = log.exportCsv()
}
