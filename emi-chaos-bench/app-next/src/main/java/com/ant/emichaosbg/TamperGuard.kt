package com.ant.emichaosbg

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.Debug
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/**
 * APP INTEGRITY — is the APK that is running the one we signed, and is anything
 * instrumenting it.
 *
 * WHAT CHANGED FROM THE OLD VERSION, and why each change was necessary:
 *
 *  1. THE SIGNATURE CHECK IS REAL NOW. The old code read
 *     `BuildConfigLike.expectedSignatureHash = ""` and then did
 *     `ok = expected.isBlank() || expected == hash`, so the check returned
 *     ok=true UNCONDITIONALLY on every build that shipped. The Security readout's
 *     integrity headline was a no-op that always said "clean". The pin now comes
 *     from [SuiteCertPins], which carries the same two digests the rest of the
 *     suite pins, and the result reports whether a pin was available at all — a
 *     check that cannot run says so instead of passing.
 *
 *  2. THE FRIDA LOOPBACK-PORT PROBE IS GONE. It opened a TCP socket to
 *     127.0.0.1:27042/3/7, which requires android.permission.INTERNET. This build
 *     deliberately holds no INTERNET permission — a counter-surveillance tool that
 *     can open a socket is a contradiction — so the probe could only ever throw.
 *     Rather than keep a check that silently always fails, it is removed and the
 *     `limits` array names it, so the screen says which evidence is NOT being
 *     gathered instead of implying full coverage.
 *
 *  3. NON-BLOCKING BY CONSTRUCTION. [status] returns the last completed scan
 *     immediately and kicks a background one; it never runs the scan on the
 *     caller's thread. The heuristics read /proc/self/maps, /proc/self/task and
 *     hash the signing cert, which is real work.
 *
 * DETECT AND REPORT ONLY. Nothing here blocks the app, kills it, or degrades a
 * feature. Anti-debug retaliation is trivially bypassed by the tooling it targets
 * and turns a false positive into a bricked app for an ordinary user.
 */
class TamperGuard(private val ctx: Context) {

    @Volatile private var cached: String? = null
    @Volatile private var scanning = false
    private val bg = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        Thread(r, "orb-integrity").apply { isDaemon = true }
    }

    /** Last completed scan, or a "checking" placeholder that is NOT a verdict. */
    fun status(): String {
        kick()
        return cached ?: JSONObject()
            .put("ran", false)
            .put("scanning", true)
            .put("clean", false)
            .put("findings", JSONArray())
            .put("reason", "not yet run")
            .toString()
    }

    /** Force a fresh scan. Blocks the calling thread — call it off the main one. */
    fun scanBlocking(): String = runIntegrityScan().also { cached = it }

    private fun kick() {
        if (scanning) return
        synchronized(this) {
            if (scanning) return
            scanning = true
        }
        bg.execute {
            try { cached = runIntegrityScan() } catch (_: Throwable) {} finally { scanning = false }
        }
    }

    private fun runIntegrityScan(): String {
        val o = JSONObject()
        val findings = JSONArray()

        // ---- 1. Is this the APK we signed? -------------------------------------------
        val sig = checkSignature()
        o.put("signatureHash", sig.hash)
        o.put("signaturePinned", sig.pinned)
        o.put("signatureOk", sig.ok)
        o.put("signatureNote", sig.note)
        if (sig.pinned && !sig.ok) findings.put(
            "SIGNING CERTIFICATE MISMATCH. This APK is signed by ${sig.hash.take(16)}… but the " +
                "build pins ${sig.expected.take(16)}…. A re-signed APK is somebody else's build " +
                "of this app.")

        // ---- 2. Debugger --------------------------------------------------------------
        val dbg = try { Debug.isDebuggerConnected() || Debug.waitingForDebugger() }
            catch (_: Exception) { false }
        o.put("debuggerAttached", dbg)
        if (dbg) findings.put("A debugger is attached to this process right now.")

        // ---- 3. Instrumentation traces IN THIS PROCESS ---------------------------------
        val frida = fridaHeuristics()
        o.put("instrumentation", JSONArray(frida))
        frida.forEach { findings.put(it) }

        // ---- 4. Root posture ------------------------------------------------------------
        val root = rootHeuristics()
        o.put("root", JSONArray(root))
        o.put("rootSuspicion", root.isNotEmpty())

        o.put("findings", findings)
        o.put("count", findings.length())
        o.put("clean", findings.length() == 0)
        o.put("ran", true)
        o.put("scanning", false)
        o.put("checkedAt", System.currentTimeMillis())
        o.put("limits", JSONArray(listOf(
            "The Frida loopback-port probe is NOT performed. It needs a TCP socket, which needs " +
                "android.permission.INTERNET, which this build deliberately does not hold. Live " +
                "instrumentation is looked for in this process's own memory map and thread names " +
                "instead.",
            "Root indicators describe the DEVICE, not an attack. A rooted phone is the owner's " +
                "choice and is listed separately from findings for that reason.",
            "Anything with kernel-level control can defeat every check here. This raises the cost " +
                "of a quiet compromise; it does not prove there isn't one."
        )))
        return o.toString()
    }

    // ------------------------------------------------------------------ signature

    private data class SigResult(
        val ok: Boolean, val pinned: Boolean, val hash: String,
        val expected: String, val note: String
    )

    private fun checkSignature(): SigResult {
        val expected = SuiteCertPins.expected(BuildConfig.DEBUG)
        val hash = try {
            val pm = ctx.packageManager
            val sigs: Array<Signature> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val si = info.signingInfo
                if (si?.hasMultipleSigners() == true) si.apkContentsSigners
                else si?.signingCertificateHistory ?: emptyArray()
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info.signatures ?: emptyArray()
            }
            if (sigs.isEmpty()) "" else MessageDigest.getInstance("SHA-256")
                .digest(sigs[0].toByteArray()).joinToString("") { "%02x".format(it) }
        } catch (_: Exception) { "" }

        if (hash.isBlank()) return SigResult(
            ok = false, pinned = expected.isNotBlank(), hash = "", expected = expected,
            note = "The signing certificate could not be read at all. That is not an all-clear.")
        if (expected.isBlank()) return SigResult(
            ok = false, pinned = false, hash = hash, expected = "",
            note = "NOT PINNED — this check is inactive. No expected certificate digest is " +
                "compiled into this build, so the hash below is reported for comparison and " +
                "nothing is being verified.")
        val ok = expected.equals(hash, ignoreCase = true)
        return SigResult(
            ok = ok, pinned = true, hash = hash, expected = expected,
            note = if (ok)
                "Signed by the pinned suite certificate for this variant."
            else
                "This APK is NOT signed by the certificate this build pins.")
    }

    // ------------------------------------------------------------------ heuristics

    /**
     * Traces of a hooking engine INSIDE THIS PROCESS. Each hit names WHAT matched so the
     * finding can be judged rather than taken on faith; "possible Frida" with no detail is
     * unactionable in either direction.
     */
    private fun fridaHeuristics(): List<String> {
        val hits = mutableListOf<String>()
        // Injected agents spawn recognisable threads. Reading our own task list is cheap and
        // survives a renamed binary.
        try {
            File("/proc/self/task").listFiles()?.take(400)?.forEach { t ->
                val nameFile = File(t, "comm")
                if (nameFile.canRead()) {
                    val n = nameFile.readText().trim().lowercase()
                    if (n == "gmain" || n == "gdbus" || n.startsWith("gum-js") ||
                        n.contains("frida") || n == "pool-frida"
                    ) hits.add("A thread named '$n' is running inside this app — that is a name " +
                        "an injected instrumentation agent creates, not one this app creates.")
                }
            }
        } catch (_: Exception) {}
        // Library names already MAPPED into us. Not a disk scan: the question is whether one is
        // inside this process, not whether one exists on the device.
        try {
            File("/proc/self/maps").takeIf { it.canRead() }?.useLines { seq ->
                val needles = listOf("frida", "gum-js-loop", "linjector", "gadget")
                val hit = seq.take(6000).firstOrNull { l ->
                    val lower = l.lowercase(); needles.any { lower.contains(it) }
                }
                if (hit != null) hits.add(
                    "This app's memory map contains an instrumentation library: " +
                        hit.trim().takeLast(80))
            }
        } catch (_: Exception) {}
        // A tool sitting on disk is NOT an attachment, and saying so matters: the owner may have
        // put it there doing their own research. Reported at its true weight.
        try {
            listOf(
                "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
                "/data/local/tmp/frida-agent.so", "/data/local/tmp/frida-gadget.so",
                "/sdcard/frida-server"
            ).filter { File(it).exists() }.forEach {
                hits.add("An instrumentation tool is PRESENT ON DISK at $it. This is a file, not " +
                    "an attachment: it does not by itself mean anything is running or attached " +
                    "to this app. Check whether you put it there. The findings that WOULD show " +
                    "live instrumentation are the thread-name and memory-map hits above and a " +
                    "non-zero TracerPid on Process integrity.")
            }
        } catch (_: Exception) {}
        return hits
    }

    /**
     * Device root posture. Deliberately NOT a finding: a rooted phone is the owner controlling
     * their own device. It is reported so the other results can be read in context.
     */
    private fun rootHeuristics(): List<String> {
        val hits = mutableListOf<String>()
        val su = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su", "/su/bin/su")
        su.firstOrNull { File(it).exists() }?.let { hits.add("su binary present at $it") }
        try {
            val pm = ctx.packageManager
            listOf(
                "com.topjohnwu.magisk", "eu.chainfire.supersu",
                "com.noshufou.android.su", "com.koushikdutta.superuser"
            ).forEach { pkg ->
                runCatching { pm.getPackageInfo(pkg, 0) }.onSuccess {
                    hits.add("root-manager app installed: $pkg")
                }
            }
        } catch (_: Exception) {}
        if ((Build.TAGS ?: "").contains("test-keys")) hits.add("build signed with test-keys")
        return hits
    }
}
