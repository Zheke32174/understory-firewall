package com.ant.emichaosbg

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.Debug
import android.webkit.JavascriptInterface
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.security.MessageDigest

/**
 * `window.EMITamper` — read-only app-integrity indicators, exposed to the JS UI as a
 * status readout. Detect-and-report only: nothing here blocks the app from running, wipes
 * data, or does anything punitive. It answers one question — "is this APK's own signing
 * certificate and runtime environment what I'd expect" — and lets the UI show a plain
 * status. Standard, widely-used mobile hardening technique (the same category of check
 * banking and DRM apps ship) aimed at making casual APK modification and dynamic
 * instrumentation (Frida) more visible, not "unhackable."
 */
class TamperGuard(private val ctx: Context) {

    @JavascriptInterface
    fun getIntegrityStatus(): String {
        val o = JSONObject()
        val findings = JSONArray()

        val sigResult = checkSignature()
        o.put("signatureOk", sigResult.first)
        o.put("signatureHash", sigResult.second)
        if (!sigResult.first) findings.put("signature mismatch or unreadable")

        val debuggerAttached = try { Debug.isDebuggerConnected() || Debug.waitingForDebugger() } catch (_: Exception) { false }
        o.put("debuggerAttached", debuggerAttached)
        if (debuggerAttached) findings.put("debugger attached")

        val fridaHints = fridaHeuristics()
        o.put("fridaSuspicion", fridaHints.isNotEmpty())
        if (fridaHints.isNotEmpty()) findings.put("possible Frida/injection: " + fridaHints.joinToString(", "))

        val rootHints = rootHeuristics()
        o.put("rootSuspicion", rootHints.isNotEmpty())
        if (rootHints.isNotEmpty()) findings.put("possible root: " + rootHints.joinToString(", "))

        o.put("findings", findings)
        o.put("clean", findings.length() == 0)
        return o.toString()
    }

    /** Compares the running APK's signing certificate SHA-256 against the one this build
     *  was compiled with (baked in at build time via [expectedSignatureHash]). A tampered/
     *  re-signed APK will have a different certificate and fail this check. */
    private fun checkSignature(): Pair<Boolean, String> {
        try {
            val pm = ctx.packageManager
            val sigs: Array<Signature> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = info.signingInfo
                if (signingInfo?.hasMultipleSigners() == true) signingInfo.apkContentsSigners
                else signingInfo?.signingCertificateHistory ?: emptyArray()
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info.signatures ?: emptyArray()
            }
            if (sigs.isEmpty()) return Pair(false, "")
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(sigs[0].toByteArray()).joinToString("") { "%02x".format(it) }
            val expected = BuildConfigLike.expectedSignatureHash
            // If no expected hash has been pinned for this build (e.g. a fresh debug keystore
            // that changes per machine), report the hash without failing the check — there's
            // nothing meaningful to compare against yet. Pin EXPECTED_SIGNATURE_HASH for a
            // release build to make this a real tamper check.
            val ok = expected.isBlank() || expected.equals(hash, ignoreCase = true)
            return Pair(ok, hash)
        } catch (_: Exception) {
            return Pair(false, "")
        }
    }

    /** Frida's default tooling leaves a handful of common traces: its default TCP port,
     *  characteristic thread/library names once injected, and (for frida-server on rooted
     *  devices) a well-known binary path. Any single hint is circumstantial; several
     *  together are a real signal. This never blocks anything — it only informs the UI. */
    /**
     * Expanded because a real detection was reported in the field, and the original set was
     * too coarse to tell a genuine hook from a false positive.
     *
     * Each hit now names WHAT matched, so the finding can be judged rather than taken on
     * faith. That matters: the single most common false positive is an unrelated process
     * holding 27042, and "possible Frida" with no detail is unactionable either way.
     *
     * Still detect-and-report only. Deliberately no anti-debug retaliation, no self-kill, no
     * crash-on-detect: those are trivially bypassed by the very tooling they target, and they
     * turn a false positive into a bricked app for an ordinary user.
     */
    private fun fridaHeuristics(): List<String> {
        val hits = mutableListOf<String>()
        // Default and commonly-used alternate frida-server ports.
        try {
            for (p in intArrayOf(27042, 27043, 27047)) if (portOpen(p)) hits.add("listening port $p")
        } catch (_: Exception) {}
        // Frida's gadget/agent spawns recognisable threads. Reading our own task list is
        // cheap and is one of the few signals that survives a renamed binary.
        try {
            File("/proc/self/task").listFiles()?.take(400)?.forEach { t ->
                val nameFile = File(t, "comm")
                if (nameFile.canRead()) {
                    val n = nameFile.readText().trim().lowercase()
                    if (n == "gmain" || n == "gdbus" || n.startsWith("gum-js") || n.contains("frida") || n == "pool-frida") {
                        hits.add("thread name '$n'")
                    }
                }
            }
        } catch (_: Exception) {}
        // A hooking engine has to make pages writable+executable to install trampolines.
        try {
            File("/proc/self/maps").takeIf { it.canRead() }?.let { f ->
                var rwx = 0
                BufferedReader(InputStreamReader(f.inputStream())).use { r ->
                    var line: String?; var n = 0
                    while (r.readLine().also { line = it } != null && n < 6000) {
                        n++
                        val l = line ?: continue
                        if (l.contains(" rwxp ")) rwx++
                    }
                }
                if (rwx > 0) hits.add("$rwx writable+executable mapping(s)")
            }
        } catch (_: Exception) {}
        try {
            File("/proc/self/maps").takeIf { it.canRead() }?.let { f ->
                BufferedReader(InputStreamReader(f.inputStream())).use { r ->
                    val needles = listOf("frida", "gum-js-loop", "gmain", "linjector")
                    var line: String?
                    var lines = 0
                    while (r.readLine().also { line = it } != null && lines < 4000) {
                        lines++
                        val l = line?.lowercase() ?: continue
                        if (needles.any { l.contains(it) }) { hits.add("proc/maps: matched loaded-library hint"); break }
                    }
                }
            }
        } catch (_: Exception) {}
        try {
            val knownServerPaths = listOf(
                "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
                "/data/local/tmp/frida-agent.so", "/data/local/tmp/frida-gadget.so",
                "/sdcard/frida-server", "/data/local/tmp/re.frida.server.so"
            )
            /* A FILE ON DISK IS NOT AN ATTACHMENT, AND SAYING SO MATTERS.
             *
             * This reported "possible Frida/injection: binary present: /data/local/tmp/
             * frida-server" at the same weight as evidence of actual instrumentation. Those are
             * different claims by a wide margin: the binary sitting there means someone — very
             * possibly the device's owner, doing their own research — pushed a tool onto the
             * device at some point. It does not mean it is running, and it certainly does not
             * mean it is attached to THIS process.
             *
             * Overstating it is expensive in both directions. A user who put it there learns to
             * dismiss the alert, and then dismisses it on the day it matters. A user who did not
             * put it there is told they are compromised on evidence that does not support it.
             *
             * So the finding now says exactly what was observed, and names the checks that WOULD
             * indicate attachment — a listening frida port, the maps/thread-name hints, and
             * EscalationGuard's TracerPid — so the two can be read together instead of confused.
             */
            knownServerPaths.filter { File(it).exists() }.forEach {
                hits.add("instrumentation tool PRESENT ON DISK at $it — this is a file, not an " +
                    "attachment: it does not by itself mean anything is running or attached to " +
                    "this app. Check whether you put it there. The findings that would indicate " +
                    "live instrumentation are a listening Frida port, matching entries in this " +
                    "process's memory map, and a non-zero TracerPid on the Escalation guard")
            }
        } catch (_: Exception) {}
        return hits
    }

    private fun portOpen(port: Int): Boolean {
        return try {
            val socket = java.net.Socket()
            socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 150)
            socket.close()
            true
        } catch (_: Exception) { false }
    }

    private fun rootHeuristics(): List<String> {
        val hits = mutableListOf<String>()
        val suBinaries = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su", "/su/bin/su")
        if (suBinaries.any { File(it).exists() }) hits.add("su binary present")
        val rootApps = listOf(
            "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su", "com.koushikdutta.superuser"
        )
        try {
            val pm = ctx.packageManager
            if (rootApps.any { pkg -> try { pm.getPackageInfo(pkg, 0); true } catch (_: PackageManager.NameNotFoundException) { false } })
                hits.add("root-manager app installed")
        } catch (_: Exception) {}
        if ((Build.TAGS ?: "").contains("test-keys")) hits.add("test-keys build tag")
        return hits
    }
}

/** Placeholder for a build-time-pinned expected signature hash. Left blank by default
 *  (the debug keystore's hash changes per build machine, so pinning it here would make
 *  every debug build "fail" its own check) — set EXPECTED_SIGNATURE_HASH for a release
 *  build signed with a stable, known keystore to make the signature check meaningful. */
object BuildConfigLike {
    const val expectedSignatureHash: String = ""
}
