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
    private fun fridaHeuristics(): List<String> {
        val hits = mutableListOf<String>()
        try {
            if (portOpen(27042)) hits.add("port 27042")
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
            val knownServerPaths = listOf("/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server")
            if (knownServerPaths.any { File(it).exists() }) hits.add("frida-server binary present")
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
