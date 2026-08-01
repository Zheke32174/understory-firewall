package com.ant.emichaosbg

/**
 * Runs inside a separate `app_process` hosted by Shizuku, with whatever privilege the
 * user's Shizuku setup grants (adb shell, or root on a rooted device). Shizuku
 * instantiates this class via a no-arg constructor and binds [IShizukuDiagService]
 * against it — see [ShizukuBridge.runDiagnostic].
 *
 * ALLOWLIST IS THE WHOLE SAFETY MODEL: every entry below is a fixed, read-only
 * diagnostic command. There is no free-form exec, no write path, no AT-command
 * injection, and nothing here can key up a radio or touch `/dev/diag` for anything
 * beyond a presence/permission check. Extend the allowlist only with commands that
 * are similarly inert and read-only.
 */
class ShizukuUserService : IShizukuDiagService.Stub() {

    companion object {
        // key -> shell command. Every command here is read-only.
        val ALLOWLIST: Map<String, Array<String>> = mapOf(
            "telephony_registry" to arrayOf("dumpsys", "telephony.registry"),
            "props" to arrayOf("getprop"),
            "connectivity" to arrayOf("dumpsys", "connectivity"),
            // Presence/permission check only — never reads diag frames. Real QMDL/DIAG
            // capture and parsing is a substantial protocol-reverse-engineering effort
            // that this project intentionally does not duplicate; see EFF's Rayhunter
            // (https://github.com/EFForg/rayhunter), which already does this properly.
            // This entry only reports whether the node exists and what its permission
            // bits look like, so the UI can say "diag access looks possible here" —
            // it is a hint, not a detector.
            "diag_probe" to arrayOf("sh", "-c", "ls -la /dev/diag* 2>&1 || echo 'no /dev/diag node'")
        )
    }

    override fun runDiagnostic(key: String): String {
        val cmd = ALLOWLIST[key] ?: return "error: '$key' is not on the read-only allowlist"
        return try {
            val proc = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            val out = proc.inputStream.bufferedReader().readText()
            proc.waitFor()
            if (out.length > 20_000) out.substring(0, 20_000) + "\n...(truncated)" else out
        } catch (e: Exception) {
            "error: ${e.message}"
        }
    }

    override fun remoteUid(): Int = android.os.Process.myUid()

    override fun destroy() {
        // Shizuku tears the hosting process down; nothing to release here.
    }
}
