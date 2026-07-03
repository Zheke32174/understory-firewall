package com.understory.elevation.shizuku

import android.os.SystemClock
import com.understory.elevation.IShellService
import com.understory.elevation.ShellResultParcel
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * The Shizuku UserService. Shizuku forks a process at the **granted shell uid**
 * (typically 2000, or root if the manager runs as root) and instantiates this
 * class by its no-arg constructor, then hands the app the [IShellService]
 * binder. Every `Runtime.exec` here therefore runs at that shell privilege —
 * this is what lets `appops`, `pm`, `cmd netpolicy`, `settings put`,
 * `am force-stop` succeed without root and without our app holding the
 * permissions itself.
 *
 * Declaration: this class is named in the [Shizuku.UserServiceArgs] the broker
 * builds (see Elevation.runShell / the README's UserServiceArgs pattern). It
 * lives in the CONSUMING app's process image (the app depends on :elevation),
 * so Shizuku can load it by name.
 *
 * Shizuku's server calls the no-arg constructor. A Context-taking constructor
 * is also supported by the Shizuku API; we keep the no-arg form because the
 * shell contract needs no Context.
 */
class ShellUserService : IShellService.Stub() {

    override fun runCommand(cmd: Array<out String>?, timeoutMs: Long): ShellResultParcel {
        val argv = cmd?.filterNotNull()?.toTypedArray()
            ?: return ShellResultParcel(-1, "", "empty command")
        if (argv.isEmpty()) return ShellResultParcel(-1, "", "empty command")

        return try {
            val proc = Runtime.getRuntime().exec(argv)

            // Drain both streams on separate threads so a chatty stderr can
            // never deadlock a full stdout pipe buffer (or vice-versa).
            val outSb = StringBuilder()
            val errSb = StringBuilder()
            val outT = drainThread(proc.inputStream, outSb)
            val errT = drainThread(proc.errorStream, errSb)

            val exit: Int
            if (timeoutMs > 0L) {
                val deadline = SystemClock.elapsedRealtime() + timeoutMs
                var finished = false
                while (SystemClock.elapsedRealtime() < deadline) {
                    try {
                        proc.exitValue() // throws IllegalThreadStateException while running
                        finished = true
                        break
                    } catch (_: IllegalThreadStateException) {
                        Thread.sleep(20)
                    }
                }
                if (!finished) {
                    proc.destroy()
                    outT.join(250)
                    errT.join(250)
                    return ShellResultParcel(
                        -1,
                        outSb.toString(),
                        (errSb.toString() + "\n[elevation] command timed out after ${timeoutMs}ms").trim(),
                    )
                }
                exit = proc.exitValue()
            } else {
                exit = proc.waitFor()
            }

            outT.join(500)
            errT.join(500)
            ShellResultParcel(exit, outSb.toString(), errSb.toString())
        } catch (t: Throwable) {
            ShellResultParcel(-1, "", t.message ?: t.javaClass.simpleName)
        }
    }

    override fun destroy() {
        // Best-effort self-termination of the Shizuku-hosted process.
        System.exit(0)
    }

    private fun drainThread(stream: java.io.InputStream, into: StringBuilder): Thread {
        val t = Thread {
            try {
                BufferedReader(InputStreamReader(stream)).use { r ->
                    val buf = CharArray(4096)
                    while (true) {
                        val n = r.read(buf)
                        if (n < 0) break
                        synchronized(into) { into.append(buf, 0, n) }
                    }
                }
            } catch (_: Throwable) {
                // Stream closed as the process exits — nothing to do.
            }
        }
        t.isDaemon = true
        t.start()
        return t
    }
}
