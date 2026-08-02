package com.understory.godwall.subsystem.tor

import android.content.Context
import com.understory.godwall.privilege.Privilege
import com.understory.godwall.subsystem.PrefixInstaller
import com.understory.security.Diagnostics
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64

/**
 * The client for tor's control port — the engine behind "New Tor identity".
 *
 * ## Why this is a real capability and not a button that lies
 *
 * "New Tor identity" is a `SIGNAL NEWNYM` on tor's control port; there is nothing to
 * signal without a tor process. So this connects to `127.0.0.1:ControlPort` from
 * Godwall's own process — loopback is shared across uids, the same property the
 * health probes rely on — authenticates with tor's cookie, and issues the signal.
 * Every path returns an honest [Result]: no control port open ⇒ "Tor is not
 * running", never a cheerful no-op.
 *
 * ## The cookie, and the one place privilege is needed
 *
 * `CookieAuthentication 1` makes tor write `control_auth_cookie` into its
 * DataDirectory as uid 2000. Godwall's own uid cannot read that file (SELinux
 * `shell_data_file`), so the 32 cookie bytes are pulled through Yojimbo's shell as
 * base64 and decoded here. The control *connection* itself needs no privilege — only
 * reading the cookie does. When no privileged shell is attached, that is reported as
 * the reason, distinct from "tor is down".
 */
object TorControl {

    private const val TAG = "godwall.subsystem.tor.TorControl"

    /** DataDirectory is {PREFIX}/home/tor; the cookie sits inside it. Prefix-relative. */
    private const val COOKIE_REL = "home/tor/control_auth_cookie"

    private const val CONNECT_TIMEOUT_MS = 3_000
    private const val READ_TIMEOUT_MS = 5_000

    data class Result(val ok: Boolean, val message: String)

    /**
     * Request a fresh circuit set (`SIGNAL NEWNYM`). Blocking — call off the main
     * thread. [controlPort] defaults to the configured control port.
     */
    fun newIdentity(context: Context, controlPort: Int = TorDaemonStore.snapshot(context).controlPort): Result {
        val cookie = readCookieHex()
            ?: return Result(false, cookieFailureReason())
        return withControl(controlPort) { reader, writer ->
            if (!authenticate(reader, writer, cookie)) {
                return@withControl Result(false, "Tor rejected control authentication. New identity not issued.")
            }
            send(writer, "SIGNAL NEWNYM")
            val line = reader.readLine().orEmpty()
            if (line.startsWith("250")) {
                Diagnostics.log(TAG, "NEWNYM issued")
                Result(true, "New Tor identity requested. New connections will use fresh circuits.")
            } else {
                Result(false, "Tor did not accept the new-identity signal: ${line.ifBlank { "no reply" }}")
            }
        }
    }

    /**
     * Tor's bootstrap percentage (0–100), or null when it cannot be read (tor down,
     * no cookie, or no privileged shell). Lets a status surface tell "listening" from
     * "connected to the Tor network" honestly rather than conflating them.
     */
    fun bootstrapPercent(context: Context, controlPort: Int = TorDaemonStore.snapshot(context).controlPort): Int? {
        val cookie = readCookieHex() ?: return null
        return withControl(controlPort) { reader, writer ->
            if (!authenticate(reader, writer, cookie)) return@withControl Result(false, "")
            send(writer, "GETINFO status/bootstrap-phase")
            // Reply: 250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done ...
            var pct: Int? = null
            while (true) {
                val line = reader.readLine() ?: break
                Regex("PROGRESS=(\\d+)").find(line)?.let { pct = it.groupValues[1].toIntOrNull() }
                if (line.startsWith("250 ") || line == "250 OK") break
                if (line.startsWith("5")) break
            }
            Result(pct != null, pct?.toString() ?: "")
        }.let { if (it.ok) it.message.toIntOrNull() else null }
    }

    // ---- internals ---------------------------------------------------------------

    private fun withControl(port: Int, body: (BufferedReader, OutputStreamWriter) -> Result): Result {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", port), CONNECT_TIMEOUT_MS)
                socket.soTimeout = READ_TIMEOUT_MS
                val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.US_ASCII))
                val writer = OutputStreamWriter(socket.getOutputStream(), Charsets.US_ASCII)
                body(reader, writer)
            }
        } catch (e: IOException) {
            Result(false, "Tor's control port (127.0.0.1:$port) is not answering — Tor is not running.")
        }
    }

    private fun authenticate(reader: BufferedReader, writer: OutputStreamWriter, cookieHex: String): Boolean {
        send(writer, "AUTHENTICATE $cookieHex")
        return reader.readLine().orEmpty().startsWith("250")
    }

    private fun send(writer: OutputStreamWriter, command: String) {
        writer.write(command)
        writer.write("\r\n")
        writer.flush()
    }

    /** The control cookie as hex, or null when it cannot be read. */
    private fun readCookieHex(): String? {
        if (!Privilege.isAvailable()) return null
        val path = PrefixInstaller.resolve(COOKIE_REL)
        val r = PrefixInstaller.exec(
            "[ -f " + PrefixInstaller.quote(path) + " ] || exit 3\n" +
                "base64 " + PrefixInstaller.quote(path),
        )
        if (!r.ok) return null
        val bytes = runCatching {
            Base64.getMimeDecoder().decode(r.out.trim().replace("\n", "").replace("\r", ""))
        }.getOrNull() ?: return null
        if (bytes.isEmpty()) return null
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun cookieFailureReason(): String =
        if (!Privilege.isAvailable()) {
            "No privileged shell is attached, so Tor's control cookie cannot be read. " +
                "New identity is unavailable until Yojimbo attaches one."
        } else {
            "Tor's control cookie is not present — Tor is not running, so there is no identity to renew."
        }
}
