package com.understory.firewall

import android.content.Context
import com.understory.security.Diagnostics
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.SSLSocketFactory

/**
 * Egress canaries (design-v2/firewall.md §5.6): the empirical "is my
 * DNS/egress actually what I think" proof — the honest substitute for
 * claiming to read Tailscale's DNS/exit state.
 *
 * STRICT RULES to preserve the no-telemetry posture (CD-4):
 *   - Explicit-tap-only. Nothing fires on screen open; each probe is a
 *     button the caller wires.
 *   - Named endpoint on the button face — the user sees the exact host
 *     before tapping (the [Probe.host] constants below).
 *   - All calls on Dispatchers.IO with short timeouts; the raw response is
 *     surfaced for Diagnostics.
 *
 * INTERNET is already held (manifest). No other permission needed.
 */
object CanaryProbes {

    private const val TIMEOUT_MS = 6_000

    /** The default probe set. Each names its exact host for the UI. */
    enum class Probe(val title: String, val host: String, val description: String) {
        EGRESS_IP(
            "Egress IP",
            "api.ipify.org",
            "Shows the public IP your traffic exits from — a Tailscale exit " +
                "node or your local ISP.",
        ),
        RESOLVER_IDENTITY(
            "Resolver identity / DNS leak",
            "1.1.1.1/cdn-cgi/trace",
            "Reports which resolver POP answered. If it isn't the Private DNS " +
                "provider you configured, your DNS may be routed elsewhere " +
                "(e.g. a Tailscale exit node).",
        ),
        DOT_REACH(
            "DoT reachability",
            "<configured>:853",
            "TLS-connects to your configured Private DNS host on port 853 — " +
                "success/fail only, no query sent.",
        ),
    }

    /** One probe outcome. [ok] is the coarse verdict; [detail] is the
     *  human line; [raw] is the full response for Diagnostics. */
    data class ProbeResult(val ok: Boolean, val detail: String, val raw: String)

    /** Egress IP via a plain GET. Returns the observed public IP. */
    fun egressIp(): ProbeResult = httpGet("https://api.ipify.org")
        .fold(
            onSuccess = { body ->
                val ip = body.trim()
                ProbeResult(ip.isNotBlank(), "Public egress IP: $ip", body)
            },
            onFailure = { err(it) },
        )

    /** Resolver identity / DNS-leak indicator via Cloudflare's trace. */
    fun resolverIdentity(): ProbeResult = httpGet("https://1.1.1.1/cdn-cgi/trace")
        .fold(
            onSuccess = { body ->
                // The trace body is key=value lines; surface the resolver POP.
                val colo = body.lineSequence()
                    .firstOrNull { it.startsWith("colo=") }?.substringAfter("=")
                val loc = body.lineSequence()
                    .firstOrNull { it.startsWith("loc=") }?.substringAfter("=")
                val detail = buildString {
                    append("Answered by Cloudflare POP ")
                    append(colo ?: "?")
                    if (loc != null) append(" ($loc)")
                    append(". If you configured a different Private DNS provider, ")
                    append("compare — a mismatch can indicate DNS routed via a VPN/exit node.")
                }
                ProbeResult(colo != null, detail, body)
            },
            onFailure = { err(it) },
        )

    /**
     * DoT reachability: TLS-connect to [host]:853 with SNI = host. No DNS
     * query is sent — success means the port is reachable and negotiates
     * TLS. [host] is the configured Private DNS specifier; if it's blank
     * the caller should not offer this probe.
     */
    fun dotReachability(host: String): ProbeResult {
        if (host.isBlank()) {
            return ProbeResult(false, "No Private DNS host is configured.", "")
        }
        var socket: java.net.Socket? = null
        return try {
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val plain = Socket()
            plain.connect(InetSocketAddress(host, 853), TIMEOUT_MS)
            val ssl = factory.createSocket(plain, host, 853, true) as javax.net.ssl.SSLSocket
            socket = ssl
            ssl.soTimeout = TIMEOUT_MS
            ssl.startHandshake()
            ProbeResult(true, "TLS to $host:853 succeeded.", "handshake ok: ${ssl.session.protocol}")
        } catch (t: Throwable) {
            Diagnostics.error("firewall.CanaryProbes", "dotReachability($host) failed: ${t.message}")
            ProbeResult(false, "TLS to $host:853 failed: ${t.javaClass.simpleName}", t.message ?: "")
        } finally {
            runCatching { socket?.close() }
        }
    }

    // ---------------------------------------------------------------

    private fun httpGet(urlStr: String): Result<String> = runCatching {
        val url = URL(urlStr)
        val conn = url.openConnection() as HttpURLConnection
        conn.connectTimeout = TIMEOUT_MS
        conn.readTimeout = TIMEOUT_MS
        conn.requestMethod = "GET"
        conn.instanceFollowRedirects = false
        try {
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader()?.use(BufferedReader::readText).orEmpty()
            if (code !in 200..299) {
                throw java.io.IOException("HTTP $code")
            }
            body
        } finally {
            conn.disconnect()
        }
    }

    private fun err(t: Throwable): ProbeResult {
        Diagnostics.error("firewall.CanaryProbes", "probe failed: ${t.message}")
        return ProbeResult(false, "Failed: ${t.javaClass.simpleName}: ${t.message}", t.message ?: "")
    }
}
