package com.understory.firewall.chain

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * A REAL HTTP CONNECT tunnel client (RFC 9110 §9.3.6 / the classic proxy CONNECT).
 *
 * Like [Socks5Client] this runs over an ALREADY-CONNECTED stream pair so hops
 * compose: after [connectThrough] returns, the same stream is a transparent tunnel
 * to the target and the next hop can handshake over it.
 *
 * Pure userspace, no external dependency.
 */
internal object HttpConnectClient {

    /** A proxy that answers a CONNECT with megabytes of headers is not one we humour. */
    private const val MAX_HEADER_BYTES = 16 * 1024
    private const val MAX_LINE_BYTES = 4 * 1024

    /**
     * Issue `CONNECT targetHost:targetPort` and consume the response so the stream is
     * left positioned exactly at the start of tunnelled payload.
     *
     * The target host is sent verbatim — resolution happens AT THE PROXY, never locally,
     * so the destination is not leaked to the local resolver.
     *
     * @throws IOException on any non-2xx status or malformed response. It fails loudly
     *   on purpose: silently continuing would send payload to a proxy that never opened
     *   the tunnel.
     */
    fun connectThrough(
        input: InputStream,
        output: OutputStream,
        targetHost: String,
        targetPort: Int,
        username: String = "",
        password: String = "",
    ) {
        val authority = formatAuthority(targetHost, targetPort)
        val req = buildString {
            append("CONNECT ").append(authority).append(" HTTP/1.1\r\n")
            append("Host: ").append(authority).append("\r\n")
            if (username.isNotEmpty()) {
                // java.util.Base64 (API 26+, we are minSdk 33) rather than android.util.Base64:
                // it is the same encoding without the Android stub, so this stays unit-testable
                // on a plain JVM.
                val token = java.util.Base64.getEncoder()
                    .encodeToString("$username:$password".toByteArray(Charsets.UTF_8))
                append("Proxy-Authorization: Basic ").append(token).append("\r\n")
            }
            // Ask the proxy not to collapse the tunnel; CONNECT semantics keep it open.
            append("Proxy-Connection: Keep-Alive\r\n")
            append("\r\n")
        }
        output.write(req.toByteArray(Charsets.US_ASCII))
        output.flush()

        val status = readLine(input) ?: throw IOException("HTTP CONNECT: proxy closed before replying")
        val code = parseStatusCode(status)
            ?: throw IOException("HTTP CONNECT: malformed status line \"${status.take(80)}\"")
        // Drain headers regardless of status so the stream is never left mid-response.
        var consumed = status.length
        while (true) {
            val line = readLine(input) ?: throw IOException("HTTP CONNECT: stream ended inside headers")
            consumed += line.length + 2
            if (consumed > MAX_HEADER_BYTES) throw IOException("HTTP CONNECT: response headers too large")
            if (line.isEmpty()) break
        }
        if (code !in 200..299) {
            throw IOException("HTTP CONNECT: proxy refused with status $code (${status.take(80)})")
        }
    }

    /** IPv6 literals must be bracketed in an authority. */
    private fun formatAuthority(host: String, port: Int): String =
        if (host.contains(':') && !host.startsWith("[")) "[$host]:$port" else "$host:$port"

    /** "HTTP/1.1 200 Connection established" -> 200. */
    private fun parseStatusCode(statusLine: String): Int? {
        val parts = statusLine.split(' ')
        if (parts.size < 2) return null
        if (!parts[0].startsWith("HTTP/")) return null
        return parts[1].toIntOrNull()
    }

    /**
     * Read one CRLF-terminated line WITHOUT buffering ahead. Reading a byte at a time
     * is deliberate: a buffered reader would swallow the first bytes of tunnelled
     * payload into its buffer, corrupting the stream the caller is about to use.
     */
    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n'.code) return sb.toString()
            if (c != '\r'.code) {
                sb.append(c.toChar())
                if (sb.length > MAX_LINE_BYTES) throw IOException("HTTP CONNECT: response line too long")
            }
        }
    }
}
