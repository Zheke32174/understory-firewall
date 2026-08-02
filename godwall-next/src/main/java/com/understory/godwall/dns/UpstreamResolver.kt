package com.understory.godwall.dns

import android.net.VpnService
import com.understory.godwall.chain.ChainDialer
import com.understory.godwall.chain.ProxyHop
import com.understory.security.Diagnostics
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Forwards one DNS query upstream and returns the wire response, over one of
 * three transports.
 *
 * What each branch actually does, verified against the bytes it writes:
 *
 *  - [Mode.PLAINTEXT]: a UDP datagram to :53. No confidentiality. Offered because
 *    a resolver you can only reach in the clear is still better than no resolver,
 *    but the UI labels it as unencrypted.
 *  - [Mode.DOT]: RFC 7858. Opens TLS to :853 and frames the query with the 2-byte
 *    big-endian length prefix DNS-over-TCP uses, then reads the same prefix back.
 *  - [Mode.DOH]: RFC 8484. Issues an HTTP/1.1 POST with
 *    `Content-Type: application/dns-message`, and parses BOTH `Content-Length`
 *    and `Transfer-Encoding: chunked` reply bodies, rejecting any non-2xx status.
 *
 * Both encrypted transports go through [openVerifiedTls], which sets an
 * [SNIHostName] and `endpointIdentificationAlgorithm = "HTTPS"` and then calls
 * `startHandshake()`, so a wrong certificate or hostname THROWS instead of
 * continuing. Every failure path returns null. Nothing here ever downgrades to
 * plaintext after an encrypted transport fails: the query goes unanswered, which
 * the caller can see, rather than silently leaking in the clear.
 *
 * The TCP carrier under TLS is opened by [openCarrier], which routes through the
 * egress chain when hops are configured and enabled. TLS is layered ON TOP of the
 * carrier, so the resolver's certificate is still verified end to end — a proxy
 * hop carries ciphertext and cannot forge answers. If a chain is enabled but
 * cannot be established, [openCarrier] returns null and the query is dropped; it
 * does not quietly egress direct.
 */
class UpstreamResolver private constructor(
    private val resolverIp: InetAddress,
    val mode: Mode,
    /** SNI + certificate-verification hostname for DoT/DoH. Null on plaintext. */
    private val tlsHostname: String?,
    /** Request path for DoH (e.g. "/dns-query"). Unused by the other modes. */
    private val dohPath: String,
) {

    enum class Mode { PLAINTEXT, DOT, DOH }

    fun describe(): String = when (mode) {
        Mode.DOT -> "DNS-over-TLS → $tlsHostname (${resolverIp.hostAddress}:853), certificate verified"
        Mode.DOH -> "DNS-over-HTTPS → https://$tlsHostname$dohPath (${resolverIp.hostAddress}:443), certificate verified"
        Mode.PLAINTEXT -> "plaintext UDP ${resolverIp.hostAddress}:53 — NOT encrypted"
    }

    /**
     * Resolve [query] (a DNS wire message) and return the wire response, or null
     * on any failure. [service] protects the socket from our own tun; pass null
     * when resolving from outside the tunnel, which is what the in-app upstream
     * test does.
     */
    fun resolve(service: VpnService?, query: ByteArray, hops: List<ProxyHop>, chainOn: Boolean): ByteArray? =
        when (mode) {
            Mode.DOT -> resolveDot(service, query, hops, chainOn)
            Mode.DOH -> resolveDoh(service, query, hops, chainOn)
            Mode.PLAINTEXT -> resolvePlaintext(service, query)
        }

    private fun resolvePlaintext(service: VpnService?, query: ByteArray): ByteArray? {
        val socket = DatagramSocket()
        return try {
            if (service != null && !service.protect(socket)) return null
            socket.soTimeout = TIMEOUT_MS
            socket.send(DatagramPacket(query, query.size, resolverIp, 53))
            val buf = ByteArray(BUF)
            val pkt = DatagramPacket(buf, buf.size)
            socket.receive(pkt)
            buf.copyOf(pkt.length)
        } catch (_: Throwable) {
            null
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun resolveDot(
        service: VpnService?,
        query: ByteArray,
        hops: List<ProxyHop>,
        chainOn: Boolean,
    ): ByteArray? {
        var raw: Socket? = null
        var ssl: SSLSocket? = null
        return try {
            val pair = openVerifiedTls(service, 853, hops, chainOn) ?: return null
            raw = pair.first; ssl = pair.second
            val out = ssl.outputStream
            out.write((query.size ushr 8) and 0xff)
            out.write(query.size and 0xff)
            out.write(query)
            out.flush()
            val ins = ssl.inputStream
            val hi = ins.read(); val lo = ins.read()
            if (hi < 0 || lo < 0) return null
            val len = (hi shl 8) or lo
            if (len <= 0 || len > MAX_DNS) return null
            readFully(ins, len)
        } catch (_: Throwable) {
            null // fail closed — never downgrade to plaintext
        } finally {
            runCatching { ssl?.close() }
            runCatching { raw?.close() }
        }
    }

    private fun resolveDoh(
        service: VpnService?,
        query: ByteArray,
        hops: List<ProxyHop>,
        chainOn: Boolean,
    ): ByteArray? {
        var raw: Socket? = null
        var ssl: SSLSocket? = null
        return try {
            val pair = openVerifiedTls(service, 443, hops, chainOn) ?: return null
            raw = pair.first; ssl = pair.second
            val header = buildString {
                append("POST ").append(dohPath).append(" HTTP/1.1\r\n")
                append("Host: ").append(tlsHostname).append("\r\n")
                append("Accept: application/dns-message\r\n")
                append("Content-Type: application/dns-message\r\n")
                append("Content-Length: ").append(query.size).append("\r\n")
                append("Connection: close\r\n\r\n")
            }
            val out = ssl.outputStream
            out.write(header.toByteArray(Charsets.US_ASCII))
            out.write(query)
            out.flush()
            readHttpBody(ssl.inputStream)
        } catch (_: Throwable) {
            null // fail closed
        } finally {
            runCatching { ssl?.close() }
            runCatching { raw?.close() }
        }
    }

    private fun openVerifiedTls(
        service: VpnService?,
        port: Int,
        hops: List<ProxyHop>,
        chainOn: Boolean,
    ): Pair<Socket, SSLSocket>? {
        val raw = openCarrier(service, port, hops, chainOn) ?: return null
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val ssl = factory.createSocket(raw, tlsHostname, port, true) as SSLSocket
        ssl.soTimeout = TIMEOUT_MS
        ssl.sslParameters = ssl.sslParameters.apply {
            if (tlsHostname != null) serverNames = listOf(SNIHostName(tlsHostname))
            endpointIdentificationAlgorithm = "HTTPS"
        }
        ssl.startHandshake() // throws on certificate / hostname mismatch
        return raw to ssl
    }

    private fun openCarrier(
        service: VpnService?,
        port: Int,
        hops: List<ProxyHop>,
        chainOn: Boolean,
    ): Socket? {
        val useChain = chainOn && hops.isNotEmpty()
        if (!useChain) {
            val raw = Socket()
            return try {
                if (service != null && !service.protect(raw)) {
                    runCatching { raw.close() }
                    return null
                }
                raw.soTimeout = TIMEOUT_MS
                raw.connect(InetSocketAddress(resolverIp, port), TIMEOUT_MS)
                raw
            } catch (_: Throwable) {
                runCatching { raw.close() }
                null
            }
        }
        val target = resolverIp.hostAddress ?: return null
        return when (val r = ChainDialer.dial(service, hops, target, port, TIMEOUT_MS)) {
            is ChainDialer.Result.Connected -> r.socket
            is ChainDialer.Result.Unavailable -> {
                Diagnostics.error(TAG, "encrypted DNS NOT sent — chain unavailable: ${r.reason}")
                null
            }
        }
    }

    private fun readFully(ins: InputStream, len: Int): ByteArray? {
        val resp = ByteArray(len)
        var off = 0
        while (off < len) {
            val n = ins.read(resp, off, len - off)
            if (n < 0) break
            off += n
        }
        return if (off == len) resp else null
    }

    /** Status line + headers, then body by Content-Length or chunked. Non-2xx is refused. */
    private fun readHttpBody(ins: InputStream): ByteArray? {
        val status = readLine(ins) ?: return null
        val code = status.split(' ').getOrNull(1)?.toIntOrNull() ?: return null
        if (code < 200 || code >= 300) return null
        var contentLength = -1
        var chunked = false
        while (true) {
            val line = readLine(ins) ?: return null
            if (line.isEmpty()) break
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            val name = line.substring(0, idx).trim().lowercase()
            val value = line.substring(idx + 1).trim()
            when (name) {
                "content-length" -> contentLength = value.toIntOrNull() ?: -1
                "transfer-encoding" -> if (value.lowercase().contains("chunked")) chunked = true
            }
        }
        return when {
            chunked -> readChunked(ins)
            contentLength in 0..MAX_DNS -> readFully(ins, contentLength)
            else -> null
        }
    }

    private fun readLine(ins: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val c = ins.read()
            if (c < 0) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n'.code) return sb.toString()
            if (c != '\r'.code) sb.append(c.toChar())
        }
    }

    private fun readChunked(ins: InputStream): ByteArray? {
        val acc = ByteArrayOutputStream()
        while (true) {
            val sizeLine = readLine(ins) ?: return null
            val size = sizeLine.trim().substringBefore(';').toIntOrNull(16) ?: return null
            if (size == 0) break
            if (acc.size() + size > MAX_DNS) return null
            val chunk = readFully(ins, size) ?: return null
            acc.write(chunk)
            readLine(ins)
        }
        return acc.toByteArray()
    }

    companion object {
        private const val TAG = "godwall.dns.UpstreamResolver"
        private const val TIMEOUT_MS = 5_000
        private const val BUF = 1500

        /** DNS-over-TCP length field is 16-bit, so no valid response exceeds this. */
        private const val MAX_DNS = 65_535

        private const val DEFAULT_IP = "1.1.1.1"

        private fun addrOf(ip: String): InetAddress =
            runCatching { InetAddress.getByName(ip.trim().ifBlank { DEFAULT_IP }) }
                .getOrElse { InetAddress.getByName(DEFAULT_IP) }

        fun plaintext(ip: String) =
            UpstreamResolver(addrOf(ip), Mode.PLAINTEXT, tlsHostname = null, dohPath = "")

        fun dot(ip: String, hostname: String) =
            UpstreamResolver(addrOf(ip), Mode.DOT, tlsHostname = hostname.trim(), dohPath = "")

        fun doh(ip: String, hostname: String, path: String = "/dns-query") =
            UpstreamResolver(
                addrOf(ip), Mode.DOH, tlsHostname = hostname.trim(),
                dohPath = path.trim().ifBlank { "/dns-query" }.let { if (it.startsWith("/")) it else "/$it" },
            )

        /** Curated resolvers: label, IP, verification hostname. Same set serves DoT and DoH. */
        val PRESETS: List<Triple<String, String, String>> = listOf(
            Triple("Cloudflare", "1.1.1.1", "cloudflare-dns.com"),
            Triple("Quad9 (malware-blocking)", "9.9.9.9", "dns.quad9.net"),
            Triple("Google", "8.8.8.8", "dns.google"),
            Triple("AdGuard (ad + tracker blocking)", "94.140.14.14", "dns.adguard-dns.com"),
            Triple("Mullvad (no-log)", "194.242.2.2", "dns.mullvad.net"),
        )
    }
}
