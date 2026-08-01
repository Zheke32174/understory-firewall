package com.understory.firewall.tunnel

import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.understory.net.engine.DnsBlocklist
import com.understory.net.engine.DnsMessage
import com.understory.net.engine.VpnPacketParser
import com.understory.security.Diagnostics
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The adblock-DNS filtering loop (S6) — the REAL core of the standalone tunnel
 * tier. Reads DNS queries off the tun, checks each domain against the on-device
 * [DnsBlocklist], SINKHOLES blocked domains (NXDOMAIN / 0.0.0.0) without any
 * upstream round-trip, and FORWARDS allowed queries to the configured upstream
 * resolver over a [VpnService.protect]ed socket (so the forward bypasses our own
 * tun). Attributes each query to its owning app via [ConnectionAttributor] and
 * records it to [DnsEventLog] for the visibility surface (S7).
 *
 * This reuses the salvaged [VpnPacketParser] (IPv4+UDP parse + response build)
 * and [DnsMessage] (query parse + sinkhole build), so the hard-won packet
 * correctness is shared, not re-derived.
 *
 * SCOPE / HONESTY (what is REAL here vs stubbed):
 *   REAL: IPv4/UDP DNS capture on the tun's DNS route, blocklist match with
 *         parent-domain semantics, NXDOMAIN/zero-IP sinkhole, upstream forward
 *         to a plaintext resolver (system or user-set IP), per-app attribution,
 *         event logging.
 *   REAL (added): ENCRYPTED upstream via DNS-over-TLS (RFC 7858). When a DoT
 *         hostname is configured, allowed queries forward over verified TLS to
 *         :853 (SNI + HTTPS endpoint identification, fail-closed on a bad cert),
 *         framed with the DNS-over-TCP length prefix — see [UpstreamResolver.dot].
 *         This is the in-tunnel encrypted upstream that InviZible Pro / RethinkDNS
 *         centre on, native here rather than via a bundled resolver daemon. Blank
 *         hostname ⇒ the plaintext UDP path below.
 *   STILL NOT IMPLEMENTED: DoH/DNSCrypt/Tor upstreams (DoT is the implemented
 *         encrypted transport). System Private DNS (S4) remains available for the
 *         system resolver path.
 *   IPv6 DNS: not filtered here (parser is v4). The tun claims only the v4 DNS
 *         route, so v6 DNS is not captured — it flows normally, unfiltered. The
 *         UI states this boundary.
 */
class DnsFilterTun(
    private val service: VpnService,
    private val tun: ParcelFileDescriptor,
    private val fakeDnsIp: InetAddress,
    private val upstream: UpstreamResolver,
    private val attributor: ConnectionAttributor,
    private val blocklistProvider: () -> DnsBlocklist,
    private val answerStyle: DnsMessage.BlockAnswer,
) : Runnable {

    private val running = AtomicBoolean(true)
    @Volatile private var lastError: String? = null

    fun stop() = running.set(false)

    override fun run() {
        val input = FileInputStream(tun.fileDescriptor)
        val output = FileOutputStream(tun.fileDescriptor)
        val buf = ByteArray(MTU)
        Diagnostics.log(TAG, "DNS-filter loop started (upstream=${upstream.describe()})")

        while (running.get()) {
            val n = try { input.read(buf) } catch (_: Throwable) { break }
            if (n < 0) break
            if (n < 28) continue

            val parsed = VpnPacketParser.parseIpv4Udp(buf, n) ?: continue
            // Only DNS to our advertised fake resolver enters here (the tun
            // routes just that IP), but double-check dst IP + port so a stray
            // packet is never mis-forwarded.
            if (parsed.dstPort != VpnPacketParser.DNS_PORT) continue
            if (parsed.dstIp != fakeDnsIp) continue

            val payload = buf.copyOfRange(parsed.payloadOffset, parsed.payloadOffset + parsed.payloadLen)
            val question = DnsMessage.parseFirstQuestion(payload)
            val domain = question?.name.orEmpty()

            // Attribute to app (best-effort; tun-scoped). Uses the query's
            // src/dst for getConnectionOwnerUid.
            val uid = attributor.uidFor(
                protocol = ConnectionAttributor.PROTO_UDP,
                srcIp = parsed.srcIp.hostAddress ?: "",
                srcPort = parsed.srcPort,
                dstIp = parsed.dstIp.hostAddress ?: "",
                dstPort = parsed.dstPort,
            )
            val label = attributor.labelFor(uid)

            val blocked = domain.isNotEmpty() && blocklistProvider().isBlocked(domain)
            if (domain.isNotEmpty()) {
                DnsEventLog.record(domain, label, uid, blocked)
            }

            val responsePayload: ByteArray? = if (blocked) {
                DnsMessage.buildBlockedResponse(payload, answerStyle)
            } else {
                upstream.resolve(service, payload)
            }
            if (responsePayload == null) continue

            val outPacket = VpnPacketParser.buildIpv4UdpResponse(parsed, responsePayload)
            try {
                output.write(outPacket)
            } catch (_: Throwable) {
                // Tun closed mid-write; app sees a timeout, loop exits next read.
            }
        }
        Diagnostics.log(TAG, "DNS-filter loop ended")
    }

    /**
     * Forward an allowed DNS query to a PLAINTEXT upstream resolver and return
     * the response payload. Encrypted-resolver routing is a documented STUB —
     * see [encrypted].
     */
    class UpstreamResolver private constructor(
        private val resolverIp: InetAddress,
        private val encrypted: Boolean,
        /** SNI + certificate-verification hostname for DoT. Null on the plaintext path. */
        private val tlsHostname: String?,
    ) {
        fun describe(): String =
            if (encrypted) "DNS-over-TLS → $tlsHostname (${resolverIp.hostAddress}:853), verified"
            else "plaintext UDP ${resolverIp.hostAddress}:53"

        fun resolve(service: VpnService, query: ByteArray): ByteArray? =
            if (encrypted) resolveDot(service, query) else resolvePlaintext(service, query)

        private fun resolvePlaintext(service: VpnService, query: ByteArray): ByteArray? {
            val socket = DatagramSocket()
            return try {
                if (!service.protect(socket)) return null
                socket.soTimeout = DNS_TIMEOUT_MS
                socket.send(DatagramPacket(query, query.size, resolverIp, 53))
                val rbuf = ByteArray(MTU)
                val pkt = DatagramPacket(rbuf, rbuf.size)
                socket.receive(pkt)
                rbuf.copyOf(pkt.length)
            } catch (_: Throwable) {
                null
            } finally {
                runCatching { socket.close() }
            }
        }

        /**
         * REAL DNS-over-TLS (RFC 7858) — the encrypted upstream InviZible Pro and RethinkDNS
         * centre on, done natively inside the filter tunnel rather than by bundling a resolver
         * daemon. The underlying TCP socket is [VpnService.protect]ed BEFORE the TLS handshake so
         * the forward bypasses our own tun; SNI is set and endpoint identification is set to
         * "HTTPS" so the handshake FAILS CLOSED on a certificate/hostname mismatch — an
         * encrypted resolver that does not authenticate its peer is theatre, so this refuses to
         * fall back to plaintext on failure (it returns null and the query simply goes
         * unanswered, which the caller surfaces). Frames the query with the 2-byte length prefix
         * DoT uses (DNS-over-TCP framing).
         */
        private fun resolveDot(service: VpnService, query: ByteArray): ByteArray? {
            var raw: java.net.Socket? = null
            var ssl: javax.net.ssl.SSLSocket? = null
            return try {
                raw = java.net.Socket()
                if (!service.protect(raw)) return null
                raw.connect(java.net.InetSocketAddress(resolverIp, 853), DNS_TIMEOUT_MS)
                val factory = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory
                ssl = factory.createSocket(raw, tlsHostname, 853, true) as javax.net.ssl.SSLSocket
                ssl.soTimeout = DNS_TIMEOUT_MS
                ssl.sslParameters = ssl.sslParameters.apply {
                    if (tlsHostname != null) serverNames = listOf(javax.net.ssl.SNIHostName(tlsHostname))
                    endpointIdentificationAlgorithm = "HTTPS"   // fail closed on bad cert/hostname
                }
                ssl.startHandshake()                            // throws on verification failure
                val out = ssl.outputStream
                out.write((query.size ushr 8) and 0xff)
                out.write(query.size and 0xff)
                out.write(query)
                out.flush()
                val ins = ssl.inputStream
                val hi = ins.read(); val lo = ins.read()
                if (hi < 0 || lo < 0) return null
                val len = (hi shl 8) or lo
                if (len <= 0 || len > 65_535) return null
                val resp = ByteArray(len)
                var off = 0
                while (off < len) {
                    val n = ins.read(resp, off, len - off)
                    if (n < 0) break
                    off += n
                }
                if (off == len) resp else null
            } catch (_: Throwable) {
                null   // fail closed — never silently downgrade to plaintext
            } finally {
                runCatching { ssl?.close() }
                runCatching { raw?.close() }
            }
        }

        companion object {
            /** Default resolver if the user's IP is blank/malformed. */
            private const val DEFAULT_IP = "1.1.1.1"

            /** Plaintext UDP resolver at [ip]. A blank/garbage IP falls back to [DEFAULT_IP]. */
            fun plaintext(ip: String): UpstreamResolver {
                val addr = runCatching { InetAddress.getByName(ip.trim().ifBlank { DEFAULT_IP }) }
                    .getOrElse { InetAddress.getByName(DEFAULT_IP) }
                return UpstreamResolver(addr, encrypted = false, tlsHostname = null)
            }

            /**
             * REAL encrypted upstream: DNS-over-TLS to [ip] on :853, authenticated against
             * [hostname]. [hostname] is required — DoT without a verified hostname is not
             * encryption you can trust. Known-good pairs are in [DOT_PRESETS].
             */
            fun dot(ip: String, hostname: String): UpstreamResolver {
                val addr = runCatching { InetAddress.getByName(ip.trim().ifBlank { DEFAULT_IP }) }
                    .getOrElse { InetAddress.getByName(DEFAULT_IP) }
                return UpstreamResolver(addr, encrypted = true, tlsHostname = hostname.trim())
            }

            /** Curated DoT resolvers (ip → SNI/verification hostname). */
            val DOT_PRESETS: List<Triple<String, String, String>> = listOf(
                Triple("Cloudflare", "1.1.1.1", "cloudflare-dns.com"),
                Triple("Quad9 (malware-blocking)", "9.9.9.9", "dns.quad9.net"),
                Triple("Google", "8.8.8.8", "dns.google"),
                Triple("AdGuard (ad+tracker-blocking)", "94.140.14.14", "dns.adguard-dns.com"),
                Triple("Mullvad (no-log)", "194.242.2.2", "dns.mullvad.net"),
            )
        }
    }

    companion object {
        private const val TAG = "firewall.tunnel.DnsFilterTun"
        private const val MTU = 1500
        private const val DNS_TIMEOUT_MS = 5_000
    }
}
