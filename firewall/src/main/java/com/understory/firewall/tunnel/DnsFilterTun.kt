package com.understory.firewall.tunnel

import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.understory.net.engine.DnsBlocklist
import com.understory.net.engine.DnsMessage
import com.understory.net.engine.VpnPacketParser
import com.understory.net.engine.crypto.CryptoSelfTest
import com.understory.net.engine.dnscrypt.DnsStamp
import com.understory.net.engine.dnscrypt.DnscryptClient
import com.understory.security.Diagnostics
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.SecureRandom
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

            // Packet capture (PCAPdroid-style): the raw DNS query packet as it enters the tun.
            PcapController.record(buf, 0, n)

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
            // Capture the response packet (sinkholed or forwarded) too.
            PcapController.record(outPacket, 0, outPacket.size)
            try {
                output.write(outPacket)
            } catch (_: Throwable) {
                // Tun closed mid-write; app sees a timeout, loop exits next read.
            }
        }
        Diagnostics.log(TAG, "DNS-filter loop ended")
    }

    /**
     * Forward an allowed DNS query to the configured upstream and return the
     * response payload. Three transports, chosen at construction:
     *   - [Mode.PLAINTEXT]: UDP :53 (unencrypted; the fallback).
     *   - [Mode.DOT]:       DNS-over-TLS :853 (RFC 7858) — see [resolveDot].
     *   - [Mode.DOH]:       DNS-over-HTTPS :443 (RFC 8484) — see [resolveDoh].
     * The two encrypted transports are the InviZible Pro / RethinkDNS / Fyrypt
     * core, done natively in-tunnel here rather than by bundling a resolver
     * daemon (dnscrypt-proxy). Both verify the peer certificate and FAIL CLOSED.
     */
    class UpstreamResolver private constructor(
        private val resolverIp: InetAddress,
        private val mode: Mode,
        /** SNI + certificate-verification hostname for DoT/DoH. Null on the plaintext path. */
        private val tlsHostname: String?,
        /** Request path for DoH (e.g. "/dns-query"). Ignored for DoT/plaintext. */
        private val dohPath: String,
        /** DNSCrypt resolver stamp; non-null only for [Mode.DNSCRYPT]. */
        private val dnscryptStamp: DnsStamp? = null,
        /** UDP/TCP port for the DNSCrypt exchange (from the stamp). */
        private val dnscryptPort: Int = 443,
        /** SOCKS5 proxy for [Mode.SOCKS_DNS] (Tor/I2P/custom). */
        private val socksHost: String = "",
        private val socksPort: Int = 0,
        private val socksUser: String = "",
        private val socksPass: String = "",
        /** Human label for the proxy ("Tor", "I2P", "Proxy"). */
        private val socksLabel: String = "Proxy",
    ) {
        enum class Mode { PLAINTEXT, DOT, DOH, DNSCRYPT, SOCKS_DNS }

        fun describe(): String = when (mode) {
            Mode.DOT -> "DNS-over-TLS → $tlsHostname (${resolverIp.hostAddress}:853), verified"
            Mode.DOH -> "DNS-over-HTTPS → https://$tlsHostname$dohPath (${resolverIp.hostAddress}:443), verified"
            Mode.DNSCRYPT -> "DNSCrypt → ${dnscryptStamp?.providerName} (${resolverIp.hostAddress}:$dnscryptPort), " +
                "cert-verified, ${CryptoSelfTest.result().summary()}"
            Mode.SOCKS_DNS -> "$socksLabel → DNS-over-TCP to ${resolverIp.hostAddress}:53 via SOCKS5 $socksHost:$socksPort"
            Mode.PLAINTEXT -> "plaintext UDP ${resolverIp.hostAddress}:53"
        }

        fun resolve(service: VpnService, query: ByteArray): ByteArray? = when (mode) {
            Mode.DOT -> resolveDot(service, query)
            Mode.DOH -> resolveDoh(service, query)
            Mode.DNSCRYPT -> resolveDnscrypt(service, query)
            Mode.SOCKS_DNS -> resolveSocksDns(service, query)
            Mode.PLAINTEXT -> resolvePlaintext(service, query)
        }

        /**
         * REAL DNS-over-TCP through a SOCKS5 proxy — the Tor / I2P upstream. Dials the proxy,
         * CONNECTs to the target resolver on :53, and speaks DNS-over-TCP (2-byte length prefix).
         * When the proxy is Orbot's SOCKS the query egresses over the Tor network; the resolver
         * never sees the device's IP. Fails to null if the proxy is down (the caller falls back).
         */
        private fun resolveSocksDns(service: VpnService, query: ByteArray): ByteArray? {
            val socket = Socks5Client.connect(
                proxyHost = socksHost, proxyPort = socksPort,
                targetHost = resolverIp.hostAddress ?: return null, targetPort = 53,
                timeoutMs = DNS_TIMEOUT_MS, protect = { service.protect(it) },
                username = socksUser, password = socksPass,
            ) ?: return null
            return try {
                val out = socket.getOutputStream()
                out.write((query.size ushr 8) and 0xff)
                out.write(query.size and 0xff)
                out.write(query)
                out.flush()
                val ins = socket.getInputStream()
                val hi = ins.read(); val lo = ins.read()
                if (hi < 0 || lo < 0) return null
                val len = (hi shl 8) or lo
                if (len <= 0 || len > MAX_DNS) return null
                readFully(ins, len)
            } catch (_: Throwable) {
                null
            } finally {
                runCatching { socket.close() }
            }
        }

        // ---- DNSCrypt session state (Mode.DNSCRYPT only) ----
        private val rng = SecureRandom()
        @Volatile private var dnscryptSession: DnscryptClient.Session? = null
        @Volatile private var dnscryptSessionAtMs: Long = 0L

        /**
         * REAL native DNSCrypt v2 (the InviZible Pro / dnscrypt-proxy transport, done in-process):
         * lazily fetch + Ed25519-verify the resolver's certificate, X25519 key-agree an ephemeral
         * session, then encrypt each query and decrypt the response — all over [VpnService.protect]ed
         * UDP. Decryption FAILS CLOSED on a bad tag (a forged answer is dropped, never returned), so
         * a crypto fault degrades to "no answer", never a wrong answer. Only cipher suites this
         * device's [CryptoSelfTest] verified are accepted.
         */
        private fun resolveDnscrypt(service: VpnService, query: ByteArray): ByteArray? {
            val stamp = dnscryptStamp ?: return null
            val session = ensureDnscryptSession(service, stamp) ?: return null
            val packet = DnscryptClient.encryptQuery(session, query, rng)
            val resp = exchangeUdp(service, packet) ?: return null
            return DnscryptClient.decryptResponse(session, packet, resp)
        }

        @Synchronized
        private fun ensureDnscryptSession(service: VpnService, stamp: DnsStamp): DnscryptClient.Session? {
            val now = System.currentTimeMillis()
            val cur = dnscryptSession
            if (cur != null &&
                now - dnscryptSessionAtMs < DNSCRYPT_CERT_TTL_MS &&
                now / 1000 < cur.cert.tsEnd - 60
            ) {
                return cur
            }
            val supported = buildSet {
                val r = CryptoSelfTest.result()
                if (r.es2Ready) add(2)
                if (r.es1Ready) add(1)
            }
            if (supported.isEmpty()) return null
            val certQuery = DnscryptClient.buildCertQuery(stamp.providerName, rng)
            val certResp = exchangeUdp(service, certQuery) ?: return cur // keep prior session on transient failure
            val certs = DnscryptClient.parseCertificates(certResp, stamp.publicKey, now / 1000, supported)
            val best = certs.firstOrNull() ?: return cur
            val ns = DnscryptClient.newSession(best, rng)
            dnscryptSession = ns
            dnscryptSessionAtMs = now
            Diagnostics.log(TAG, "DNSCrypt session for ${stamp.providerName}: es-version ${best.esVersion}")
            return ns
        }

        /** One protected-UDP request/response against [resolverIp]:[dnscryptPort]. */
        private fun exchangeUdp(service: VpnService, payload: ByteArray): ByteArray? {
            val socket = DatagramSocket()
            return try {
                if (!service.protect(socket)) return null
                socket.soTimeout = DNS_TIMEOUT_MS
                socket.send(DatagramPacket(payload, payload.size, resolverIp, dnscryptPort))
                val rbuf = ByteArray(4096)
                val pkt = DatagramPacket(rbuf, rbuf.size)
                socket.receive(pkt)
                rbuf.copyOf(pkt.length)
            } catch (_: Throwable) {
                null
            } finally {
                runCatching { socket.close() }
            }
        }

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
                val (r, s) = openVerifiedTls(service, 853) ?: return null
                raw = r; ssl = s
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
                readFully(ins, len)
            } catch (_: Throwable) {
                null   // fail closed — never silently downgrade to plaintext
            } finally {
                runCatching { ssl?.close() }
                runCatching { raw?.close() }
            }
        }

        /**
         * REAL DNS-over-HTTPS (RFC 8484) — encrypted DNS over :443, the transport Fyrypt,
         * RethinkDNS and InviZible Pro (via dnscrypt-proxy) all offer, done natively here.
         * DoH's edge over DoT is that it rides ordinary HTTPS on 443, so a network that
         * blocks :853 to force plaintext DNS cannot single it out. Same verified-TLS setup
         * (SNI + HTTPS endpoint identification, fail-closed) as DoT; the DNS wire query is
         * the body of a minimal HTTP/1.1 POST with Content-Type application/dns-message, and
         * the wire response is the body. Handles both Content-Length and chunked responses.
         * Connection: close keeps it single-shot (no keep-alive/HTTP2 state to carry).
         */
        private fun resolveDoh(service: VpnService, query: ByteArray): ByteArray? {
            var raw: java.net.Socket? = null
            var ssl: javax.net.ssl.SSLSocket? = null
            return try {
                val (r, s) = openVerifiedTls(service, 443) ?: return null
                raw = r; ssl = s
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
                null   // fail closed
            } finally {
                runCatching { ssl?.close() }
                runCatching { raw?.close() }
            }
        }

        /** Protect a fresh TCP socket, connect to [resolverIp]:[port], wrap in a verified TLS layer. */
        private fun openVerifiedTls(
            service: VpnService,
            port: Int,
        ): Pair<java.net.Socket, javax.net.ssl.SSLSocket>? {
            val raw = java.net.Socket()
            if (!service.protect(raw)) { runCatching { raw.close() }; return null }
            raw.connect(java.net.InetSocketAddress(resolverIp, port), DNS_TIMEOUT_MS)
            val factory = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory
            val ssl = factory.createSocket(raw, tlsHostname, port, true) as javax.net.ssl.SSLSocket
            ssl.soTimeout = DNS_TIMEOUT_MS
            ssl.sslParameters = ssl.sslParameters.apply {
                if (tlsHostname != null) serverNames = listOf(javax.net.ssl.SNIHostName(tlsHostname))
                endpointIdentificationAlgorithm = "HTTPS"   // fail closed on bad cert/hostname
            }
            ssl.startHandshake()                            // throws on verification failure
            return raw to ssl
        }

        /** Read exactly [len] bytes or return null if the stream ends early. */
        private fun readFully(ins: java.io.InputStream, len: Int): ByteArray? {
            val resp = ByteArray(len)
            var off = 0
            while (off < len) {
                val n = ins.read(resp, off, len - off)
                if (n < 0) break
                off += n
            }
            return if (off == len) resp else null
        }

        /**
         * Parse a minimal HTTP/1.1 response off [ins] and return the body bytes (the DNS wire
         * response). Reads the status line + headers as ASCII lines, then the body via
         * Content-Length or Transfer-Encoding: chunked. Rejects any non-2xx status (fail closed).
         */
        private fun readHttpBody(ins: java.io.InputStream): ByteArray? {
            val status = readLine(ins) ?: return null
            // "HTTP/1.1 200 OK" — accept only 2xx.
            val code = status.split(' ').getOrNull(1)?.toIntOrNull() ?: return null
            if (code < 200 || code >= 300) return null
            var contentLength = -1
            var chunked = false
            while (true) {
                val line = readLine(ins) ?: return null
                if (line.isEmpty()) break               // blank line ends headers
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
                contentLength in 0..65_535 -> readFully(ins, contentLength)
                else -> null
            }
        }

        /** Read one CRLF-terminated line (ASCII) without over-reading into the body. */
        private fun readLine(ins: java.io.InputStream): String? {
            val sb = StringBuilder()
            while (true) {
                val c = ins.read()
                if (c < 0) return if (sb.isEmpty()) null else sb.toString()
                if (c == '\n'.code) return sb.toString()
                if (c != '\r'.code) sb.append(c.toChar())
            }
        }

        /** Read a Transfer-Encoding: chunked body, bounded by [MAX_DNS] so a hostile server can't grow it. */
        private fun readChunked(ins: java.io.InputStream): ByteArray? {
            val acc = java.io.ByteArrayOutputStream()
            while (true) {
                val sizeLine = readLine(ins) ?: return null
                val size = sizeLine.trim().substringBefore(';').toIntOrNull(16) ?: return null
                if (size == 0) break                    // last chunk
                if (acc.size() + size > MAX_DNS) return null
                val chunk = readFully(ins, size) ?: return null
                acc.write(chunk)
                readLine(ins)                           // trailing CRLF after the chunk
            }
            return acc.toByteArray()
        }

        companion object {
            /** Default resolver if the user's IP is blank/malformed. */
            private const val DEFAULT_IP = "1.1.1.1"

            private fun addrOf(ip: String): InetAddress =
                runCatching { InetAddress.getByName(ip.trim().ifBlank { DEFAULT_IP }) }
                    .getOrElse { InetAddress.getByName(DEFAULT_IP) }

            /** Plaintext UDP resolver at [ip]. A blank/garbage IP falls back to [DEFAULT_IP]. */
            fun plaintext(ip: String): UpstreamResolver =
                UpstreamResolver(addrOf(ip), Mode.PLAINTEXT, tlsHostname = null, dohPath = "")

            /**
             * REAL encrypted upstream: DNS-over-TLS to [ip] on :853, authenticated against
             * [hostname]. [hostname] is required — DoT without a verified hostname is not
             * encryption you can trust. Known-good pairs are in [DOT_PRESETS].
             */
            fun dot(ip: String, hostname: String): UpstreamResolver =
                UpstreamResolver(addrOf(ip), Mode.DOT, tlsHostname = hostname.trim(), dohPath = "")

            /**
             * REAL encrypted upstream: DNS-over-HTTPS to [ip] on :443, authenticated against
             * [hostname], POSTing to [path] (default "/dns-query"). Rides ordinary HTTPS so a
             * :853 block can't force it down to plaintext. Known-good triples in [DOH_PRESETS].
             */
            fun doh(ip: String, hostname: String, path: String = "/dns-query"): UpstreamResolver =
                UpstreamResolver(
                    addrOf(ip), Mode.DOH, tlsHostname = hostname.trim(),
                    dohPath = path.trim().ifBlank { "/dns-query" }.let { if (it.startsWith("/")) it else "/$it" },
                )

            /**
             * REAL native DNSCrypt v2 upstream from a resolver [stamp] (sdns://, DNSCRYPT proto).
             * The stamp carries the resolver address, provider name, and long-term Ed25519 key the
             * client verifies the certificate against. This is the transport InviZible Pro provides
             * via a bundled dnscrypt-proxy; here it is in-process (see [DnscryptClient]).
             */
            fun dnscrypt(stamp: DnsStamp): UpstreamResolver {
                val ip = stamp.addressIp().ifBlank { DEFAULT_IP }
                return UpstreamResolver(
                    addrOf(ip), Mode.DNSCRYPT, tlsHostname = null, dohPath = "",
                    dnscryptStamp = stamp, dnscryptPort = stamp.addressPort(443),
                )
            }

            /**
             * Build the right upstream for ANY resolver stamp: DNSCrypt stamps use the native
             * DNSCrypt client; DoH/DoT stamps reuse the existing verified-TLS path (the stamp's
             * hostname authenticates the peer). Returns null for a stamp type we don't carry
             * traffic over (relay/ODoH/plain) so the caller can fall back honestly.
             */
            fun fromStamp(stamp: DnsStamp): UpstreamResolver? = when (stamp.proto) {
                DnsStamp.Proto.DNSCRYPT -> dnscrypt(stamp)
                DnsStamp.Proto.DOH ->
                    doh(stamp.addressIp().ifBlank { stamp.hostname }, stamp.hostname, stamp.path.ifBlank { "/dns-query" })
                DnsStamp.Proto.DOT ->
                    dot(stamp.addressIp().ifBlank { stamp.hostname }, stamp.hostname)
                else -> null
            }

            /**
             * DNS-over-TCP to [targetIp]:53 tunnelled through a SOCKS5 proxy — the Tor / I2P
             * upstream. [label] names the proxy in diagnostics ("Tor", "I2P", "Proxy").
             */
            fun socksDns(
                socksHost: String,
                socksPort: Int,
                targetIp: String,
                label: String,
                username: String = "",
                password: String = "",
            ): UpstreamResolver = UpstreamResolver(
                addrOf(targetIp), Mode.SOCKS_DNS, tlsHostname = null, dohPath = "",
                socksHost = socksHost, socksPort = socksPort, socksUser = username, socksPass = password,
                socksLabel = label,
            )

            /** Curated DoT resolvers (label → ip → SNI/verification hostname). */
            val DOT_PRESETS: List<Triple<String, String, String>> = listOf(
                Triple("Cloudflare", "1.1.1.1", "cloudflare-dns.com"),
                Triple("Quad9 (malware-blocking)", "9.9.9.9", "dns.quad9.net"),
                Triple("Google", "8.8.8.8", "dns.google"),
                Triple("AdGuard (ad+tracker-blocking)", "94.140.14.14", "dns.adguard-dns.com"),
                Triple("Mullvad (no-log)", "194.242.2.2", "dns.mullvad.net"),
            )

            /** Curated DoH resolvers (label → ip → hostname); all serve DoH at /dns-query. */
            val DOH_PRESETS: List<Triple<String, String, String>> = listOf(
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
        /** DNS-over-TCP length field is 16-bit, so a well-formed response never exceeds this. */
        private const val MAX_DNS = 65_535
        /** Re-fetch a DNSCrypt resolver certificate at most this often (also bounded by cert expiry). */
        private const val DNSCRYPT_CERT_TTL_MS = 30 * 60 * 1000L
    }
}
