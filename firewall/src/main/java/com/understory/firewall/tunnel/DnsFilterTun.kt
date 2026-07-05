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
 *   NOT IMPLEMENTED (stubbed cleanly, see [UpstreamResolver]): encrypted-
 *         resolver routing (DoT/DoH/DNSCrypt/Tor upstream). The forward goes to
 *         a PLAINTEXT UDP resolver. The UI must not claim the upstream is
 *         encrypted. Pair this with system Private DNS (S4) for an encrypted
 *         upstream on the *system* resolver path — that is the honest story.
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
    ) {
        fun describe(): String =
            if (encrypted) "encrypted (NOT IMPLEMENTED — falls back to plaintext)"
            else "plaintext UDP ${resolverIp.hostAddress}:53"

        fun resolve(service: VpnService, query: ByteArray): ByteArray? {
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

        companion object {
            /** Default resolver if the user's IP is blank/malformed. */
            private const val DEFAULT_IP = "1.1.1.1"

            /** Plaintext UDP resolver at [ip] (e.g. "1.1.1.1"). The honest,
             *  implemented path. Total: a blank/garbage IP falls back to
             *  [DEFAULT_IP] rather than throwing at establish time. */
            fun plaintext(ip: String): UpstreamResolver {
                val addr = runCatching { InetAddress.getByName(ip.trim().ifBlank { DEFAULT_IP }) }
                    .getOrElse { InetAddress.getByName(DEFAULT_IP) }
                return UpstreamResolver(addr, encrypted = false)
            }

            /**
             * STUB for encrypted-resolver routing (DoT/DoH/DNSCrypt/Tor). Not
             * implemented — returns a plaintext resolver so DNS still works, and
             * is flagged [encrypted]=true only so [describe] can state honestly
             * that encryption is NOT active. Callers MUST NOT present this as an
             * encrypted upstream. The real encrypted path today is system
             * Private DNS (S4).
             */
            fun encryptedStub(fallbackIp: String): UpstreamResolver =
                UpstreamResolver(InetAddress.getByName(fallbackIp), encrypted = true)
        }
    }

    companion object {
        private const val TAG = "firewall.tunnel.DnsFilterTun"
        private const val MTU = 1500
        private const val DNS_TIMEOUT_MS = 5_000
    }
}
