package com.understory.net.engine

import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Userspace DNS-redirect tun reader.
 *
 * SALVAGE NOTE (design-v2/firewall.md §7, A9): the app-facing DNS-redirect
 * mode was DROPPED — the shipping Standalone engine has exactly one mode
 * (app-drop) and never instantiates this class. It survives here, compiled
 * and dependency-light, for a future userspace forwarder. Its dependencies
 * on the (now-removed) DNSCrypt proxy service, port-block settings, and the
 * in-firewall DropStats have been lifted to constructor parameters so the
 * class stands alone in this library.
 *
 * When wired, the tun is configured to:
 *   - addAddress(localAddr, 32)     — the tun's local IP
 *   - addRoute(fakeDnsIp, 32)       — only this IP routes via the tun
 *   - addDnsServer(fakeDnsIp)       — apps see this as their resolver
 *
 * Per packet: parse IPv4+UDP; confirm dst == fakeDnsIp:53; forward the DNS
 * payload to 127.0.0.1:[proxyPort] over a [VpnService.protect]ed socket
 * (so it bypasses our own tun); wrap the response back into an IPv4+UDP
 * packet and write it to the tun.
 *
 * @param proxyPort loopback port of an upstream DNS proxy to forward to.
 * @param isPortBlocked caller predicate: drop TCP packets whose dest port
 *   the caller considers blocked. Defaults to "never" — the salvage engine
 *   has no port-block concept.
 * @param onDrop invoked once per dropped packet, for a caller-owned
 *   counter. Defaults to no-op.
 * @param onError invoked once per distinct error message (de-duplicated),
 *   for caller-owned diagnostics. Defaults to no-op.
 */
class DnsRedirector(
    private val vpnService: VpnService,
    private val tun: ParcelFileDescriptor,
    private val fakeDnsIp: InetAddress,
    private val proxyPort: Int,
    private val isPortBlocked: (Int) -> Boolean = { false },
    private val onDrop: () -> Unit = {},
    private val onError: (String) -> Unit = {},
) : Runnable {

    private val running = AtomicBoolean(true)
    @Volatile private var lastForwardError: String? = null

    fun stop() {
        running.set(false)
    }

    override fun run() {
        val input = FileInputStream(tun.fileDescriptor)
        val output = FileOutputStream(tun.fileDescriptor)
        val readBuf = ByteArray(MTU)

        while (running.get()) {
            val n = try {
                input.read(readBuf)
            } catch (_: Throwable) {
                break
            }
            if (n < 0) break
            if (n < 28) continue  // shorter than the smallest IPv4+UDP frame

            val tcpDst = VpnPacketParser.parseIpv4TcpDestPort(readBuf, n)
            if (tcpDst != null) {
                // TCP on a DNS-only route is always dropped — there is no
                // TCP forwarder. isPortBlocked is consulted for the caller's
                // accounting only; either way the packet is dropped.
                isPortBlocked(tcpDst)
                onDrop()
                continue
            }

            val parsed = VpnPacketParser.parseIpv4Udp(readBuf, n) ?: continue
            if (parsed.dstIp != fakeDnsIp || parsed.dstPort != VpnPacketParser.DNS_PORT) {
                continue
            }

            val payload = readBuf.copyOfRange(
                parsed.payloadOffset,
                parsed.payloadOffset + parsed.payloadLen,
            )

            val response = forward(payload) ?: continue
            val outPacket = VpnPacketParser.buildIpv4UdpResponse(parsed, response)
            try {
                output.write(outPacket)
            } catch (_: Throwable) {
                // Tun closed mid-write; the app sees a timeout. Reader
                // exits on the next input.read.
            }
        }
    }

    /** Forward the DNS query payload to the local proxy and return the
     *  response payload, or null on timeout/error. */
    private fun forward(query: ByteArray): ByteArray? {
        val socket = DatagramSocket()
        try {
            if (!vpnService.protect(socket)) {
                logForwardErrorOnce("vpnService.protect(socket) returned false")
                return null
            }
            socket.soTimeout = DNS_TIMEOUT_MS
            socket.send(
                DatagramPacket(
                    query, query.size,
                    InetAddress.getByName("127.0.0.1"), proxyPort,
                )
            )
            val buf = ByteArray(MTU)
            val pkt = DatagramPacket(buf, buf.size)
            socket.receive(pkt)
            return buf.copyOf(pkt.length)
        } catch (t: Throwable) {
            logForwardErrorOnce("forward failed: ${t.javaClass.simpleName}: ${t.message}")
            return null
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun logForwardErrorOnce(msg: String) {
        if (lastForwardError == msg) return
        lastForwardError = msg
        onError(msg)
    }

    /**
     * Convenience wrapper over [rebindRiskInResponse] for use inside [forward]
     * when the DNS-redirect engine mode wants to refuse a rebinding answer
     * before writing it back to the tun. Pure delegation; kept as an instance
     * method so a future forwarder can call it without touching the companion
     * object. NOTE: not invoked in the current shipping app-drop engine (see the
     * SALVAGE NOTE at the top of this file) — this is engine-mode capability,
     * unit-tested via the companion object below, not active companion behavior.
     */
    fun responseIsRebinding(queriedHost: String, dnsResponse: ByteArray): Boolean =
        rebindRiskInResponse(queriedHost, dnsResponse).rebindRisk

    companion object {
        private const val MTU = 1500
        /** Per-query timeout. 3s matches Android's default DNS retry
         *  interval; slower responses get retried by the system. */
        private const val DNS_TIMEOUT_MS = 3_000

        /**
         * Extract every A (IPv4) and AAAA (IPv6) answer address from a raw DNS
         * *response* message ([dnsResponse] is the DNS payload only — no IP/UDP
         * headers, i.e. exactly the bytes [forward] returns). Total and
         * bounds-checked: returns an empty list for a malformed / truncated
         * message rather than throwing.
         *
         * DNS message layout (RFC 1035 §4):
         *   Header (12 bytes): ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
         *   Question section  (QDCOUNT entries): QNAME, QTYPE(2), QCLASS(2)
         *   Answer section    (ANCOUNT entries): NAME, TYPE(2), CLASS(2),
         *                       TTL(4), RDLENGTH(2), RDATA(RDLENGTH)
         * Names use label compression (a length byte with the top two bits set
         * is a pointer); we skip names without following pointers, which is all
         * we need to reach each RR's fixed fields.
         */
        fun extractAnswerIps(dnsResponse: ByteArray): List<InetAddress> {
            val n = dnsResponse.size
            if (n < 12) return emptyList()
            fun u16(off: Int): Int =
                ((dnsResponse[off].toInt() and 0xFF) shl 8) or (dnsResponse[off + 1].toInt() and 0xFF)

            val qd = u16(4)
            val an = u16(6)
            // No answers, or an implausible count from a malformed message.
            if (an <= 0 || an > 1000) return emptyList()

            var pos = 12
            // Skip the question section.
            repeat(qd) {
                pos = skipName(dnsResponse, pos)
                if (pos < 0 || pos + 4 > n) return emptyList()
                pos += 4 // QTYPE + QCLASS
            }

            val out = ArrayList<InetAddress>()
            repeat(an) {
                pos = skipName(dnsResponse, pos)
                if (pos < 0 || pos + 10 > n) return out
                val type = u16(pos)
                val rdLen = u16(pos + 8)
                val rdStart = pos + 10
                if (rdStart + rdLen > n) return out
                when (type) {
                    TYPE_A -> if (rdLen == 4) {
                        runCatching {
                            out.add(InetAddress.getByAddress(dnsResponse.copyOfRange(rdStart, rdStart + 4)))
                        }
                    }
                    TYPE_AAAA -> if (rdLen == 16) {
                        runCatching {
                            out.add(InetAddress.getByAddress(dnsResponse.copyOfRange(rdStart, rdStart + 16)))
                        }
                    }
                }
                pos = rdStart + rdLen
            }
            return out
        }

        /**
         * Advance past a DNS name starting at [start]. Handles the two forms
         * that appear before an RR's fixed fields: a sequence of length-prefixed
         * labels terminated by a zero byte, or a compression pointer (top two
         * bits of the length byte set) which is a 2-byte field ending the name.
         * Returns the offset just past the name, or -1 if it runs off the end.
         */
        private fun skipName(buf: ByteArray, start: Int): Int {
            var pos = start
            val n = buf.size
            while (pos < n) {
                val len = buf[pos].toInt() and 0xFF
                when {
                    len == 0 -> return pos + 1
                    (len and 0xC0) == 0xC0 -> {
                        // Compression pointer occupies 2 bytes and ends the name.
                        return if (pos + 2 <= n) pos + 2 else -1
                    }
                    else -> pos += 1 + len
                }
            }
            return -1
        }

        /**
         * The engine hook: given the [queriedHost] the app asked about and the
         * raw DNS [dnsResponse] payload, return the rebinding [RebindClassifier.Verdict]
         * over the response's A/AAAA answers. A DNS-redirect engine mode can use
         * `verdict.rebindRisk` to drop or rewrite a public name that lies about
         * resolving to a private address.
         */
        fun rebindRiskInResponse(
            queriedHost: String,
            dnsResponse: ByteArray,
        ): RebindClassifier.Verdict =
            RebindClassifier.classify(queriedHost, extractAnswerIps(dnsResponse))

        private const val TYPE_A = 1
        private const val TYPE_AAAA = 28
    }
}
