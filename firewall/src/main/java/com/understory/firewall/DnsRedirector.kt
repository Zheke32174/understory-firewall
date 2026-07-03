package com.understory.firewall

import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.understory.security.Diagnostics
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Phase 3 DNS-redirect tun reader.
 *
 * Tun is configured (in FirewallVpnService DNS-redirect mode) to:
 *   - addAddress(VPN_LOCAL_ADDR, 32)        — our tun's local IP
 *   - addRoute(FAKE_DNS_IP, 32)             — only this IP routes via tun
 *   - addDnsServer(FAKE_DNS_IP)             — apps see this as their DNS
 *
 * So apps' DNS queries to FAKE_DNS_IP land on this fd as IPv4+UDP
 * packets. Everything else bypasses the tun and uses the normal
 * network unmodified.
 *
 * Per packet:
 *   1. Parse IPv4+UDP header (VpnPacketParser).
 *   2. Confirm dst IP is FAKE_DNS_IP and dst port is 53.
 *   3. Forward the DNS payload to 127.0.0.1:DNSCRYPT_PROXY_PORT via a
 *      DatagramSocket protected with vpnService.protect() so the
 *      socket itself bypasses our tun (no infinite loop).
 *   4. Async-receive the response from the proxy.
 *   5. Wrap in IPv4+UDP, swapping src/dst, recomputing checksums.
 *   6. Write back to tun.
 *
 * Concurrency:
 *   - One reader thread on the tun fd. Per-query, it creates a tiny
 *     ephemeral DatagramSocket to the proxy and blocks for the
 *     response on a per-query timeout (DNS_TIMEOUT_MS). DNS
 *     responses are small + fast; this is simpler than a connection
 *     table and keeps memory bounded.
 *   - For higher throughput, phase 3b can replace the per-query
 *     ephemeral socket with a single long-lived NIO selector. Today
 *     a phone making <100 DNS queries/sec is comfortably handled
 *     by the simple model.
 *
 * Failure modes:
 *   - Proxy not running / not bound on the expected port: forward
 *     fails, no response written, app sees DNS timeout. Logged once
 *     in Diagnostics; we don't spam (the supervisor service will
 *     restart the proxy if it died).
 *   - Malformed packet: drop silently. Don't write garbage to tun.
 *   - Tun fd closed: read loop terminates cleanly.
 */
class DnsRedirector(
    private val vpnService: VpnService,
    private val tun: ParcelFileDescriptor,
    private val fakeDnsIp: InetAddress,
    private val proxyPort: Int = DnsCryptProxyService.LOCAL_PORT,
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

            // Phase-3 keeps phase-2's port-block drop semantics for
            // packets we DO handle. Even though only DNS routes via
            // this tun, parsing TCP destination port lets us drop a
            // few stray TCP packets that hit our route (mostly DoT to
            // 53; rare in practice).
            val tcpDst = VpnPacketParser.parseIpv4TcpDestPort(readBuf, n)
            if (tcpDst != null) {
                val blocked = FirewallSettings.getBlockedPorts(vpnService)
                if (tcpDst in blocked) {
                    DropStats.record()
                    continue
                }
                // TCP packet on our DNS-only route that isn't blocked —
                // we have nowhere to forward it (no TCP forwarder yet),
                // so drop it. In practice this only happens for DoT/53
                // which we aren't redirecting; phase 3b will forward.
                DropStats.record()
                continue
            }

            val parsed = VpnPacketParser.parseIpv4Udp(readBuf, n) ?: continue
            // Sanity: only redirect packets aimed at our fake DNS IP.
            // Any other UDP that lands here is unexpected (the tun's
            // route filter should have prevented it); drop quietly.
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
                // Tun closed mid-write. Drop the response; the app
                // sees a timeout. The reader will exit on the next
                // input.read.
            }
        }
    }

    /** Forward the DNS query payload to the local proxy and return
     *  the response payload, or null on timeout/error. */
    private fun forward(query: ByteArray): ByteArray? {
        val socket = DatagramSocket()
        try {
            // CRITICAL: protect the socket so its packets bypass our
            // own tun. Without this, the socket's outbound DNS query
            // to 127.0.0.1:5354 would re-enter the tun (because the
            // tun captures FAKE_DNS_IP, not 127.0.0.1, but Android's
            // routing of loopback is special and historically buggy
            // when a VPN is up). protect() guarantees bypass at the
            // kernel level.
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

    /** Log forward errors at most once per distinct message, so a
     *  failing proxy doesn't flood Diagnostics. */
    private fun logForwardErrorOnce(msg: String) {
        if (lastForwardError == msg) return
        lastForwardError = msg
        Diagnostics.error("firewall.DnsRedirector", msg)
    }

    companion object {
        private const val MTU = 1500
        /** Per-query timeout. 3s matches Android's default DNS retry
         *  interval; slower responses get retried by the system. */
        private const val DNS_TIMEOUT_MS = 3_000
    }
}
