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

    companion object {
        private const val MTU = 1500
        /** Per-query timeout. 3s matches Android's default DNS retry
         *  interval; slower responses get retried by the system. */
        private const val DNS_TIMEOUT_MS = 3_000
    }
}
