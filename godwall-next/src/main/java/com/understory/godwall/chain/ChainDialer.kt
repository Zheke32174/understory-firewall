package com.understory.godwall.chain

import android.net.VpnService
import com.understory.security.Diagnostics
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Establishes a real multi-hop connection through the egress [EndpointChain].
 *
 * The composition trick: each hop's handshake ([Socks5Client], [HttpConnectClient])
 * runs over an already-connected stream pair and leaves that stream pointing at
 * whatever address it was asked for. So the chain is one TCP socket connected to
 * the FIRST hop, then each hop handshaked toward the NEXT hop's address, and the
 * last hop handshaked toward the real destination:
 *
 *     socket ── connect ──▶ hop0
 *            ── hop0 handshake ──▶ hop1
 *            ── hop1 handshake ──▶ hop2
 *            ── hop2 handshake ──▶ destination
 *
 * Hostnames are handed to the proxy rather than resolved locally, so the
 * destination never leaks to the local resolver.
 *
 * FAIL CLOSED: if the chain cannot be established end to end, this connects to
 * NOTHING and returns [Result.Unavailable]. It never falls back to a direct
 * connection, because a chain that silently bypasses itself is worse than no
 * chain — the user believes they are covered when they are not.
 */
object ChainDialer {

    private const val TAG = "godwall.chain.ChainDialer"

    sealed interface Result {
        /** [socket] is connected and tunnelled all the way to the destination. */
        data class Connected(val socket: Socket, val path: String) : Result

        /** Nothing was connected. [reason] is user-surfaceable. */
        data class Unavailable(val reason: String) : Result
    }

    private data class Leg(
        val host: String,
        val port: Int,
        val label: String,
        val handshake: (java.io.InputStream, java.io.OutputStream, String, Int) -> Unit,
    )

    /**
     * Dial [destHost]:[destPort] through [hops]. An empty chain is a direct
     * connection, which is honest — the caller asked for no hops.
     *
     * [service] is used to [VpnService.protect] the socket so the chain's own
     * traffic does not route back into our tun. Pass null when dialling from
     * outside the tunnel (the in-app chain test does exactly that).
     */
    fun dial(
        service: VpnService?,
        hops: List<ProxyHop>,
        destHost: String,
        destPort: Int,
        timeoutMs: Int,
    ): Result {
        val plan = plan(hops)
        if (plan.isEmpty()) {
            val direct = connectRaw(service, destHost, destPort, timeoutMs)
                ?: return Result.Unavailable("Could not open a direct connection to $destHost:$destPort")
            return Result.Connected(direct, "direct → $destHost:$destPort")
        }

        val entry = plan.first()
        val socket = connectRaw(service, entry.host, entry.port, timeoutMs)
            ?: return Result.Unavailable("Could not reach the first hop (${entry.label})")

        return try {
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            for (i in plan.indices) {
                val nextHost = if (i + 1 < plan.size) plan[i + 1].host else destHost
                val nextPort = if (i + 1 < plan.size) plan[i + 1].port else destPort
                plan[i].handshake(input, output, nextHost, nextPort)
            }
            val path = plan.joinToString(" → ") { it.label } + " → $destHost:$destPort"
            Diagnostics.log(TAG, "chain established: $path")
            Result.Connected(socket, path)
        } catch (t: Throwable) {
            runCatching { socket.close() }
            val why = "${t.javaClass.simpleName}: ${t.message}"
            Diagnostics.error(TAG, "chain handshake failed — $why")
            Result.Unavailable("Chain handshake failed — $why")
        }
    }

    /**
     * Reduce [hops] to the ordered plan. A [ProxyHop.Direct] terminates the
     * chain: egress happens there, so anything after it is dropped rather than
     * silently "skipped". Every remaining hop type has a transport, so unlike
     * the old build there is no "unimplemented hop" case to refuse.
     */
    private fun plan(hops: List<ProxyHop>): List<Leg> {
        val out = ArrayList<Leg>(hops.size)
        for (hop in hops) {
            when (hop) {
                is ProxyHop.Direct -> return out
                is ProxyHop.Socks5 -> out += Leg(
                    host = hop.host, port = hop.port, label = hop.label(),
                    handshake = { i, o, h, p ->
                        Socks5Client.connectThrough(i, o, h, p, hop.username, hop.password)
                    },
                )
                is ProxyHop.HttpConnect -> out += Leg(
                    host = hop.host, port = hop.port, label = hop.label(),
                    handshake = { i, o, h, p ->
                        HttpConnectClient.connectThrough(i, o, h, p, hop.username, hop.password)
                    },
                )
            }
        }
        return out
    }

    private fun connectRaw(service: VpnService?, host: String, port: Int, timeoutMs: Int): Socket? {
        val socket = Socket()
        return try {
            if (service != null && !service.protect(socket)) {
                runCatching { socket.close() }
                Diagnostics.error(TAG, "VpnService.protect() refused the chain socket")
                return null
            }
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(host, port), timeoutMs)
            socket
        } catch (t: Throwable) {
            runCatching { socket.close() }
            Diagnostics.error(TAG, "connect to $host:$port failed — ${t.javaClass.simpleName}: ${t.message}")
            null
        }
    }
}
