package com.understory.firewall.chain

import android.net.VpnService
import com.understory.security.Diagnostics
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Establishes a REAL multi-hop connection through the egress [EndpointChain].
 *
 * The composition trick is that each hop's handshake ([Socks5Client], [HttpConnectClient])
 * runs over an already-connected stream and leaves that stream pointing at the address it
 * was asked for. So the chain is built by connecting a single TCP socket to the FIRST hop
 * and then, for each hop in turn, handshaking it toward the NEXT hop's address — with the
 * final hop handshaked toward the real destination:
 *
 *     socket ── connect ──▶ hop0
 *            ── hop0 handshake ──▶ hop1
 *            ── hop1 handshake ──▶ hop2
 *            ── hop2 handshake ──▶ destination
 *
 * One socket, N hops, and every hop after the first only ever sees ciphertext-or-payload
 * from its predecessor. Hostnames are handed to the proxy rather than resolved locally, so
 * the destination is never leaked to the local resolver.
 *
 * FAIL CLOSED: if the chain contains a hop whose transport is not implemented, this returns
 * [Result.Unavailable] and connects to NOTHING. It never silently falls back to a direct
 * connection — a proxy chain that quietly bypasses itself is worse than no proxy chain,
 * because the user believes they are covered.
 */
object ChainDialer {

    private const val TAG = "firewall.chain.ChainDialer"

    sealed interface Result {
        /** [socket] is connected and tunnelled all the way to the requested destination. */
        data class Connected(val socket: Socket, val path: String) : Result

        /** Nothing was connected. [reason] is user-surfaceable and never blames the user. */
        data class Unavailable(val reason: String) : Result
    }

    /** A hop that this dialer can actually establish today, reduced to what it needs. */
    private data class Dialable(
        val host: String,
        val port: Int,
        val handshake: (java.io.InputStream, java.io.OutputStream, String, Int) -> Unit,
        val label: String,
    )

    /**
     * Dial [destHost]:[destPort] through [hops].
     *
     * An empty chain means direct egress, which is the pre-chain behavior and is honest —
     * the caller asked for no hops. [service] is used to [VpnService.protect] the underlying
     * socket so the chain does not route back into our own tun; pass null only off-tunnel.
     */
    fun dial(
        service: VpnService?,
        hops: List<ProxyHop>,
        destHost: String,
        destPort: Int,
        timeoutMs: Int,
    ): Result {
        val plan = plan(hops) ?: return Result.Unavailable(unsupportedReason(hops))
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
            // Hop i is handshaked toward hop i+1; the last hop toward the real destination.
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
     * Reduce [hops] to the ordered dialable plan, or null when a hop's transport is not
     * implemented. A [ProxyHop.Direct] terminates the chain: egress happens there, so any
     * hop after it is unreachable and is dropped rather than silently "skipped".
     */
    private fun plan(hops: List<ProxyHop>): List<Dialable>? {
        val out = ArrayList<Dialable>(hops.size)
        for (hop in hops) {
            when (hop) {
                is ProxyHop.Direct -> return out // egress here; the rest of the chain is moot
                is ProxyHop.Socks5 -> out += Dialable(
                    host = hop.host,
                    port = hop.port,
                    label = hop.label(),
                    handshake = { i, o, h, p ->
                        Socks5Client.connectThrough(i, o, h, p, hop.username, hop.password)
                    },
                )
                is ProxyHop.HttpConnect -> out += Dialable(
                    host = hop.host,
                    port = hop.port,
                    label = hop.label(),
                    handshake = { i, o, h, p ->
                        HttpConnectClient.connectThrough(i, o, h, p, hop.username, hop.password)
                    },
                )
                // Everything else needs a transport we have not linked yet. Refuse the whole
                // chain rather than establishing a partial one that misrepresents coverage.
                else -> return null
            }
        }
        return out
    }

    /** The honest explanation for a chain we cannot establish. */
    private fun unsupportedReason(hops: List<ProxyHop>): String {
        val blocking = hops.filter { it !is ProxyHop.Socks5 && it !is ProxyHop.HttpConnect && it !is ProxyHop.Direct }
        if (blocking.isEmpty()) return "Chain could not be planned."
        return "Not connected — these hops have no linked transport yet: " +
            blocking.joinToString(", ") { it.label() } +
            ". The chain fails closed rather than bypassing them."
    }

    /** A protected TCP socket, so the chain's own traffic never re-enters our tun. */
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
