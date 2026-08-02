package com.understory.firewall.chain

import android.content.Context
import com.understory.firewall.tailscale.TailscaleController

/**
 * Establishes and reports on the egress [EndpointChain]. This is the seam between
 * the stored chain config and the real data plane. Each [ProxyHop.Backend] is
 * carried by a backend that is either LINKED (a live implementation is present)
 * or PENDING (the surface exists, the transport does not yet). The controller is
 * honest by construction: it validates a chain, reports per-hop readiness, and
 * NEVER claims a hop carries traffic unless its backend is actually linked.
 *
 * Backend status today:
 *   - SOCKS5 / HTTP_CONNECT → LINKED. Implemented in-tree as real pure-userspace
 *                   clients ([Socks5Client] RFC 1928/1929, [HttpConnectClient]) and
 *                   composed into multi-hop chains by [ChainDialer]. No external
 *                   dependency, nothing native.
 *   - TAILSCALE   → delegated to [TailscaleController]; PENDING until libtailscale
 *                   (Tailscale's Go data plane) is linked.
 *   - WIREGUARD / SHADOWSOCKS / TOR → PENDING; each needs its own transport.
 *   - CONTAINER   → PENDING; needs a reachable container server.
 *   - DIRECT      → LINKED (egress straight out is the existing behavior).
 */
object ProxyChainController {

    enum class Readiness { LINKED, PENDING }

    data class HopStatus(val hop: ProxyHop, val readiness: Readiness, val note: String)

    fun backendReadiness(ctx: Context, backend: ProxyHop.Backend): Readiness = when (backend) {
        ProxyHop.Backend.DIRECT -> Readiness.LINKED
        // REAL, implemented in-tree: pure-userspace clients with no external dependency.
        // See Socks5Client / HttpConnectClient, composed by ChainDialer.
        ProxyHop.Backend.SOCKS5, ProxyHop.Backend.HTTP_CONNECT -> Readiness.LINKED
        ProxyHop.Backend.TAILSCALE ->
            if (TailscaleController.isLinked(ctx)) Readiness.LINKED else Readiness.PENDING
        else -> Readiness.PENDING
    }

    private fun note(backend: ProxyHop.Backend, readiness: Readiness): String {
        if (readiness == Readiness.LINKED) return "ready"
        return when (backend) {
            ProxyHop.Backend.TAILSCALE ->
                "needs the Tailscale data plane (libtailscale) linked"
            ProxyHop.Backend.SOCKS5, ProxyHop.Backend.HTTP_CONNECT -> "ready"
            ProxyHop.Backend.WIREGUARD -> "needs a WireGuard transport"
            ProxyHop.Backend.SHADOWSOCKS -> "needs a Shadowsocks transport"
            ProxyHop.Backend.TOR -> "needs a Tor transport"
            // Measured, not assumed — TransportCapability probes what this device actually
            // has, so the reason names the missing piece instead of restating the category.
            ProxyHop.Backend.CONTAINER ->
                "container relay not implemented — " + TransportCapability.snapshot().containerDetail()
            ProxyHop.Backend.DIRECT -> "ready"
        }
    }

    /** Per-hop readiness for the current chain, in route order. */
    fun status(ctx: Context): List<HopStatus> =
        EndpointChain.hops(ctx).map {
            val r = backendReadiness(ctx, it.backend())
            HopStatus(it, r, note(it.backend(), r))
        }

    /**
     * Can the WHOLE chain carry traffic right now? True only if every hop's backend
     * is LINKED. A single PENDING hop means the chain can be saved and previewed but
     * not run end-to-end — surfaced honestly, never silently skipped.
     */
    fun isChainRunnable(ctx: Context): Boolean {
        val hops = EndpointChain.hops(ctx)
        if (hops.isEmpty()) return true // direct egress
        return hops.all { backendReadiness(ctx, it.backend()) == Readiness.LINKED }
    }

    /** One-line honest summary for the UI. */
    fun summary(ctx: Context): String {
        val hops = EndpointChain.hops(ctx)
        if (hops.isEmpty()) return "Direct egress — no chain configured."
        val pending = status(ctx).filter { it.readiness == Readiness.PENDING }
        return if (pending.isEmpty()) {
            "Chain ready: ${EndpointChain.describe(ctx)}"
        } else {
            "Chain saved but not runnable yet — ${pending.size} hop(s) pending: " +
                pending.joinToString(", ") { "${it.hop.label()} (${it.note})" }
        }
    }
}
