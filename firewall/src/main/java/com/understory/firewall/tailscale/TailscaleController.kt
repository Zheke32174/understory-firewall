package com.understory.firewall.tailscale

import android.content.Context

/**
 * The seam to Tailscale's data plane. Real Tailscale connectivity (mesh, DERP
 * relays, NAT traversal, MagicDNS) is provided by Tailscale's Go library
 * (libtailscale) — there is no pure-Kotlin tailnet. Until that native backend is
 * linked into the build, [isLinked] is false and this reports config-only status;
 * it NEVER pretends a tailnet is up.
 *
 * When the backend lands, a real implementation registers via [link] and drives
 * Godwall's [com.understory.firewall.FirewallVpnService]: the node runs inside
 * Godwall's own VPN slot (userspace WireGuard netstack), so one slot delivers the
 * tailnet AND the DNS/app firewall — replacing the old "XOR Tailscale" posture.
 * The node can also be one hop of the egress [com.understory.firewall.chain.EndpointChain],
 * so traffic can link the tailnet and then hop onward into further proxies.
 */
object TailscaleController {

    /** Backend contract the native (libtailscale-backed) implementation fulfils. */
    interface Backend {
        fun start(ctx: Context, cfg: NodeConfig): Boolean
        fun stop(ctx: Context)
        fun status(ctx: Context): Status
    }

    /** Immutable snapshot of the config the backend needs, read from [TailscaleSettings]. */
    data class NodeConfig(
        val loginServer: String,
        val authKey: String,
        val exitNode: String,
        val acceptRoutes: Boolean,
        val acceptDns: Boolean,
        val advertiseExit: Boolean,
        val hostname: String,
    )

    enum class State { NOT_LINKED, STOPPED, STARTING, NEEDS_LOGIN, RUNNING, ERROR }

    data class Status(
        val state: State,
        /** Interactive-login URL when [state] == NEEDS_LOGIN (else blank). */
        val authUrl: String = "",
        /** This node's tailnet IPs when RUNNING. */
        val tailnetIps: List<String> = emptyList(),
        val detail: String = "",
    )

    @Volatile private var backend: Backend? = null

    /** The native backend calls this once at init to become the live data plane. */
    fun link(b: Backend) { backend = b }

    fun isLinked(ctx: Context): Boolean = backend != null

    fun configOf(ctx: Context): NodeConfig = NodeConfig(
        loginServer = TailscaleSettings.loginServer(ctx),
        authKey = TailscaleSettings.authKey(ctx),
        exitNode = TailscaleSettings.exitNode(ctx),
        acceptRoutes = TailscaleSettings.acceptRoutes(ctx),
        acceptDns = TailscaleSettings.acceptDns(ctx),
        advertiseExit = TailscaleSettings.advertiseExit(ctx),
        hostname = TailscaleSettings.hostname(ctx),
    )

    fun start(ctx: Context): Boolean = backend?.start(ctx, configOf(ctx)) ?: false

    fun stop(ctx: Context) { backend?.stop(ctx) }

    fun status(ctx: Context): Status =
        backend?.status(ctx) ?: Status(
            state = State.NOT_LINKED,
            detail = "Tailscale data plane (libtailscale) is not linked into this build. " +
                "Config is saved; the tailnet is not established.",
        )
}
