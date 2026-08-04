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

    // ---------------------------------------------------------------
    // Login + admin (browser / app hand-off) and verification
    // ---------------------------------------------------------------

    /** The Tailscale Android app package (also the VPN-slot incumbent on a Tailscale phone). */
    const val TAILSCALE_PKG = "com.tailscale.ipn"

    private const val DEFAULT_ADMIN_URL = "https://login.tailscale.com/admin"
    private const val DEFAULT_LOGIN_URL = "https://login.tailscale.com/login"

    /** True when the configured control server is Tailscale's own (not a self-hosted Headscale). */
    fun usesDefaultControl(ctx: Context): Boolean =
        TailscaleSettings.loginServer(ctx).contains("tailscale.com", ignoreCase = true)

    /**
     * The URL to open for interactive login/verification. If the linked backend is mid-login it
     * hands back a real device-auth URL; otherwise this is the control server's login page
     * (Tailscale's for the default control plane, or the Headscale base URL for self-hosted).
     */
    fun loginUrl(ctx: Context): String {
        val s = status(ctx)
        if (s.authUrl.isNotBlank()) return s.authUrl
        return if (usesDefaultControl(ctx)) DEFAULT_LOGIN_URL else TailscaleSettings.loginServer(ctx)
    }

    /** The admin console URL — Tailscale's for the default control plane, else the control server. */
    fun adminUrl(ctx: Context): String =
        if (usesDefaultControl(ctx)) DEFAULT_ADMIN_URL else TailscaleSettings.loginServer(ctx)

    /** Whether the Tailscale Android app is installed (a valid login/verification path). */
    fun isTailscaleAppInstalled(ctx: Context): Boolean = try {
        ctx.packageManager.getPackageInfo(TAILSCALE_PKG, 0)
        true
    } catch (_: Throwable) {
        false
    }

    /** Honest verification snapshot — what we can actually observe about the tailnet. */
    data class Verification(
        val appInstalled: Boolean,
        val aVpnHoldsSlot: Boolean,
        val backendLinked: Boolean,
        val backendState: State,
        val summary: String,
    )

    fun verify(ctx: Context): Verification {
        val appInstalled = isTailscaleAppInstalled(ctx)
        val aVpnActive = runCatching { com.understory.firewall.VpnSlotProbe.isAnotherVpnActive(ctx) }.getOrDefault(false)
        val linked = isLinked(ctx)
        val st = status(ctx).state
        val summary = when {
            linked && st == State.RUNNING -> "Godwall's tailnet node is running."
            linked && st == State.NEEDS_LOGIN -> "Godwall's node needs login — opening the auth URL."
            appInstalled && aVpnActive ->
                "Tailscale app is installed and a VPN is currently active (likely the tailnet). " +
                    "Godwall's own node backend isn't linked in this build, so it observes rather than runs it."
            appInstalled ->
                "Tailscale app is installed but no VPN is active — open it to log in and connect."
            else ->
                "Tailscale app not detected. Log in on the web to create/verify your account, then " +
                    "install the app or link Godwall's node backend to bring up the tailnet."
        }
        return Verification(appInstalled, aVpnActive, linked, st, summary)
    }
}
