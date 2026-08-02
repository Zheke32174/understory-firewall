package com.understory.firewall.tailscale

import android.content.Context

/**
 * Persisted configuration for Godwall's own Tailscale node.
 *
 * Tailscale is absorbed as a donor: instead of Godwall merely *coexisting with*
 * the Tailscale app for the one Android VPN slot (the old XOR-Tailscale posture),
 * Godwall can *be* the Tailscale node — a userspace WireGuard + tailnet backend
 * running inside Godwall's own [com.understory.firewall.FirewallVpnService], so
 * the single VPN slot delivers mesh connectivity AND the DNS/app firewall at once.
 *
 * This holds the node config the backend needs. The backend itself
 * ([TailscaleController]) is a seam — the real data plane is Tailscale's Go
 * library (libtailscale); until that is linked, config is stored and surfaced
 * honestly but no tunnel is established. No value here implies a live tailnet.
 */
object TailscaleSettings {
    private const val PREF = "firewall_tailscale"

    private const val K_ENABLED = "ts_enabled"
    private const val K_LOGIN_SERVER = "ts_login_server"
    private const val K_AUTH_KEY = "ts_auth_key"
    private const val K_EXIT_NODE = "ts_exit_node"
    private const val K_ACCEPT_ROUTES = "ts_accept_routes"
    private const val K_ACCEPT_DNS = "ts_accept_dns"          // MagicDNS
    private const val K_ADVERTISE_EXIT = "ts_advertise_exit"
    private const val K_HOSTNAME = "ts_hostname"

    /** The default Tailscale coordination server. Overridable for Headscale / self-hosted control. */
    const val DEFAULT_LOGIN_SERVER = "https://controlplane.tailscale.com"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    /** Master switch: the user wants Godwall to bring up the tailnet in its VPN. */
    fun isEnabled(ctx: Context): Boolean = p(ctx).getBoolean(K_ENABLED, false)
    fun setEnabled(ctx: Context, on: Boolean) = p(ctx).edit().putBoolean(K_ENABLED, on).apply()

    /** Control-plane URL — Tailscale by default, or a self-hosted Headscale endpoint. */
    fun loginServer(ctx: Context): String =
        p(ctx).getString(K_LOGIN_SERVER, DEFAULT_LOGIN_SERVER)?.trim()?.ifBlank { DEFAULT_LOGIN_SERVER }
            ?: DEFAULT_LOGIN_SERVER
    fun setLoginServer(ctx: Context, v: String) =
        p(ctx).edit().putString(K_LOGIN_SERVER, v.trim().ifBlank { DEFAULT_LOGIN_SERVER }).apply()

    /**
     * Pre-authenticated node key (tskey-auth-…). Optional: without it the backend
     * uses interactive login (a browser auth URL). Stored locally only; never logged.
     */
    fun authKey(ctx: Context): String = p(ctx).getString(K_AUTH_KEY, "")?.trim().orEmpty()
    fun setAuthKey(ctx: Context, v: String) = p(ctx).edit().putString(K_AUTH_KEY, v.trim()).apply()

    /** Route all egress via this tailnet exit node (stable ID or hostname). Blank = no exit node. */
    fun exitNode(ctx: Context): String = p(ctx).getString(K_EXIT_NODE, "")?.trim().orEmpty()
    fun setExitNode(ctx: Context, v: String) = p(ctx).edit().putString(K_EXIT_NODE, v.trim()).apply()

    /** Accept subnet routes advertised by other tailnet nodes. */
    fun acceptRoutes(ctx: Context): Boolean = p(ctx).getBoolean(K_ACCEPT_ROUTES, true)
    fun setAcceptRoutes(ctx: Context, on: Boolean) = p(ctx).edit().putBoolean(K_ACCEPT_ROUTES, on).apply()

    /** Use MagicDNS from the tailnet. Composes with the DNS-filter tunnel (filter first, then tailnet resolver). */
    fun acceptDns(ctx: Context): Boolean = p(ctx).getBoolean(K_ACCEPT_DNS, true)
    fun setAcceptDns(ctx: Context, on: Boolean) = p(ctx).edit().putBoolean(K_ACCEPT_DNS, on).apply()

    /** Advertise THIS device as an exit node for the tailnet. */
    fun advertiseExit(ctx: Context): Boolean = p(ctx).getBoolean(K_ADVERTISE_EXIT, false)
    fun setAdvertiseExit(ctx: Context, on: Boolean) = p(ctx).edit().putBoolean(K_ADVERTISE_EXIT, on).apply()

    /** Node hostname on the tailnet. Blank = let the backend derive one. */
    fun hostname(ctx: Context): String = p(ctx).getString(K_HOSTNAME, "")?.trim().orEmpty()
    fun setHostname(ctx: Context, v: String) = p(ctx).edit().putString(K_HOSTNAME, v.trim()).apply()
}
