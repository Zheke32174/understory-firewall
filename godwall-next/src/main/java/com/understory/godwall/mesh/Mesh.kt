package com.understory.godwall.mesh

import android.content.Context
import android.net.VpnService
import com.understory.godwall.BuildConfig
import com.understory.security.Diagnostics

/**
 * Godwall's mesh node — the tailnet, running **inside Godwall's own VPN slot**.
 *
 * ## The invariant this file exists to hold
 *
 * > If it has to ask the thing it replaces, it has not replaced it.
 *
 * The previous Godwall had a `TunnelPostureScreen` with an `openTailscale()` button that called
 * `getLaunchIntentForPackage("com.tailscale.ipn")`, and a manifest `<queries>` entry so it could
 * find that app. That is the definition of not having replaced it — the user said as much:
 * *"why would Godwall open the tailscale app if it is tailscale"*. None of that exists here.
 * There is no launch intent, no `<queries>` entry, no "coexistence" mode, and no screen that
 * reports on another app's tunnel.
 *
 * ## Why this is a seam rather than an implementation
 *
 * There is no pure-Kotlin tailnet. Mesh connectivity — DERP relays, NAT traversal, MagicDNS,
 * WireGuard key exchange — is Tailscale's Go implementation, delivered as `libtailscale.aar`
 * from `gomobile bind`. It is not on Maven; upstream builds it and links it as a local file.
 *
 * So the build takes it as an input (`-Plibtailscale.aar=…`, `LIBTAILSCALE_AAR`, or
 * `godwall-next/libs/libtailscale.aar`) and compiles the real backend from `src/tailscale/java`
 * only when it is present. When it is absent, [status] returns [State.ABSENT] and the Mesh
 * screen states plainly that the data plane is not in this build.
 *
 * That honesty is the entire design. A mesh toggle that flips to "connected" without a data
 * plane is worse than a disabled one, because the user then trusts a tunnel that does not
 * exist — and this is a security app, so a confident lie about the tunnel is the worst
 * available outcome.
 */
object Mesh {

    private const val TAG = "godwall.mesh"

    /** Fulfilled by `LibtailscaleBackend` in the `tailscale` source set. */
    interface Backend {
        fun start(ctx: Context, cfg: NodeConfig): Boolean
        fun stop(ctx: Context)
        fun status(ctx: Context): Status

        /** Ask the control plane for an interactive login. Returns a result line. */
        fun requestLogin(): String

        fun logout(): String
    }

    data class NodeConfig(
        val loginServer: String,
        val authKey: String,
        val exitNode: String,
        val acceptRoutes: Boolean,
        val acceptDns: Boolean,
        val advertiseExit: Boolean,
        val hostname: String,
    )

    enum class State {
        /** libtailscale was not supplied to this build. Nothing is running; nothing pretends to be. */
        ABSENT,
        STOPPED,
        STARTING,
        NEEDS_LOGIN,
        RUNNING,
        ERROR,
    }

    data class Status(
        val state: State,
        /** Interactive-login URL while [state] == NEEDS_LOGIN. */
        val authUrl: String = "",
        val tailnetIps: List<String> = emptyList(),
        val detail: String = "",
    )

    @Volatile
    private var backend: Backend? = null

    /** True when this build carries the data plane at all — a compile-time fact. */
    val compiledIn: Boolean get() = BuildConfig.HAS_MESH_DATAPLANE

    val linked: Boolean get() = backend != null

    fun link(b: Backend) {
        backend = b
        Diagnostics.log(TAG, "mesh data plane linked")
    }

    /**
     * Link the real backend, which lives in the source set that only exists when the aar was
     * supplied. This module cannot name that class directly and still compile without it, so one
     * narrow reflective lookup bridges the gap; a miss is the ordinary no-aar build, not an error.
     *
     * Called by the VpnService, because the backend needs a [VpnService] to build its tun.
     */
    fun linkNative(service: VpnService): Boolean {
        if (backend != null) return true
        if (!compiledIn) return false
        return runCatching {
            val cls = Class.forName("com.understory.godwall.mesh.LibtailscaleBackend")
            link(cls.getConstructor(VpnService::class.java).newInstance(service) as Backend)
            true
        }.getOrElse {
            Diagnostics.warn(TAG, "backend present at build time but not linkable: ${it.message}")
            false
        }
    }

    fun config(ctx: Context): NodeConfig = NodeConfig(
        loginServer = MeshSettings.loginServer(ctx),
        authKey = MeshSettings.authKey(ctx),
        exitNode = MeshSettings.exitNode(ctx),
        acceptRoutes = MeshSettings.acceptRoutes(ctx),
        acceptDns = MeshSettings.acceptDns(ctx),
        advertiseExit = MeshSettings.advertiseExit(ctx),
        hostname = MeshSettings.hostname(ctx),
    )

    /**
     * Start the node. Blocking — call off the main thread.
     *
     * Returns false when there is no backend, which happens for exactly two
     * reasons and the Mesh screen distinguishes them: the data plane is not in
     * this build, or Godwall is not holding the VPN slot yet. The node lives
     * INSIDE Godwall's slot, so [linkNative] cannot have run until the service
     * exists — there is no third case where this silently does nothing.
     */
    fun start(ctx: Context): Boolean = backend?.start(ctx, config(ctx)) ?: false

    /** True when the data plane is in the build but the slot is not held yet. */
    fun awaitingSlot(): Boolean = compiledIn && backend == null

    fun requestLogin(): String =
        backend?.requestLogin() ?: "The node is not running."

    fun logout(): String = backend?.logout() ?: "The node is not running."

    fun stop(ctx: Context) {
        backend?.stop(ctx)
    }

    fun status(ctx: Context): Status = backend?.status(ctx) ?: Status(
        state = State.ABSENT,
        detail = "The mesh data plane (libtailscale) is not in this build. Your settings are " +
            "saved, and no tunnel is running.",
    )
}

/** Mesh node configuration. Saved whether or not a data plane is present. */
object MeshSettings {

    private const val PREFS = "godwall_mesh"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun loginServer(ctx: Context): String =
        p(ctx).getString("login_server", DEFAULT_LOGIN_SERVER) ?: DEFAULT_LOGIN_SERVER

    fun setLoginServer(ctx: Context, v: String) {
        p(ctx).edit().putString("login_server", v.trim()).apply()
    }

    fun authKey(ctx: Context): String = p(ctx).getString("auth_key", "") ?: ""

    fun setAuthKey(ctx: Context, v: String) {
        p(ctx).edit().putString("auth_key", v.trim()).apply()
    }

    fun exitNode(ctx: Context): String = p(ctx).getString("exit_node", "") ?: ""

    fun setExitNode(ctx: Context, v: String) {
        p(ctx).edit().putString("exit_node", v.trim()).apply()
    }

    fun hostname(ctx: Context): String =
        p(ctx).getString("hostname", android.os.Build.MODEL ?: "godwall")
            ?: "godwall"

    fun setHostname(ctx: Context, v: String) {
        p(ctx).edit().putString("hostname", v.trim()).apply()
    }

    fun acceptRoutes(ctx: Context): Boolean = p(ctx).getBoolean("accept_routes", true)

    fun setAcceptRoutes(ctx: Context, v: Boolean) {
        p(ctx).edit().putBoolean("accept_routes", v).apply()
    }

    /**
     * Default OFF, unlike upstream. Godwall runs its own filtered, encrypted resolver; letting
     * the tailnet push MagicDNS over it would silently move every lookup off the resolver the
     * user configured here — a surprising override in the one place this app is meant to be
     * authoritative. Opt in if you want it.
     */
    fun acceptDns(ctx: Context): Boolean = p(ctx).getBoolean("accept_dns", false)

    fun setAcceptDns(ctx: Context, v: Boolean) {
        p(ctx).edit().putBoolean("accept_dns", v).apply()
    }

    fun advertiseExit(ctx: Context): Boolean = p(ctx).getBoolean("advertise_exit", false)

    fun setAdvertiseExit(ctx: Context, v: Boolean) {
        p(ctx).edit().putBoolean("advertise_exit", v).apply()
    }

    const val DEFAULT_LOGIN_SERVER = "https://controlplane.tailscale.com"
}
