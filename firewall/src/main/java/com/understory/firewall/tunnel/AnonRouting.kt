package com.understory.firewall.tunnel

import android.content.Context
import android.content.pm.PackageManager
import android.net.VpnService

/**
 * Anonymizing DNS egress over Tor or I2P — the other two engines InviZible Pro
 * bundles (alongside DNSCrypt). Godwall is a rootless, single-VPN-slot app, so it
 * does NOT embed a Tor/I2P daemon; instead it routes the DNS-filter tunnel's
 * upstream through a SOCKS5 proxy those apps already expose:
 *
 *   - **Tor** via Orbot's SOCKS on 127.0.0.1:9050 (Orbot in proxy mode coexists
 *     with our VPN slot; Orbot in VPN mode would take the slot and the guardrail
 *     keeps us off it).
 *   - **I2P** via the I2P router / i2pd SOCKS on 127.0.0.1:4447.
 *   - **Custom** — any user-supplied SOCKS5 endpoint.
 *
 * The upstream is only built when the proxy actually answers a SOCKS5 greeting
 * ([Socks5Client.isReachable]); otherwise the tunnel falls back honestly rather
 * than black-holing DNS. This is the real, working "route DNS through Tor" path —
 * no daemon shipped, no privilege assumed.
 */
object AnonRouting {

    private const val PREF = "firewall_anon"
    private const val K_ENABLED = "anon_dns_enabled"
    private const val K_MODE = "anon_mode" // tor | i2p | custom
    private const val K_HOST = "anon_custom_host"
    private const val K_PORT = "anon_custom_port"
    private const val K_TARGET = "anon_target_resolver"
    private const val K_USER = "anon_user"
    private const val K_PASS = "anon_pass"

    const val MODE_TOR = "tor"
    const val MODE_I2P = "i2p"
    const val MODE_CUSTOM = "custom"

    const val TOR_HOST = "127.0.0.1"
    const val TOR_PORT = 9050
    const val I2P_HOST = "127.0.0.1"
    const val I2P_PORT = 4447

    private const val PROBE_TIMEOUT_MS = 600

    // Known provider packages (declared in <queries> so they're visible on API 30+).
    val ORBOT_PACKAGES = listOf("org.torproject.android")
    val I2P_PACKAGES = listOf("net.i2p.android.router", "net.i2p.android", "org.purplei2p.i2pd")

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    // ---- settings (defaults chosen so each value works out of the box) ----

    /** Route the tunnel's DNS through the proxy. Default OFF. */
    fun isDnsRoutedThroughProxy(ctx: Context): Boolean = p(ctx).getBoolean(K_ENABLED, false)
    fun setDnsRoutedThroughProxy(ctx: Context, on: Boolean) = p(ctx).edit().putBoolean(K_ENABLED, on).apply()

    /** tor | i2p | custom. Default "tor". */
    fun mode(ctx: Context): String =
        p(ctx).getString(K_MODE, MODE_TOR)?.takeIf { it in setOf(MODE_TOR, MODE_I2P, MODE_CUSTOM) } ?: MODE_TOR
    fun setMode(ctx: Context, m: String) = p(ctx).edit().putString(K_MODE, m).apply()

    fun customHost(ctx: Context): String = p(ctx).getString(K_HOST, "127.0.0.1")?.ifBlank { "127.0.0.1" } ?: "127.0.0.1"
    fun setCustomHost(ctx: Context, v: String) = p(ctx).edit().putString(K_HOST, v.trim()).apply()

    fun customPort(ctx: Context): Int = p(ctx).getInt(K_PORT, 1080)
    fun setCustomPort(ctx: Context, v: Int) = p(ctx).edit().putInt(K_PORT, v).apply()

    /** Resolver the query is sent to over TCP once inside the proxy. Default 1.1.1.1. */
    fun targetResolver(ctx: Context): String = p(ctx).getString(K_TARGET, "1.1.1.1")?.ifBlank { "1.1.1.1" } ?: "1.1.1.1"
    fun setTargetResolver(ctx: Context, v: String) = p(ctx).edit().putString(K_TARGET, v.trim()).apply()

    fun username(ctx: Context): String = p(ctx).getString(K_USER, "").orEmpty()
    fun setUsername(ctx: Context, v: String) = p(ctx).edit().putString(K_USER, v.trim()).apply()
    fun password(ctx: Context): String = p(ctx).getString(K_PASS, "").orEmpty()
    fun setPassword(ctx: Context, v: String) = p(ctx).edit().putString(K_PASS, v).apply()

    fun effectiveHost(ctx: Context): String = when (mode(ctx)) {
        MODE_TOR -> TOR_HOST
        MODE_I2P -> I2P_HOST
        else -> customHost(ctx)
    }

    fun effectivePort(ctx: Context): Int = when (mode(ctx)) {
        MODE_TOR -> TOR_PORT
        MODE_I2P -> I2P_PORT
        else -> customPort(ctx)
    }

    fun label(ctx: Context): String = when (mode(ctx)) {
        MODE_TOR -> "Tor"
        MODE_I2P -> "I2P"
        else -> "Proxy"
    }

    /**
     * Build the SOCKS-DNS upstream, but only if the proxy answers a SOCKS5
     * greeting. Returns null when routing is off or the proxy is unreachable, so
     * the caller falls back to the base upstream instead of black-holing DNS.
     */
    fun upstreamFor(service: VpnService): DnsFilterTun.UpstreamResolver? {
        if (!isDnsRoutedThroughProxy(service)) return null
        val host = effectiveHost(service)
        val port = effectivePort(service)
        val reachable = Socks5Client.isReachable(host, port, PROBE_TIMEOUT_MS) { service.protect(it) }
        if (!reachable) return null
        return DnsFilterTun.UpstreamResolver.socksDns(
            socksHost = host, socksPort = port,
            targetIp = targetResolver(service), label = label(service),
            username = username(service), password = password(service),
        )
    }

    /** Whether the proxy for the current mode currently answers (for the UI). */
    fun isProxyReachable(ctx: Context, service: VpnService?): Boolean {
        val host = effectiveHost(ctx); val port = effectivePort(ctx)
        val protect: (java.net.Socket) -> Boolean = { service?.protect(it) ?: true }
        return Socks5Client.isReachable(host, port, PROBE_TIMEOUT_MS, protect)
    }

    fun isOrbotInstalled(ctx: Context): Boolean = ORBOT_PACKAGES.any { installed(ctx, it) }
    fun isI2pInstalled(ctx: Context): Boolean = I2P_PACKAGES.any { installed(ctx, it) }

    private fun installed(ctx: Context, pkg: String): Boolean = try {
        ctx.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    } catch (_: Throwable) {
        false
    }
}
