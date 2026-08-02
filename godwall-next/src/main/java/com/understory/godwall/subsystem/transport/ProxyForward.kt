package com.understory.godwall.subsystem.transport

import android.content.Context
import com.understory.godwall.R
import com.understory.godwall.chain.ProxyHop

/**
 * The proxy-forward settings surface — InviZible Pro's "Use socks5 proxy" (`swUseProxy`,
 * "InviZible Pro will make all connections through the SOCKS5 proxy") and NetGuard's SOCKS5 proxy
 * (address / port / username / password, "Only TCP traffic will be sent to the proxy server") — as a
 * real, persisted policy with a pure resolver and an honestly-reported enforcement boundary.
 *
 * ## What this is, and the one thing it is honest about
 *
 * This is the POLICY, not the plumbing. [decide] answers, for one app and one destination, "does this
 * flow go out through the forward proxy or straight out?" — a total, side-effect-free function the
 * datapath calls. [asChainHop] turns the configured upstream into a real
 * [com.understory.godwall.chain.ProxyHop] that Godwall's own [com.understory.godwall.chain.ChainDialer]
 * carries traffic through today.
 *
 * What it does NOT do by itself is force EVERY app's traffic through that proxy. Steering an arbitrary
 * app's flows into the upstream requires a FULL-TRAFFIC tun2socks datapath (firestack's data plane,
 * gated in this build — `GatedCapability.PACKET_DATAPLANE`); Godwall's current tun captures DNS only.
 * So the per-app selection is STORED and RESOLVED here, but system-wide ENFORCEMENT waits on that
 * datapath. [enforcement] reports which state holds, in one sentence, so a screen over this never
 * draws an "all apps forwarded" control it cannot back — the same discipline WP-4's TorRoutingPolicy
 * uses. A forward toggle that silently changes nothing is precisely the dead control this campaign
 * removes.
 *
 * ## The reach it can always back
 *
 * As a chain hop the upstream is real now: the in-app chain and any flow Godwall routes through the
 * [com.understory.godwall.chain.EndpointChain] are carried through it by ChainDialer, fail-closed. And
 * SOCKS5/HTTP CONNECT carry TCP only — UDP is not proxied — which the reach sentence states, matching
 * NetGuard's own "Only TCP traffic" note.
 *
 * Pure data + pure functions: no Context is held and no I/O happens on [ProxyForwardSettings].
 * [ProxyForwardStore] owns persistence; the resolver is a total function of its input so it can be
 * reasoned about — and, off-device, tested — without a datapath or a shell.
 */
data class ProxyForwardSettings(
    /** "Use socks5 proxy" master switch (`swUseProxy`). Off ⇒ everything goes direct. */
    val enabled: Boolean = false,

    /** SOCKS5 (RFC 1928) or HTTP CONNECT — the two transports ChainDialer speaks. */
    val mode: Mode = Mode.SOCKS5,

    /** Upstream proxy address (`proxy_server_ip`, NetGuard `setting_socks5_addr`). */
    val host: String = "127.0.0.1",

    /** Upstream proxy port (`proxy_server_port`, NetGuard `setting_socks5_port`). */
    val port: Int = 1080,

    /** Optional username (NetGuard `setting_socks5_username`). Blank ⇒ no auth offered. */
    val username: String = "",

    /** Optional password (NetGuard `setting_socks5_password`). */
    val password: String = "",

    /**
     * "Make all connections through the SOCKS5 proxy" (InviZible proxy mode). On ⇒ everything is
     * forwarded except [excludeApps] / [excludeSites] (and LAN, when [bypassLan]). Off ⇒ only
     * [forwardApps] / [forwardSites] are forwarded.
     */
    val forwardAll: Boolean = true,

    /** Hostnames/IPs to forward, when [forwardAll] is off. */
    val forwardSites: Set<String> = emptySet(),

    /** Package names to forward, when [forwardAll] is off. */
    val forwardApps: Set<String> = emptySet(),

    /** Hostnames/IPs to send direct (InviZible "Exclude sites"). */
    val excludeSites: Set<String> = emptySet(),

    /** Package names to send direct (InviZible `proxy_exclude_apps_from_proxy`). */
    val excludeApps: Set<String> = emptySet(),

    /** LAN + IANA-reserved destinations bypass the proxy. Default on, matching InviZible "Allow LAN". */
    val bypassLan: Boolean = true,
) {

    /** The proxy transport. */
    enum class Mode { SOCKS5, HTTP }

    /** Where a flow should go. */
    enum class Verdict { FORWARD, DIRECT }

    /**
     * The route for one flow. Pure. [host] may be an IP literal or a hostname; when it is a hostname,
     * [bypassLan] cannot be evaluated (that needs the resolved IP, which the datapath holds) and is
     * treated as not-LAN here.
     *
     * @param packageName the owning app's package, or null when unknown.
     * @param host destination host (IP literal or name), or null when unknown.
     */
    fun decide(packageName: String?, host: String?): Verdict {
        if (!enabled) return Verdict.DIRECT
        if (bypassLan && host != null && isLanOrReserved(host)) return Verdict.DIRECT

        val appExcluded = packageName != null && packageName in excludeApps
        val siteExcluded = host != null && matchesSite(host, excludeSites)
        val appForwarded = packageName != null && packageName in forwardApps
        val siteForwarded = host != null && matchesSite(host, forwardSites)

        return if (forwardAll) {
            if (appExcluded || siteExcluded) Verdict.DIRECT else Verdict.FORWARD
        } else {
            if (appForwarded || siteForwarded) Verdict.FORWARD else Verdict.DIRECT
        }
    }

    /**
     * The upstream as a real chain hop, or null when the proxy is off or the address is unusable.
     * Carried by ChainDialer today for any flow routed through the EndpointChain — this is the reach
     * that does not depend on the gated datapath.
     */
    fun asChainHop(id: String): ProxyHop? {
        if (!enabled) return null
        val h = host.trim()
        if (h.isEmpty() || port !in 1..65535) return null
        return when (mode) {
            Mode.SOCKS5 -> ProxyHop.Socks5(id = id, host = h, port = port, username = username, password = password)
            Mode.HTTP -> ProxyHop.HttpConnect(id = id, host = h, port = port, username = username, password = password)
        }
    }

    /**
     * Whether this policy is merely stored or actually carried out system-wide.
     *
     * @param datapathPresent whether the full-traffic tun2socks datapath is wired (firestack). It is
     *   NOT in this build, so callers pass `GatedCapability.PACKET_DATAPLANE.available` (false) and
     *   this reports [Enforcement.STORED_NO_DATAPATH].
     */
    fun enforcement(datapathPresent: Boolean): Enforcement = when {
        !enabled -> Enforcement.DISABLED
        !datapathPresent -> Enforcement.STORED_NO_DATAPATH
        else -> Enforcement.ENFORCED
    }

    enum class Enforcement(val enforced: Boolean) {
        /** The proxy-forward switch is off; every flow goes direct. */
        DISABLED(false),

        /**
         * The datapath that would carry every app's traffic to the proxy is not in this build:
         * Godwall's tun captures DNS only today. The selection is saved and resolvable, and the
         * upstream still forwards flows routed through the egress chain.
         */
        STORED_NO_DATAPATH(false),

        /** The datapath exists and is steering the selected flows into the upstream proxy. */
        ENFORCED(true),
    }

    companion object {
        val DEFAULT = ProxyForwardSettings()

        /**
         * Suffix-aware site match: "example.com" matches "example.com" and "api.example.com"; IP
         * literals match exactly; case-insensitive. Self-contained so this file couples to no sibling
         * work package.
         */
        fun matchesSite(host: String, list: Set<String>): Boolean {
            if (list.isEmpty()) return false
            val h = host.trim().lowercase().trimEnd('.')
            for (raw in list) {
                val e = raw.trim().lowercase().trimEnd('.')
                if (e.isEmpty()) continue
                if (h == e) return true
                if (h.endsWith(".$e")) return true
            }
            return false
        }

        /**
         * True for loopback, RFC1918 / RFC4193 private space, link-local, CGNAT and a few
         * IANA-reserved blocks — the "Allow LAN" set. Only evaluates IP literals; a hostname returns
         * false because its network class is unknown until it is resolved (which the datapath does,
         * not this pure function).
         */
        fun isLanOrReserved(host: String): Boolean {
            val h = host.trim()
            if (h.isEmpty()) return false
            if (h.contains(':')) return isReservedIpv6(h)
            val parts = h.split('.')
            if (parts.size != 4) return false
            val o = IntArray(4)
            for (i in 0 until 4) {
                o[i] = parts[i].toIntOrNull() ?: return false
                if (o[i] !in 0..255) return false
            }
            return when {
                o[0] == 10 -> true                       // 10.0.0.0/8
                o[0] == 127 -> true                      // loopback
                o[0] == 172 && o[1] in 16..31 -> true    // 172.16.0.0/12
                o[0] == 192 && o[1] == 168 -> true       // 192.168.0.0/16
                o[0] == 169 && o[1] == 254 -> true       // link-local
                o[0] == 100 && o[1] in 64..127 -> true   // 100.64.0.0/10 CGNAT
                o[0] == 0 -> true                        // 0.0.0.0/8
                o[0] >= 224 -> true                      // multicast + reserved
                else -> false
            }
        }

        private fun isReservedIpv6(h: String): Boolean {
            val a = h.lowercase().substringBefore('%') // strip zone id
            return a == "::1" ||
                a == "::" ||
                a.startsWith("fe80") ||
                a.startsWith("fc") || a.startsWith("fd") ||
                a.startsWith("ff")
        }

        /**
         * The authoritative sentence resource for an [Enforcement] state, so the surface (WP-9) shows
         * this package's own honest wording rather than inventing its own. Returns a `R.string` id.
         */
        fun enforcementSentenceRes(e: Enforcement): Int = when (e) {
            Enforcement.DISABLED -> R.string.transport_forward_enforce_disabled
            Enforcement.STORED_NO_DATAPATH -> R.string.transport_forward_enforce_stored
            Enforcement.ENFORCED -> R.string.transport_forward_enforce_active
        }
    }
}

/**
 * Persistence for [ProxyForwardSettings]. Saved whether or not the full-traffic datapath is present —
 * a user's forward selections are not lost because the payload that would enforce them system-wide is
 * absent from this build, the same discipline as WP-4's TorRoutingStore.
 */
object ProxyForwardStore {

    private const val PREFS = "godwall_proxy_forward"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The current settings snapshot. Reads SharedPreferences — call off the main thread. */
    fun snapshot(ctx: Context): ProxyForwardSettings {
        val d = ProxyForwardSettings.DEFAULT
        val s = p(ctx)
        val mode = runCatching {
            ProxyForwardSettings.Mode.valueOf(s.getString("mode", d.mode.name) ?: d.mode.name)
        }.getOrDefault(d.mode)
        return ProxyForwardSettings(
            enabled = s.getBoolean("enabled", d.enabled),
            mode = mode,
            host = s.getString("host", d.host) ?: d.host,
            port = s.getInt("port", d.port),
            username = s.getString("username", d.username) ?: d.username,
            password = s.getString("password", d.password) ?: d.password,
            forwardAll = s.getBoolean("forwardAll", d.forwardAll),
            forwardSites = s.getStringSet("forwardSites", d.forwardSites)?.toSet() ?: d.forwardSites,
            forwardApps = s.getStringSet("forwardApps", d.forwardApps)?.toSet() ?: d.forwardApps,
            excludeSites = s.getStringSet("excludeSites", d.excludeSites)?.toSet() ?: d.excludeSites,
            excludeApps = s.getStringSet("excludeApps", d.excludeApps)?.toSet() ?: d.excludeApps,
            bypassLan = s.getBoolean("bypassLan", d.bypassLan),
        )
    }

    /** Persist a whole snapshot. */
    fun save(ctx: Context, v: ProxyForwardSettings) {
        p(ctx).edit()
            .putBoolean("enabled", v.enabled)
            .putString("mode", v.mode.name)
            .putString("host", v.host.trim())
            .putInt("port", v.port.coerceIn(1, 65535))
            .putString("username", v.username)
            .putString("password", v.password)
            .putBoolean("forwardAll", v.forwardAll)
            .putStringSet("forwardSites", v.forwardSites)
            .putStringSet("forwardApps", v.forwardApps)
            .putStringSet("excludeSites", v.excludeSites)
            .putStringSet("excludeApps", v.excludeApps)
            .putBoolean("bypassLan", v.bypassLan)
            .apply()
    }
}
