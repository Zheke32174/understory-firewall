package com.understory.godwall.subsystem.tor

import android.content.Context

/**
 * The inclusion / exclusion machinery InviZible exposes for Tor — route-all-through-Tor,
 * select sites, select applications, exclude sites, exclude applications, refresh
 * interval, bypass-LAN, and the bridge selection — as a real, persisted policy with
 * a pure resolver.
 *
 * ## What this is, and the one thing it is honest about
 *
 * This is the POLICY, not the plumbing. [decide] answers, for one app and one
 * destination, "does this flow go through Tor or straight out?" — the exact
 * question the tun datapath asks per flow. It is a total, side-effect-free function
 * that the datapath calls; it is the engine, and it is real.
 *
 * What it does NOT do is move packets. Steering a chosen app's traffic into tor's
 * TransPort / SOCKSPort requires a FULL-TRAFFIC tun datapath (firestack's tun2socks),
 * and Godwall's current tun captures DNS only (see core/GodwallVpnService.kt: it
 * routes the resolver address and nothing else). So the per-app / per-site selection
 * is STORED and RESOLVED here, but ENFORCED only once that datapath is wired.
 * [enforcement] reports which of the two states holds, in one sentence, so a screen
 * over this never draws an "app is on Tor" control it cannot back. That honesty is
 * the point: a routing toggle that silently changes nothing is precisely the dead
 * control this campaign removes.
 *
 * Node-country selection, isolation, ports and bridges are a DIFFERENT surface —
 * they configure the tor daemon itself and are enforced by tor once it runs. They
 * live in [TorDaemonSettings] / [TorBridges], not here.
 */
data class TorRoutingPolicy(
    /**
     * "Route All traffic through Tor" (`pref_fast_all_through_tor`, default true).
     * On  ⇒ everything goes through Tor except [excludeApps] / [excludeSites] (and
     * LAN, when [bypassLan]). Off ⇒ only [unlockApps] / [unlockSites] go through Tor.
     */
    val routeAllThroughTor: Boolean = true,

    /** "Select sites" (`prefTorSiteUnlock`) — hostnames/IPs to send through Tor. */
    val unlockSites: Set<String> = emptySet(),

    /** "Select applications" (`prefTorAppUnlock`) — package names to send through Tor. */
    val unlockApps: Set<String> = emptySet(),

    /** "Exclude sites" (`prefTorSiteExclude`) — hostnames/IPs to send direct. */
    val excludeSites: Set<String> = emptySet(),

    /** "Exclude applications" (`prefTorAppExclude`) — package names to send direct. */
    val excludeApps: Set<String> = emptySet(),

    /**
     * "Refresh interval" (`pref_fast_site_refresh_interval`, default 12) — hours
     * between re-resolving the site lists' IPs. 0 stops refreshing.
     */
    val siteRefreshIntervalHours: Int = 12,

    /** "Bypass LAN addresses" (`Allow LAN`, default true) — LAN + IANA-reserved go direct. */
    val bypassLan: Boolean = true,

    /** "Bridges" — the obfuscation transport chosen for connecting to Tor. */
    val bridgeTransport: TorBridges.Transport = TorBridges.Transport.NONE,

    /** The user's own `Bridge …` lines (InviZible "Use Bridges Own List"). */
    val ownBridgeLines: List<String> = emptyList(),

    /**
     * "Spoof SNI" (`swFakeSni`, default false). Rewrites the TLS SNI for direct
     * (non-Tor) flows. This is a datapath-layer rewrite; it is stored here and, like
     * the routing decision, enforced only when the full-traffic datapath exists.
     */
    val spoofSni: Boolean = false,
) {

    /** Where a flow should go. */
    enum class Verdict { THROUGH_TOR, DIRECT }

    /**
     * The route for one flow. Pure. [host] may be an IP literal or a hostname; when
     * it is a hostname, [bypassLan] cannot be evaluated (that needs the resolved IP,
     * which the datapath holds) and is treated as not-LAN here.
     *
     * @param packageName the owning app's package, or null when unknown.
     * @param host destination host (IP literal or name), or null when unknown.
     */
    fun decide(packageName: String?, host: String?): Verdict {
        // LAN / reserved destinations bypass Tor outright when asked to.
        if (bypassLan && host != null && isLanOrReserved(host)) return Verdict.DIRECT

        val appExcluded = packageName != null && packageName in excludeApps
        val siteExcluded = host != null && matchesSite(host, excludeSites)
        val appUnlocked = packageName != null && packageName in unlockApps
        val siteUnlocked = host != null && matchesSite(host, unlockSites)

        return if (routeAllThroughTor) {
            // All through Tor, minus the explicit exclusions.
            if (appExcluded || siteExcluded) Verdict.DIRECT else Verdict.THROUGH_TOR
        } else {
            // Only the explicitly selected apps/sites take Tor.
            if (appUnlocked || siteUnlocked) Verdict.THROUGH_TOR else Verdict.DIRECT
        }
    }

    /**
     * Whether this policy is merely stored or actually carried out. Two independent
     * requirements, reported honestly:
     *  - the tor backend must be present and running ([torRunning]), and
     *  - a full-traffic datapath must be steering flows into it ([datapathPresent]).
     */
    fun enforcement(torRunning: Boolean, datapathPresent: Boolean): Enforcement = when {
        !datapathPresent -> Enforcement.STORED_NO_DATAPATH
        !torRunning -> Enforcement.STORED_TOR_DOWN
        else -> Enforcement.ENFORCED
    }

    enum class Enforcement(val enforced: Boolean) {
        /**
         * The datapath that would carry app/site traffic to Tor is not in this build:
         * Godwall's tun captures DNS only today. The selection is saved and resolvable.
         */
        STORED_NO_DATAPATH(false),

        /** The datapath exists but tor is not running, so nothing is being routed yet. */
        STORED_TOR_DOWN(false),

        /** tor is running and the datapath is steering the selected flows into it. */
        ENFORCED(true),
    }

    companion object {
        val DEFAULT = TorRoutingPolicy()

        /**
         * Suffix-aware site match: "example.com" in the list matches "example.com"
         * and "api.example.com", the way a host rule is normally meant. IP literals
         * match exactly. Case-insensitive.
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
         * True for loopback, RFC1918 / RFC4193 private space, link-local, CGNAT and
         * a few IANA-reserved blocks — the "Allow LAN" set. Only evaluates IP
         * literals; a hostname returns false because its network class is unknown
         * until it is resolved (which the datapath does, not this pure function).
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
                o[0] == 10 -> true                                   // 10.0.0.0/8
                o[0] == 127 -> true                                  // loopback
                o[0] == 172 && o[1] in 16..31 -> true                // 172.16.0.0/12
                o[0] == 192 && o[1] == 168 -> true                   // 192.168.0.0/16
                o[0] == 169 && o[1] == 254 -> true                   // link-local
                o[0] == 100 && o[1] in 64..127 -> true               // 100.64.0.0/10 CGNAT
                o[0] == 0 -> true                                    // 0.0.0.0/8
                o[0] >= 224 -> true                                  // multicast + reserved
                else -> false
            }
        }

        private fun isReservedIpv6(h: String): Boolean {
            val a = h.lowercase().substringBefore('%') // strip zone id
            return a == "::1" ||                    // loopback
                a == "::" ||                        // unspecified
                a.startsWith("fe80") ||             // link-local
                a.startsWith("fc") || a.startsWith("fd") || // unique-local fc00::/7
                a.startsWith("ff")                  // multicast
        }
    }
}

/**
 * Persistence for [TorRoutingPolicy]. Saved whether or not the tor binary is present —
 * a user's route selections are not lost because the payload that would enforce them
 * is absent from this build.
 */
object TorRoutingStore {

    private const val PREFS = "godwall_tor_routing"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun snapshot(ctx: Context): TorRoutingPolicy {
        val d = TorRoutingPolicy.DEFAULT
        val s = p(ctx)
        val transport = runCatching {
            TorBridges.Transport.valueOf(s.getString("bridgeTransport", d.bridgeTransport.name) ?: d.bridgeTransport.name)
        }.getOrDefault(d.bridgeTransport)
        return TorRoutingPolicy(
            routeAllThroughTor = s.getBoolean("routeAllThroughTor", d.routeAllThroughTor),
            unlockSites = s.getStringSet("unlockSites", d.unlockSites)?.toSet() ?: d.unlockSites,
            unlockApps = s.getStringSet("unlockApps", d.unlockApps)?.toSet() ?: d.unlockApps,
            excludeSites = s.getStringSet("excludeSites", d.excludeSites)?.toSet() ?: d.excludeSites,
            excludeApps = s.getStringSet("excludeApps", d.excludeApps)?.toSet() ?: d.excludeApps,
            siteRefreshIntervalHours = s.getInt("siteRefreshIntervalHours", d.siteRefreshIntervalHours),
            bypassLan = s.getBoolean("bypassLan", d.bypassLan),
            bridgeTransport = transport,
            ownBridgeLines = (s.getString("ownBridgeLines", "") ?: "")
                .split('\n').map { it.trim() }.filter { it.isNotEmpty() },
            spoofSni = s.getBoolean("spoofSni", d.spoofSni),
        )
    }

    fun save(ctx: Context, v: TorRoutingPolicy) {
        p(ctx).edit()
            .putBoolean("routeAllThroughTor", v.routeAllThroughTor)
            .putStringSet("unlockSites", v.unlockSites)
            .putStringSet("unlockApps", v.unlockApps)
            .putStringSet("excludeSites", v.excludeSites)
            .putStringSet("excludeApps", v.excludeApps)
            .putInt("siteRefreshIntervalHours", v.siteRefreshIntervalHours.coerceAtLeast(0))
            .putBoolean("bypassLan", v.bypassLan)
            .putString("bridgeTransport", v.bridgeTransport.name)
            .putString("ownBridgeLines", v.ownBridgeLines.joinToString("\n"))
            .putBoolean("spoofSni", v.spoofSni)
            .apply()
    }
}
