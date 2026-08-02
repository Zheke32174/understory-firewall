package com.understory.godwall.lan

import android.content.Context
import android.net.wifi.WifiManager

/**
 * Rogue-DHCP detection — the passive half, which is the half that works unprivileged.
 *
 * ## The two things "rogue DHCP detection" can mean, and which one this is
 *
 * A rogue DHCP server on a LAN hands a victim its own address as gateway and/or DNS, putting the
 * attacker in the path. Detecting it splits into two techniques:
 *
 *  1. **Passive** — look at the lease *this device actually accepted* and ask whether the server
 *     that issued it is the one expected for this LAN. Android exposes the accepted lease through
 *     [WifiManager.getDhcpInfo] ([android.net.DhcpInfo.serverAddress]) with no special permission.
 *     If a rogue server won the race, that field already names it. This is what this object does.
 *
 *  2. **Active** — broadcast a `DHCP DISCOVER` and enumerate *every* server that answers, catching
 *     a rogue server even when the legitimate one won this particular lease. That needs a raw
 *     broadcast socket, i.e. `CAP_NET_RAW`, which neither Godwall's own uid nor uid 2000 (the
 *     Yojimbo shell) holds. It is reported absent by [LanDefence], not faked here.
 *
 * So this is an honest passive watch: it baselines the DHCP server the user confirms as
 * legitimate for a LAN (keyed by gateway — see [LanSettings]) and flags when a later lease on that
 * LAN was issued by a different server. It never claims to have probed the network; it reports the
 * server the system already trusted, and whether the user has told us to trust it too.
 *
 * ## Why the DhcpInfo API despite its deprecation
 *
 * [WifiManager.getDhcpInfo] is deprecated, but its replacement (the DHCP server address inside
 * `LinkProperties`) is not exposed to apps at all — `LinkProperties` carries the DNS servers and
 * routes but not the DHCP server identity. The deprecated call is the only permission-free way to
 * read the accepted lease's server address, so it is used deliberately, scoped to this one read.
 */
object RogueDhcp {

    enum class Verdict {
        /** Watch is off. Nothing is being checked; the UI says so rather than implying a pass. */
        DISABLED,

        /** No DHCP lease is visible (cellular, or Wi-Fi with no lease read). Nothing to check. */
        NO_LEASE,

        /** A server issued the lease and there is no trusted baseline yet — offer to trust it. */
        FIRST_SEEN,

        /** The lease server matches the trusted baseline for this LAN. */
        OK,

        /** The lease server differs from the trusted baseline — a different DHCP server answered. */
        ROGUE,
    }

    /**
     * @param server the DHCP server that issued the current lease, formatted, or null.
     * @param gateway the gateway of the current lease (the per-LAN baseline key), or null.
     * @param trusted the server the user confirmed for this LAN, or null.
     */
    data class Result(
        val verdict: Verdict,
        val server: String?,
        val gateway: String?,
        val trusted: String?,
    )

    /**
     * The rule, pure so it is testable without a device.
     *
     * @param watching whether the watch is enabled.
     * @param server the observed DHCP server for the current lease, or null when there is none.
     * @param gateway the observed gateway (the LAN key), or null.
     * @param trusted the previously trusted server for [gateway], or null.
     */
    fun classify(
        watching: Boolean,
        server: String?,
        gateway: String?,
        trusted: String?,
    ): Result {
        if (!watching) return Result(Verdict.DISABLED, server, gateway, trusted)
        if (server.isNullOrBlank() || gateway.isNullOrBlank()) {
            return Result(Verdict.NO_LEASE, server, gateway, trusted)
        }
        return when {
            trusted.isNullOrBlank() -> Result(Verdict.FIRST_SEEN, server, gateway, trusted)
            trusted == server -> Result(Verdict.OK, server, gateway, trusted)
            else -> Result(Verdict.ROGUE, server, gateway, trusted)
        }
    }

    /**
     * Read the accepted lease and classify it against the stored baseline. Touches
     * [WifiManager]; call off the main thread.
     */
    fun check(ctx: Context): Result {
        val lease = readLease(ctx)
        val gateway = lease?.gateway
        val trusted = gateway?.let { LanSettings.trustedDhcpServer(ctx, it) }
        return classify(
            watching = LanSettings.dhcpWatchEnabled(ctx),
            server = lease?.server,
            gateway = gateway,
            trusted = trusted,
        )
    }

    /** The two fields of the accepted lease this watch cares about. */
    data class Lease(val server: String, val gateway: String)

    /**
     * Read the accepted DHCP lease. Returns null when there is no Wi-Fi lease to read — a cellular
     * network has no DHCP server, and a Wi-Fi network mid-association may report 0.0.0.0, which is
     * treated as "no lease" rather than a server address.
     */
    fun readLease(ctx: Context): Lease? = runCatching {
        val wifi = ctx.applicationContext.getSystemService(WifiManager::class.java) ?: return null
        // getDhcpInfo is deprecated, and the deprecation is left visible rather than annotated
        // away: LinkProperties (its nominal successor) exposes DNS servers and routes but NOT the
        // DHCP server address, so this remains the only permission-free read of the lease's issuer.
        val info = wifi.dhcpInfo ?: return null
        val server = formatLeInt(info.serverAddress)
        val gateway = formatLeInt(info.gateway)
        if (server == UNSPECIFIED || gateway == UNSPECIFIED) return null
        Lease(server = server, gateway = gateway)
    }.getOrNull()

    private const val UNSPECIFIED = "0.0.0.0"

    /**
     * Format a [android.net.DhcpInfo] IPv4 integer, which is stored little-endian (least
     * significant byte first) by historical Android convention. Pure, so the endianness is pinned
     * by a test rather than by hoping the platform's own formatter agrees.
     */
    fun formatLeInt(v: Int): String {
        val a = v and 0xFF
        val b = (v shr 8) and 0xFF
        val c = (v shr 16) and 0xFF
        val d = (v shr 24) and 0xFF
        return "$a.$b.$c.$d"
    }
}
