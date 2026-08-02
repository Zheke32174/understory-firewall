package com.understory.godwall.ward

import android.content.Context

/**
 * Which tiers the master switch brings up — the port of RethinkDNS's `BraveMode`.
 *
 * Rethink ships three: `DNS(0)`, `FIREWALL(1)`, `DNS_FIREWALL(2)`, chosen from a chip row on the
 * home screen, with `DNS_FIREWALL` as the default. Its firewall mode still holds the tun (so app
 * exclusions apply) but stops consulting the blocklist; its DNS mode filters names and leaves the
 * per-app network rules alone. That is exactly the shape reproduced here.
 *
 * Two tiers are added that Rethink does not have, because Godwall carries a tailnet node of its
 * own instead of deferring to another app: [TAILNET_ONLY] and [FULL_STACK]. The spec's chip row
 * is those five, in this order.
 *
 * ## Every flag here is read by the engine, not just stored
 *
 * - [filtersDns] is read per query in `GodwallVpnService.handle` — off, the query is forwarded to
 *   the configured encrypted upstream without the blocklist or the per-app blackhole applying.
 * - [enforcesFirewall] decides whether the platform firewall chain is reconciled on arm
 *   (`NetworkChainBackend.applyAll`) and released on disarm.
 * - [runsTailnet] decides whether the mesh node is started inside our slot on arm.
 *
 * A mode whose tier cannot run on this device is not silently downgraded: [unmet] names the gap
 * and the health banner states it in words.
 */
enum class WardMode(
    val filtersDns: Boolean,
    val enforcesFirewall: Boolean,
    val runsTailnet: Boolean,
) {
    /** Rethink's `BraveMode.DNS` — the battery-saver tier. */
    DNS_ONLY(filtersDns = true, enforcesFirewall = false, runsTailnet = false),

    /** Rethink's `BraveMode.FIREWALL` — per-app denial, no name filtering. */
    FIREWALL_ONLY(filtersDns = false, enforcesFirewall = true, runsTailnet = false),

    /** Rethink's `BraveMode.DNS_FIREWALL`, and the default here too. */
    DNS_FIREWALL(filtersDns = true, enforcesFirewall = true, runsTailnet = false),

    /** The slot carries the mesh data plane and nothing else. */
    TAILNET_ONLY(filtersDns = false, enforcesFirewall = false, runsTailnet = true),

    /** Every tier at once. */
    FULL_STACK(filtersDns = true, enforcesFirewall = true, runsTailnet = true);

    /** The tiers this mode asks for. */
    fun tiers(): List<WardTier> = buildList {
        if (filtersDns) add(WardTier.DNS)
        if (enforcesFirewall) add(WardTier.FIREWALL)
        if (runsTailnet) add(WardTier.TAILNET)
    }

    /**
     * The tiers this mode asks for that the device cannot currently deliver.
     *
     * Pure so it can be tested without a device: the caller supplies what it probed.
     */
    fun unmet(firewallAvailable: Boolean, tailnetAvailable: Boolean): List<WardTier> = buildList {
        if (enforcesFirewall && !firewallAvailable) add(WardTier.FIREWALL)
        if (runsTailnet && !tailnetAvailable) add(WardTier.TAILNET)
    }

    /** True when nothing this mode asks for can run — the whole mode is inert. */
    fun fullyInert(firewallAvailable: Boolean, tailnetAvailable: Boolean): Boolean =
        unmet(firewallAvailable, tailnetAvailable).size == tiers().size
}

/** One enforcement tier. The DNS tier always runs; the other two have requirements. */
enum class WardTier { DNS, FIREWALL, TAILNET }

/**
 * Where the chosen mode is kept.
 *
 * [cached] exists because `GodwallVpnService.handle` consults the mode on every DNS packet, and
 * the read must not be a fresh `SharedPreferences` lookup on that path. The cache is warmed by
 * the first [current] call and refreshed by [set], so the engine and the chip row can never
 * disagree about which mode is live.
 */
object WardModeStore {

    private const val PREF = "godwall_ward"
    private const val KEY = "mode"

    val DEFAULT = WardMode.DNS_FIREWALL

    @Volatile
    private var cache: WardMode? = null

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun current(ctx: Context): WardMode {
        cache?.let { return it }
        val stored = runCatching { WardMode.valueOf(p(ctx).getString(KEY, "") ?: "") }
            .getOrDefault(DEFAULT)
        cache = stored
        return stored
    }

    fun set(ctx: Context, mode: WardMode) {
        cache = mode
        p(ctx).edit().putString(KEY, mode.name).apply()
    }

    /** Hot-path read. Falls back to [current] the first time, then never touches disk. */
    fun cached(ctx: Context): WardMode = cache ?: current(ctx)
}
