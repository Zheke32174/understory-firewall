package com.understory.firewall

import android.content.Context

/**
 * Persisted firewall configuration. Plain SharedPreferences — these
 * values aren't credentials, just user preferences (which apps the
 * user has chosen to block).
 *
 * The blocklist is the set of package names whose outbound traffic is
 * captured by our VpnService and dropped. Default: empty (nothing
 * blocked). Toggling an app to "blocked" adds it; toggling back
 * removes it.
 */
object FirewallSettings {
    private const val PREF = "firewall_settings"
    private const val K_BLOCKLIST = "blocklist"
    private const val K_VPN_ENABLED = "vpn_enabled"
    private const val K_VPN_PREEMPTED = "vpn_preempted"
    private const val K_DNS_PROVIDER = "dns_provider"
    private const val K_FIRST_RUN_AUDIT_DONE = "first_run_audit_done"
    private const val K_AUDIT_ACKNOWLEDGED = "audit_acknowledged"
    private const val K_OVERLAY_ROUTING = "overlay_routing_enabled"
    private const val K_OVERLAY_NETWORK = "overlay_network"
    private const val K_BLOCKED_PORTS = "blocked_ports"

    /**
     * Comma-separated list of ports the user wants blocked. Each entry
     * is a TCP/UDP port number 1..65535. Phase-1 stores intent only;
     * Phase-2 (packet-forwarder VPN extension) consumes this set to
     * actually drop matching packets across all apps.
     */
    fun getBlockedPorts(ctx: Context): Set<Int> {
        val raw = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(K_BLOCKED_PORTS, "") ?: ""
        return raw.split(',').mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..65_535 }
            .toSet()
    }

    fun setBlockedPorts(ctx: Context, ports: Set<Int>) {
        val canonical = ports.filter { it in 1..65_535 }.sorted()
            .joinToString(",")
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putString(K_BLOCKED_PORTS, canonical)
            .apply()
    }

    /** Which overlay network the user has selected to route through.
     *  One of "i2p" | "lokinet" | "yggdrasil"; default "i2p". */
    fun getOverlayNetwork(ctx: Context): String =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(K_OVERLAY_NETWORK, "i2p")
            ?: "i2p"

    fun setOverlayNetwork(ctx: Context, network: String) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putString(K_OVERLAY_NETWORK, network)
            .apply()
    }

    /** Whether the firewall VPN should route blocked apps through the
     *  selected overlay's SOCKS proxy instead of dropping their traffic.
     *  Phase α scaffold: storing the toggle is supported; the
     *  FirewallVpnService consumes this in a follow-up phase when the
     *  SOCKS-relay path is implemented. Default false. */
    fun isOverlayRoutingEnabled(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(K_OVERLAY_ROUTING, false)

    fun setOverlayRoutingEnabled(ctx: Context, enabled: Boolean) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean(K_OVERLAY_ROUTING, enabled)
            .apply()
    }

    /** Set of package names currently blocked. */
    fun getBlockedPackages(ctx: Context): Set<String> {
        return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getStringSet(K_BLOCKLIST, emptySet())
            ?.toSet()
            ?: emptySet()
    }

    fun setBlockedPackages(ctx: Context, packages: Set<String>) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putStringSet(K_BLOCKLIST, packages)
            .apply()
    }

    fun isBlocked(ctx: Context, packageName: String): Boolean =
        packageName in getBlockedPackages(ctx)

    fun setBlocked(ctx: Context, packageName: String, blocked: Boolean) {
        val current = getBlockedPackages(ctx).toMutableSet()
        if (blocked) current += packageName else current -= packageName
        setBlockedPackages(ctx, current)
    }

    /**
     * Whether the user has *requested* the VPN to be on. The VPN may
     * actually be off (e.g. system killed the service) even when this
     * is true — caller checks the actual VpnService state separately.
     */
    fun isVpnRequested(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(K_VPN_ENABLED, false)

    fun setVpnRequested(ctx: Context, requested: Boolean) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean(K_VPN_ENABLED, requested)
            .apply()
    }

    /**
     * Sticky flag set by [FirewallVpnService.onRevoke] when another VPN
     * (e.g. Proton, system AlwaysOn VPN) takes the tunnel slot. Android
     * only allows one active VpnService at a time and the most-recent
     * `prepare()` call wins; when ours is revoked we lose the tun and
     * the consent grant. The UI uses this flag to show a "preempted"
     * banner with a one-tap re-enable that walks back through the
     * consent dialog. Cleared on the next successful establish.
     */
    fun isVpnPreempted(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(K_VPN_PREEMPTED, false)

    fun setVpnPreempted(ctx: Context, preempted: Boolean) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean(K_VPN_PREEMPTED, preempted)
            .apply()
    }

    /**
     * The user's DNS provider preference, identified by [DnsProvider.id].
     * Default = system-default (no override). Stored only — not yet
     * driving the VpnService's tun (that's phase-2 work involving full
     * userspace tun forwarding). For now the user applies the choice
     * via Android's system Private DNS settings, which the firewall
     * deep-links to.
     */
    fun getDnsProviderId(ctx: Context): String =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(K_DNS_PROVIDER, DnsProvider.SYSTEM_DEFAULT.id)
            ?: DnsProvider.SYSTEM_DEFAULT.id

    fun setDnsProviderId(ctx: Context, id: String) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putString(K_DNS_PROVIDER, id)
            .apply()
    }

    /**
     * One-shot flag set after the user has either accepted, declined, or
     * dismissed the first-run audit prompt. The prompt offers to add
     * every detected remote-admin-class app to the blocklist in one go;
     * once handled (in either direction) we don't surface it again — the
     * AuditScreen remains available from the main UI for manual review.
     *
     * Stored as a boolean so a future "reset audit prompt" debug action
     * can clear it cleanly without having to invent a tri-state.
     */
    fun isFirstRunAuditDone(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(K_FIRST_RUN_AUDIT_DONE, false)

    fun setFirstRunAuditDone(ctx: Context, done: Boolean) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putBoolean(K_FIRST_RUN_AUDIT_DONE, done)
            .apply()
    }

    /**
     * Per-package acknowledged set: apps the user has explicitly marked
     * as "I know this one holds remote-admin caps and I'm okay with it"
     * (work-profile MDM, Find My Device, a launcher with usage-stats by
     * design, etc.). Acknowledged apps are filtered out of the audit's
     * default view and excluded from the bulk "Block all" count, but
     * still visible behind a toggle so the user can un-acknowledge.
     *
     * Acknowledging is *separate* from blocking: an app can be
     * acknowledged (don't bother me about the cap) without being on
     * the firewall blocklist. This is the right shape — the audit is
     * a triage view, the blocklist is a network-policy view, and
     * conflating them would force the user to either block legitimate
     * apps or accept perpetual nag.
     */
    fun getAuditAcknowledged(ctx: Context): Set<String> {
        return ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getStringSet(K_AUDIT_ACKNOWLEDGED, emptySet())
            ?.toSet()
            ?: emptySet()
    }

    fun setAuditAcknowledged(ctx: Context, packageName: String, acknowledged: Boolean) {
        val current = getAuditAcknowledged(ctx).toMutableSet()
        if (acknowledged) current += packageName else current -= packageName
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putStringSet(K_AUDIT_ACKNOWLEDGED, current)
            .apply()
    }
}
