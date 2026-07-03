package com.understory.firewall

import android.content.Context

/**
 * Persisted firewall configuration. Plain SharedPreferences — these
 * values aren't credentials, just user preferences (which apps the user
 * flagged, which mode the app is in).
 *
 * V2 model (design-v2/firewall.md §1, §8): the app has two modes.
 *
 *   COMPANION (default, permanent on any device with a VPN): observe /
 *     advise only. No VpnService is ever established. The restrict set is
 *     a *watchlist* the user acts on via Android's own per-app controls.
 *
 *   STANDALONE (opt-in, default-off): the salvaged VpnService engine may
 *     run iff no other VPN holds the slot (VpnSlotProbe guardrail). The
 *     restrict set additionally seeds the engine's hard-block list.
 *
 * The restrict set ([K_RESTRICT_LIST], née K_BLOCKLIST) is shared between
 * both modes: flagging an app in Companion carries over if the user later
 * enables Standalone.
 */
object FirewallSettings {
    private const val PREF = "firewall_settings"

    // ---- V2 keys ----
    private const val K_MODE = "firewall_mode"
    private const val K_ENGINE_ARMED = "engine_armed"      // was K_VPN_ENABLED
    private const val K_AUTO_STOPPED = "auto_stopped"      // was K_VPN_PREEMPTED
    private const val K_RESTRICT_LIST = "restrict_list"    // was K_BLOCKLIST
    private const val K_STANDALONE_EXPLAINED = "standalone_explained"
    private const val K_MIGRATED_V2 = "migrated_v2"
    private const val K_DNS_PROVIDER = "dns_provider"
    private const val K_FIRST_RUN_AUDIT_DONE = "first_run_audit_done"
    private const val K_AUDIT_ACKNOWLEDGED = "audit_acknowledged"

    // ---- Legacy keys (read once during migration, then deleted) ----
    private const val K_LEGACY_BLOCKLIST = "blocklist"
    private const val K_LEGACY_VPN_ENABLED = "vpn_enabled"
    private const val K_LEGACY_VPN_PREEMPTED = "vpn_preempted"
    private const val K_LEGACY_OVERLAY_ROUTING = "overlay_routing_enabled"
    private const val K_LEGACY_OVERLAY_NETWORK = "overlay_network"
    private const val K_LEGACY_BLOCKED_PORTS = "blocked_ports"

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    // ---------------------------------------------------------------
    // Mode
    // ---------------------------------------------------------------

    /**
     * The persisted mode. Default [FirewallMode.COMPANION]. On the
     * operator's Tailscale device this never leaves COMPANION because the
     * guardrail keeps Standalone-armed permanently unreachable — the app
     * is, in effect, the pure Companion egress dashboard.
     */
    fun getMode(ctx: Context): FirewallMode {
        val raw = prefs(ctx).getString(K_MODE, null)
        return runCatching { FirewallMode.valueOf(raw ?: "") }
            .getOrDefault(FirewallMode.COMPANION)
    }

    fun setMode(ctx: Context, mode: FirewallMode) {
        prefs(ctx).edit().putString(K_MODE, mode.name).apply()
    }

    // ---------------------------------------------------------------
    // Engine arm request (only meaningful in STANDALONE)
    // ---------------------------------------------------------------

    /**
     * Whether the user has *requested* the Standalone engine to be armed.
     * Only meaningful when [getMode] == STANDALONE; in COMPANION this is
     * effectively false and the engine never establishes a tun.
     * The engine may actually be down (slot taken, service killed) even
     * when this is true — the caller checks the live VpnSlot state.
     */
    fun isEngineArmed(ctx: Context): Boolean =
        prefs(ctx).getBoolean(K_ENGINE_ARMED, false)

    fun setEngineArmed(ctx: Context, armed: Boolean) {
        prefs(ctx).edit().putBoolean(K_ENGINE_ARMED, armed).apply()
    }

    // ---------------------------------------------------------------
    // Auto-stopped flag (neutral, replaces the "preempted" nag)
    // ---------------------------------------------------------------

    /**
     * Set by [FirewallVpnService.onRevoke] / the slot-watcher when a VPN
     * takes the tunnel slot while the engine was armed. Drives the neutral
     * hub message ("Standalone blocking stopped because a VPN is now using
     * the VPN slot; it will resume when you turn that VPN off"), NOT a
     * "Re-enable" nag. Cleared on the next successful arm or on mode-disable.
     */
    fun isAutoStopped(ctx: Context): Boolean =
        prefs(ctx).getBoolean(K_AUTO_STOPPED, false)

    fun setAutoStopped(ctx: Context, autoStopped: Boolean) {
        prefs(ctx).edit().putBoolean(K_AUTO_STOPPED, autoStopped).apply()
    }

    // ---------------------------------------------------------------
    // Restrict set (Companion watchlist + Standalone hard-block seed)
    // ---------------------------------------------------------------

    /** Set of package names on the restrict worklist. */
    fun getRestrictedPackages(ctx: Context): Set<String> =
        prefs(ctx).getStringSet(K_RESTRICT_LIST, emptySet())?.toSet() ?: emptySet()

    fun setRestrictedPackages(ctx: Context, packages: Set<String>) {
        prefs(ctx).edit().putStringSet(K_RESTRICT_LIST, packages).apply()
    }

    fun isRestricted(ctx: Context, packageName: String): Boolean =
        packageName in getRestrictedPackages(ctx)

    fun setRestricted(ctx: Context, packageName: String, restricted: Boolean) {
        val current = getRestrictedPackages(ctx).toMutableSet()
        if (restricted) current += packageName else current -= packageName
        setRestrictedPackages(ctx, current)
    }

    // ---------------------------------------------------------------
    // Standalone explainer seen
    // ---------------------------------------------------------------

    /** True once the user has seen (and confirmed past) the full-screen
     *  Standalone explainer, so we don't re-nag after they enable it. */
    fun isStandaloneExplained(ctx: Context): Boolean =
        prefs(ctx).getBoolean(K_STANDALONE_EXPLAINED, false)

    fun setStandaloneExplained(ctx: Context, explained: Boolean) {
        prefs(ctx).edit().putBoolean(K_STANDALONE_EXPLAINED, explained).apply()
    }

    // ---------------------------------------------------------------
    // DNS provider
    // ---------------------------------------------------------------

    /**
     * The user's DNS provider preference, identified by [DnsProvider.id].
     * Default = system-default (no override). The only enforced apply path
     * is Android's system Private DNS (DoT), via [PrivateDnsApplier] when
     * WRITE_SECURE_SETTINGS is ADB-granted, else the Settings deep-link.
     */
    fun getDnsProviderId(ctx: Context): String =
        prefs(ctx).getString(K_DNS_PROVIDER, DnsProvider.SYSTEM_DEFAULT.id)
            ?: DnsProvider.SYSTEM_DEFAULT.id

    fun setDnsProviderId(ctx: Context, id: String) {
        prefs(ctx).edit().putString(K_DNS_PROVIDER, id).apply()
    }

    // ---------------------------------------------------------------
    // Audit flow (unchanged)
    // ---------------------------------------------------------------

    /**
     * One-shot flag set after the user has handled the first-run audit
     * prompt (in either direction). Once handled we don't surface it
     * again — the AuditScreen remains available for manual review.
     */
    fun isFirstRunAuditDone(ctx: Context): Boolean =
        prefs(ctx).getBoolean(K_FIRST_RUN_AUDIT_DONE, false)

    fun setFirstRunAuditDone(ctx: Context, done: Boolean) {
        prefs(ctx).edit().putBoolean(K_FIRST_RUN_AUDIT_DONE, done).apply()
    }

    /**
     * Per-package acknowledged set: apps the user has explicitly marked as
     * "I know this one holds remote-admin caps and I'm okay with it."
     * Acknowledging is separate from restricting — the audit is a triage
     * view, the restrict set is a worklist.
     */
    fun getAuditAcknowledged(ctx: Context): Set<String> =
        prefs(ctx).getStringSet(K_AUDIT_ACKNOWLEDGED, emptySet())?.toSet() ?: emptySet()

    fun setAuditAcknowledged(ctx: Context, packageName: String, acknowledged: Boolean) {
        val current = getAuditAcknowledged(ctx).toMutableSet()
        if (acknowledged) current += packageName else current -= packageName
        prefs(ctx).edit().putStringSet(K_AUDIT_ACKNOWLEDGED, current).apply()
    }

    // ---------------------------------------------------------------
    // One-time V2 migration (§8)
    // ---------------------------------------------------------------

    /**
     * Silent, lossless, one-time migration from the v1 key layout. Guarded
     * by [K_MIGRATED_V2]. Copies the old blocklist into the restrict set,
     * deletes the dead keys (ports, overlay), resets the DNS provider if it
     * names a removed DNSCrypt id, and stamps the guard. Call once, early,
     * before any screen reads settings. No migration UI.
     */
    fun migrateV2IfNeeded(ctx: Context) {
        val p = prefs(ctx)
        if (p.getBoolean(K_MIGRATED_V2, false)) return
        val editor = p.edit()

        // Blocklist → restrict set (curated app list survives as "watched").
        // Only seed if the new key is unset, so a partial-run re-migration
        // can't clobber a v2 user's edits.
        if (!p.contains(K_RESTRICT_LIST)) {
            val legacyBlock = p.getStringSet(K_LEGACY_BLOCKLIST, emptySet()) ?: emptySet()
            editor.putStringSet(K_RESTRICT_LIST, legacyBlock.toSet())
        }

        // The old vpn-enabled/preempted flags do not carry over: v2 boots
        // in COMPANION with the engine disarmed. We do not resurrect an
        // armed engine from a v1 install (the guardrail owns arming now).

        // Drop the removed DNSCrypt selection back to system default —
        // those ids no longer exist in the catalog.
        val dnsId = p.getString(K_DNS_PROVIDER, DnsProvider.SYSTEM_DEFAULT.id)
        if (dnsId != null && dnsId.startsWith("dnscrypt-")) {
            editor.putString(K_DNS_PROVIDER, DnsProvider.SYSTEM_DEFAULT.id)
        }

        // Delete dead keys (A11/A12 + the renamed originals).
        editor.remove(K_LEGACY_BLOCKLIST)
        editor.remove(K_LEGACY_VPN_ENABLED)
        editor.remove(K_LEGACY_VPN_PREEMPTED)
        editor.remove(K_LEGACY_OVERLAY_ROUTING)
        editor.remove(K_LEGACY_OVERLAY_NETWORK)
        editor.remove(K_LEGACY_BLOCKED_PORTS)

        editor.putBoolean(K_MIGRATED_V2, true)
        editor.apply()
    }
}
