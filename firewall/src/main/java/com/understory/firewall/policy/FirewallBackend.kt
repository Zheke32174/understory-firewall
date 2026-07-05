package com.understory.firewall.policy

import android.content.Context

/**
 * Stage-1 per-app POLICY backend abstraction (design-v2/firewall.md §7 "slot-free
 * per-app policy core"; ported faithfully from de1984's `FirewallBackend` shape).
 *
 * A backend decides ONE thing: may a given app reach the network at all. This is
 * POLICY (which packages the OS allows to talk), NOT a routing tunnel — there is
 * no per-network-type granularity here, no packet inspection, no DNS/adblock, and
 * crucially NO VpnService. The whole point of the slot-free core is that it never
 * touches the VPN slot, so it coexists with Tailscale.
 *
 * All implementations run their privileged work through the suite's optional
 * [com.understory.elevation.Elevation] broker (the Shizuku shell at uid 2000),
 * never a VpnService and never a reflected `Shizuku.newProcess`. When no shell
 * tier is granted, [isAvailable] returns false and the UI degrades honestly.
 */
interface FirewallBackend {

    /** Short human name for the active-tier label (e.g. "ConnectivityManager"). */
    val name: String

    /**
     * Whether this backend can actually run on this device RIGHT NOW: the OS API
     * level is high enough AND the Shizuku shell is granted. Cheap, synchronous.
     */
    fun isAvailable(context: Context): Boolean

    /**
     * True only for a backend that can block per-network-type (WiFi vs mobile
     * separately). The slot-free ConnectivityManager mechanism is all-or-nothing,
     * so it reports false — the UI states that limitation plainly.
     */
    val supportsGranularControl: Boolean

    /**
     * Arm the underlying kernel/policy chain once, before any per-app rule. For
     * the ConnectivityManager backend this enables FIREWALL_CHAIN_OEM_DENY_3.
     * Idempotent; returns true on success.
     */
    suspend fun arm(): Boolean

    /**
     * Block ([blocked] = true) or allow a single package. Returns true iff the
     * privileged command reported success. The caller (BackendManager) is
     * responsible for exemption filtering — a backend trusts its input.
     */
    suspend fun setAppBlocked(pkg: String, blocked: Boolean): Boolean

    /**
     * Reconcile the device to exactly [blockedPkgs]: every package in the set
     * blocked, every previously-blocked package not in the set allowed again.
     * Implementations SHOULD diff against an in-memory applied-state cache so a
     * re-apply only issues shell commands for packages that actually changed.
     */
    suspend fun applyAll(blockedPkgs: Set<String>): ApplyResult

    /** Best-effort teardown: disarm the chain and clear the applied-state cache. */
    suspend fun reset()

    /**
     * Outcome of an [applyAll] reconcile. [changed] is how many packages had a
     * command issued; [failed] is how many of those commands reported an error.
     * [ok] is true when nothing failed.
     */
    data class ApplyResult(
        val changed: Int,
        val failed: Int,
    ) {
        val ok: Boolean get() = failed == 0

        companion object {
            val NOOP = ApplyResult(changed = 0, failed = 0)
        }
    }
}
