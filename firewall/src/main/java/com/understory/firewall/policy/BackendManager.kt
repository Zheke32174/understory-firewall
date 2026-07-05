package com.understory.firewall.policy

import android.content.Context
import com.understory.elevation.Elevation
import com.understory.security.Diagnostics

/**
 * The single choke point for Stage-1 per-app policy (design-v2/firewall.md §7).
 * Selects the strongest available slot-free backend, enforces the [UidExemptions]
 * safety gate on EVERY write, persists the blocked set, and re-applies it on boot.
 *
 * Backend priority: ConnectivityManager (A13+) > NetworkPolicyManager (A12-).
 * Both are slot-free (no VpnService); the CM one is the real all-networks kernel
 * drop, the NPM one is the honest metered-only fallback. Availability is tied to
 * the Shizuku shell binder lifecycle via [Elevation.canRunShell] — if Shizuku is
 * revoked, [activeBackend] goes null and the UI degrades honestly.
 *
 * Persistence lives in its OWN SharedPreferences file (not FirewallSettings): the
 * restrict worklist there is a *watchlist* the user acts on via OS deep-links,
 * whereas this blocked set is a hard, enforced policy. Keeping them separate
 * avoids conflating "flagged to review" with "actively blocked".
 */
class BackendManager private constructor(
    private val appContext: Context,
) {

    /** The [SetBlockedOutcome] distinguishes a protected (exempt) app from a fail. */
    enum class SetBlockedOutcome {
        /** The command ran and reported success. */
        APPLIED,

        /** No change was needed (already in the desired state). */
        UNCHANGED,

        /** The package is exempt (VPN provider / system-critical) — no-op, by design. */
        PROTECTED,

        /** No slot-free backend is available (Shizuku not granted / OS too old). */
        UNAVAILABLE,

        /** A backend ran the command but it failed. */
        FAILED,
    }

    // Candidate backends, strongest first. Instantiated once; isAvailable() is the
    // live gate (it re-reads the Shizuku binder + OS level every call).
    private val cm = ConnectivityManagerBackend(appContext)
    private val npm = NetworkPolicyManagerBackend(appContext)
    private val candidates: List<FirewallBackend> = listOf(cm, npm)

    /**
     * The backend that would run right now, or null when none is available. Kept a
     * fresh computed read (not cached) so a Shizuku grant/revoke that happens while
     * the screen is open is reflected without a manual refresh — mirrors de1984's
     * "keep old backend live until the new one is active" reactivity, simplified to
     * a pure selection because our backends are stateless w.r.t. the binder.
     */
    val activeBackend: FirewallBackend?
        get() = candidates.firstOrNull { it.isAvailable(appContext) }

    /** True iff some slot-free backend can run right now. */
    fun isAvailable(): Boolean = activeBackend != null

    /**
     * A short, honest tier label for the header. Always states "slot-free" and the
     * reach the active backend actually delivers — never overclaims.
     */
    fun tierLabel(): String = when (val b = activeBackend) {
        cm -> "Slot-free · Shizuku · all networks"
        npm -> "Slot-free · Shizuku · metered data only"
        null ->
            if (!Elevation.canRunShell(appContext)) "Needs Shizuku (not granted)"
            else "No slot-free backend on this OS"
        else -> b.name
    }

    // ---------------------------------------------------------------
    // Persisted blocked set
    // ---------------------------------------------------------------

    fun blockedPackages(): Set<String> =
        prefs().getStringSet(K_BLOCKED, emptySet())?.toSet() ?: emptySet()

    private fun persistBlocked(set: Set<String>) {
        prefs().edit().putStringSet(K_BLOCKED, set).apply()
    }

    // ---------------------------------------------------------------
    // Writes — every one passes through the exemption gate
    // ---------------------------------------------------------------

    /**
     * Block or allow [pkg]. Exempt packages (Tailscale / system) can NEVER be
     * blocked here — they short-circuit to [SetBlockedOutcome.PROTECTED] and are
     * never added to the persisted set. On a real ALLOW of an exempt package we
     * still scrub it from the set (defensive: a set that somehow contains an exempt
     * pkg is repaired).
     */
    suspend fun setBlocked(pkg: String, blocked: Boolean): SetBlockedOutcome {
        if (blocked && UidExemptions.isExempt(appContext, pkg)) {
            Diagnostics.log(TAG, "setBlocked($pkg, true) refused — PROTECTED (exempt)")
            // Ensure it is not lingering in the persisted set.
            val cur = blockedPackages()
            if (pkg in cur) persistBlocked(cur - pkg)
            return SetBlockedOutcome.PROTECTED
        }

        val backend = activeBackend ?: return SetBlockedOutcome.UNAVAILABLE

        val current = blockedPackages()
        val already = pkg in current
        if (blocked == already) return SetBlockedOutcome.UNCHANGED

        // Arm the chain before the first block of a session (idempotent).
        if (blocked && current.isEmpty()) backend.arm()

        val ok = backend.setAppBlocked(pkg, blocked)
        if (!ok) return SetBlockedOutcome.FAILED

        persistBlocked(if (blocked) current + pkg else current - pkg)
        return SetBlockedOutcome.APPLIED
    }

    /**
     * Reconcile the device to the given desired blocked set, minus any exempt
     * packages (filtered here at the choke point, so "block all" can never sever
     * Tailscale). Persists the filtered set and returns the backend result.
     */
    suspend fun applyAll(desiredBlocked: Set<String>): FirewallBackend.ApplyResult {
        val backend = activeBackend ?: return FirewallBackend.ApplyResult.NOOP
        val filtered = desiredBlocked.filterNot { UidExemptions.isExempt(appContext, it) }.toSet()
        if (filtered.isNotEmpty()) backend.arm()
        val result = backend.applyAll(filtered)
        persistBlocked(filtered)
        return result
    }

    /**
     * Boot / app-start restore: re-arm and re-apply the persisted blocked set (the
     * kernel chain does not survive reboot). Filters through exemptions again in
     * case the installed-app set changed (e.g. a VPN was installed since). Returns
     * the result, or NOOP if nothing to do / no backend.
     */
    suspend fun restore(): FirewallBackend.ApplyResult {
        val persisted = blockedPackages()
        if (persisted.isEmpty()) return FirewallBackend.ApplyResult.NOOP
        Diagnostics.log(TAG, "restore: re-applying ${persisted.size} persisted policies")
        return applyAll(persisted)
    }

    /** Disarm everything and clear the persisted set (a full "allow all"). */
    suspend fun clearAll() {
        activeBackend?.reset()
        persistBlocked(emptySet())
        Diagnostics.log(TAG, "clearAll: policies cleared and chain disarmed")
    }

    private fun prefs() =
        appContext.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    companion object {
        private const val TAG = "firewall.policy.BackendManager"
        private const val PREF = "firewall_policy"
        private const val K_BLOCKED = "policy_blocked_packages"

        @Volatile
        private var instance: BackendManager? = null

        /** Process-singleton, so the applied-state cache and persistence are shared. */
        fun get(context: Context): BackendManager =
            instance ?: synchronized(this) {
                instance ?: BackendManager(context.applicationContext).also { instance = it }
            }
    }
}
