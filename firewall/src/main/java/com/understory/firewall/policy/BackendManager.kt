package com.understory.firewall.policy

import android.content.Context
import com.understory.elevation.Elevation
import com.understory.security.Diagnostics
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

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

    /**
     * The explicit-ALLOW set used in [DefaultPolicy.BLOCK_ALL] (whitelist) mode:
     * the packages punched through the lockdown. In ALLOW_ALL mode this set is
     * inert. Persisted alongside the blocked set so a default-policy flip is
     * lossless in both directions.
     */
    fun allowedPackages(): Set<String> =
        prefs().getStringSet(K_ALLOWED, emptySet())?.toSet() ?: emptySet()

    private fun persistAllowed(set: Set<String>) {
        prefs().edit().putStringSet(K_ALLOWED, set).apply()
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

    // ---------------------------------------------------------------
    // Stage-3 effective-set apply (default policy + flags + exemptions)
    // ---------------------------------------------------------------

    /**
     * Compute the effective blocked set from the FULL persisted policy
     * ([DefaultPolicy] + blocked + allowed + screen-off/background flags) and
     * the given live [screenOn] state, then reconcile the device to it via the
     * existing diff-cache [applyAll]. This is the Stage-3 choke point; the
     * screen-state monitor, the QS tile, boot restore, and profile-apply all
     * funnel through here so exemptions are re-asserted every single time.
     *
     * Runs in [NonCancellable] so a screen flicker (rapid off→on) that cancels
     * the debounced caller can't tear down mid-reconcile and leave the device
     * half-applied — mirrors de1984's NonCancellable apply.
     *
     * @param installedPackages the installed-app set, needed only for BLOCK_ALL
     *   (to know what "everything" is). Pass what the UI already loaded; boot /
     *   tile paths pass a fresh enumeration.
     */
    suspend fun applyEffective(
        installedPackages: Set<String>,
        screenOn: Boolean,
    ): FirewallBackend.ApplyResult = withContext(NonCancellable) {
        val effective = EffectivePolicy.compute(
            context = appContext,
            defaultPolicy = PolicyStore.getDefaultPolicy(appContext),
            blocked = blockedPackages(),
            allowed = allowedPackages(),
            screenOff = PolicyStore.getScreenOffPackages(appContext),
            background = PolicyStore.getBackgroundPackages(appContext),
            installedPackages = installedPackages,
            screenOn = screenOn,
        )
        val backend = activeBackend ?: return@withContext FirewallBackend.ApplyResult.NOOP
        if (effective.isNotEmpty()) backend.arm()
        // NOTE: do NOT persistBlocked(effective) here — the effective set folds
        // in transient (screen-off) and derived (block-all) members. Persisting
        // it would corrupt the user's explicit blocked/allowed set. applyAll's
        // own persist is bypassed by calling the backend directly.
        backend.applyAll(effective)
    }

    /**
     * Flip the global default policy and immediately re-apply the effective set.
     * BLOCK_ALL is the whitelist "lockdown"; ALLOW_ALL is the Stage-1 blacklist.
     * Exemptions still win, so BLOCK_ALL can never sever Tailscale.
     */
    suspend fun applyDefaultPolicy(
        policy: DefaultPolicy,
        installedPackages: Set<String>,
        screenOn: Boolean,
    ): FirewallBackend.ApplyResult {
        PolicyStore.setDefaultPolicy(appContext, policy)
        return applyEffective(installedPackages, screenOn)
    }

    /**
     * Add/remove [pkg] from the explicit-ALLOW set (the whitelist holes used in
     * BLOCK_ALL). Exempt packages are already allowed implicitly; adding one is a
     * harmless no-op. Re-applies the effective set.
     */
    suspend fun setAllowed(
        pkg: String,
        allowed: Boolean,
        installedPackages: Set<String>,
        screenOn: Boolean,
    ): FirewallBackend.ApplyResult {
        val cur = allowedPackages()
        persistAllowed(if (allowed) cur + pkg else cur - pkg)
        return applyEffective(installedPackages, screenOn)
    }

    /**
     * One-tap Lockdown: set BLOCK_ALL and clear the explicit allow set (nothing
     * punched through except exemptions), then apply. The QS tile calls this.
     * [screenOn] is passed true because a manual lockdown is a deliberate,
     * screen-independent action.
     */
    suspend fun applyLockdown(installedPackages: Set<String>): FirewallBackend.ApplyResult {
        persistAllowed(emptySet())
        PolicyStore.setDefaultPolicy(appContext, DefaultPolicy.BLOCK_ALL)
        Diagnostics.log(TAG, "LOCKDOWN engaged (BLOCK_ALL, allow set cleared)")
        return applyEffective(installedPackages, screenOn = true)
    }

    /** Lift Lockdown: back to ALLOW_ALL, re-apply the explicit blocked set only. */
    suspend fun liftLockdown(installedPackages: Set<String>): FirewallBackend.ApplyResult {
        PolicyStore.setDefaultPolicy(appContext, DefaultPolicy.ALLOW_ALL)
        Diagnostics.log(TAG, "LOCKDOWN lifted (ALLOW_ALL)")
        return applyEffective(installedPackages, screenOn = true)
    }

    /** True iff the global default is BLOCK_ALL (whitelist / lockdown active). */
    fun isLockdown(): Boolean =
        PolicyStore.getDefaultPolicy(appContext) == DefaultPolicy.BLOCK_ALL

    /**
     * Persist [profile] into the store and re-apply. Used by the profiles UI to
     * switch between saved rule sets (Home / Untrusted Wi-Fi / Lockdown).
     */
    suspend fun applyProfile(
        profile: PolicyProfile,
        installedPackages: Set<String>,
        screenOn: Boolean,
    ): FirewallBackend.ApplyResult {
        // Restore the explicit blocked + allowed sets and flags into our prefs.
        persistBlocked(profile.blocked)
        persistAllowed(profile.allow)
        PolicyStore.restoreInto(appContext, profile)
        Diagnostics.log(TAG, "applyProfile: ${profile.name}")
        return applyEffective(installedPackages, screenOn)
    }

    /**
     * Boot / app-start restore: re-arm and re-apply the persisted blocked set (the
     * kernel chain does not survive reboot). Filters through exemptions again in
     * case the installed-app set changed (e.g. a VPN was installed since). Returns
     * the result, or NOOP if nothing to do / no backend.
     *
     * HONESTY: rootless firewalls have NO true boot persistence — the kernel
     * OEM_DENY_3 chain is cleared by reboot and cannot be re-armed until the
     * Shizuku shell is re-granted post-boot. [com.understory.firewall.policy.FirewallBootReceiver]
     * polls for elevation and calls this once it is available; until then the
     * rules are genuinely inactive.
     */
    suspend fun restore(): FirewallBackend.ApplyResult {
        val lockdown = isLockdown()
        val persisted = blockedPackages()
        if (persisted.isEmpty() && !lockdown) return FirewallBackend.ApplyResult.NOOP
        // In BLOCK_ALL we must enumerate installed apps so "everything" is known;
        // in ALLOW_ALL the blocked set alone suffices but enumerating is cheap
        // and harmless. Screen is treated as on during restore; the screen-state
        // monitor re-applies conditional flags on the next SCREEN_OFF.
        val installed = if (lockdown) installedNonSelfPackages() else emptySet()
        Diagnostics.log(TAG, "restore: re-applying ${persisted.size} persisted policies (lockdown=$lockdown)")
        return applyEffective(installedPackages = installed, screenOn = true)
    }

    /**
     * Every installed package except our own — the "everything" universe for
     * BLOCK_ALL. Best-effort: a scan error yields an empty set (BLOCK_ALL then
     * degrades to just the explicit blocked set, which is safe, not dangerous).
     */
    fun installedNonSelfPackages(): Set<String> = try {
        appContext.packageManager.getInstalledApplications(0)
            .asSequence()
            .map { it.packageName }
            .filter { it != appContext.packageName }
            .toSet()
    } catch (t: Throwable) {
        Diagnostics.error(TAG, "installedNonSelfPackages scan threw ${t.javaClass.simpleName}")
        emptySet()
    }

    /** Disarm everything and clear the persisted set + allow set + default policy. */
    suspend fun clearAll() {
        activeBackend?.reset()
        persistBlocked(emptySet())
        persistAllowed(emptySet())
        PolicyStore.setDefaultPolicy(appContext, DefaultPolicy.ALLOW_ALL)
        Diagnostics.log(TAG, "clearAll: policies cleared, allow set cleared, default → ALLOW_ALL, chain disarmed")
    }

    private fun prefs() =
        appContext.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    companion object {
        private const val TAG = "firewall.policy.BackendManager"
        private const val PREF = "firewall_policy"
        private const val K_BLOCKED = "policy_blocked_packages"
        private const val K_ALLOWED = "policy_allowed_packages"

        @Volatile
        private var instance: BackendManager? = null

        /** Process-singleton, so the applied-state cache and persistence are shared. */
        fun get(context: Context): BackendManager =
            instance ?: synchronized(this) {
                instance ?: BackendManager(context.applicationContext).also { instance = it }
            }
    }
}
