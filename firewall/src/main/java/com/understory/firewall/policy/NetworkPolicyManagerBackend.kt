package com.understory.firewall.policy

import android.content.Context
import android.os.Build
import com.understory.elevation.Elevation
import com.understory.security.Diagnostics
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The Android 12-and-below fallback (design-v2/firewall.md §7). The slot-free
 * ConnectivityManager chain (`set-chain3-enabled`) only exists on Android 13+, so
 * on older devices we fall back to the platform's NetworkPolicyManager via the
 * Shizuku shell: `cmd netpolicy add/remove restrict-background-blacklist <uid>`
 * (the same primitive the suite's Restrict worklist already uses).
 *
 * HONEST LIMITATION — this is strictly weaker than the CM chain and we do NOT
 * pretend otherwise: restrict-background-blacklist only reliably denies an app's
 * METERED / mobile-background traffic on stock ROMs. It is WiFi-leaky (an app can
 * still reach the network over unmetered WiFi) and foreground use is not blocked.
 * This is per-app POLICY on metered data, not an all-networks kernel drop. The
 * device this suite targets (Samsung SM-S948U, Android 14/15) runs the CM backend,
 * so this path exists only so an older device is not left with a dead screen — it
 * is not the primary mechanism and is not over-invested in.
 *
 * SLOT-FREE, like the whole package: no VpnService, no tun, no reflected
 * Shizuku.newProcess — only [Elevation.runShell] at the granted shell uid.
 */
class NetworkPolicyManagerBackend(
    private val appContext: Context,
) : FirewallBackend {

    override val name: String = "NetworkPolicyManager (metered-only)"

    override val supportsGranularControl: Boolean = false

    private val mutex = Mutex()

    /** packageName -> isBlocked, applied-state diff cache (see CM backend). */
    private val appliedPolicies = HashMap<String, Boolean>()

    override fun isAvailable(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU &&
            Elevation.canRunShell(context)

    /**
     * netpolicy has no chain to arm — the blacklist is applied per-uid directly.
     * Report success so the manager can proceed to per-app rules.
     */
    override suspend fun arm(): Boolean {
        Diagnostics.log(TAG, "arm: no-op (netpolicy is per-uid, no chain to enable)")
        return true
    }

    override suspend fun setAppBlocked(pkg: String, blocked: Boolean): Boolean = mutex.withLock {
        setAppBlockedLocked(pkg, blocked)
    }

    /** Caller must hold [mutex]. */
    private suspend fun setAppBlockedLocked(pkg: String, blocked: Boolean): Boolean {
        val uid = appUid(pkg)
        if (uid == null) {
            Diagnostics.error(TAG, "policy $pkg failed: unknown package (no uid)")
            return false
        }
        val verb = if (blocked) "add" else "remove"
        val r = runShellOrNull(
            listOf("cmd", "netpolicy", verb, "restrict-background-blacklist", uid.toString()),
        )
        val ok = r?.ok == true
        if (ok) {
            appliedPolicies[pkg] = blocked
            Diagnostics.log(TAG, "policy $pkg → ${if (blocked) "BLOCK" else "ALLOW"} (metered only)")
        } else {
            Diagnostics.error(
                TAG,
                "policy $pkg failed: exit=${r?.exit} err=${r?.err?.trim()?.take(160)}",
            )
        }
        return ok
    }

    override suspend fun applyAll(blockedPkgs: Set<String>): FirewallBackend.ApplyResult =
        mutex.withLock {
            var changed = 0
            var failed = 0
            val desired = HashMap<String, Boolean>(appliedPolicies.size + blockedPkgs.size)
            for ((p, wasBlocked) in appliedPolicies) {
                if (wasBlocked) desired[p] = false
            }
            for (p in blockedPkgs) desired[p] = true
            for ((pkg, shouldBlock) in desired) {
                if (appliedPolicies[pkg] == shouldBlock) continue
                changed++
                if (!setAppBlockedLocked(pkg, shouldBlock)) failed++
            }
            Diagnostics.log(TAG, "applyAll: ${blockedPkgs.size} blocked, $changed changed, $failed failed")
            FirewallBackend.ApplyResult(changed = changed, failed = failed)
        }

    override suspend fun reset() = mutex.withLock {
        // Best-effort: lift every blacklist entry we placed. There is no single
        // "disable" — we walk our own applied set.
        for ((pkg, wasBlocked) in appliedPolicies.toMap()) {
            if (wasBlocked) setAppBlockedLocked(pkg, false)
        }
        appliedPolicies.clear()
        Diagnostics.log(TAG, "reset: blacklist entries lifted, applied cache cleared")
    }

    private fun appUid(pkg: String): Int? =
        runCatching { appContext.packageManager.getApplicationInfo(pkg, 0).uid }.getOrNull()

    private suspend fun runShellOrNull(cmd: List<String>) =
        runCatching { Elevation.runShell(appContext, cmd, COMMAND_TIMEOUT_MS) }.getOrNull()

    companion object {
        private const val TAG = "firewall.policy.NPM"
        private const val COMMAND_TIMEOUT_MS = 15_000L
    }
}
