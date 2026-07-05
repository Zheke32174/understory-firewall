package com.understory.firewall.policy

import android.content.Context
import android.os.Build
import com.understory.elevation.Elevation
import com.understory.security.Diagnostics
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The Stage-1 slot-free star (design-v2/firewall.md §7): a genuine per-app,
 * kernel-level firewall on Android 13+ that drops a blocked app's packets on
 * EVERY network (WiFi + mobile + VPN) WITHOUT a VpnService.
 *
 * Mechanism (ported faithfully from de1984's ConnectivityManagerFirewallBackend,
 * re-expressed through OUR Shizuku substrate — NOT a reflected Shizuku.newProcess):
 *   arm once:   `cmd connectivity set-chain3-enabled true`
 *   per app:    `cmd connectivity set-package-networking-enabled <enabled> <pkg>`
 *               (enabled=false ⇒ blocked)
 * These run as the Shizuku shell user (uid 2000) via [Elevation.runShell], which
 * binds our own IShellService. The commands arm the kernel
 * FIREWALL_CHAIN_OEM_DENY_3 chain in netd; the block is all-or-nothing per app
 * (hence [supportsGranularControl] = false) and is lost on reboot (BackendManager
 * re-applies on boot).
 *
 * INVARIANT — SLOT-FREE: this path NEVER constructs a VpnService.Builder, never
 * establishes a tun, never prepares VPN consent. There is deliberately no
 * `android.net.VpnService` import anywhere in this package. That is what keeps the
 * VPN slot free for Tailscale. Do not add one.
 */
class ConnectivityManagerBackend(
    private val appContext: Context,
) : FirewallBackend {

    override val name: String = "ConnectivityManager"

    override val supportsGranularControl: Boolean = false

    private val mutex = Mutex()

    /**
     * In-memory applied-state cache: packageName -> isBlocked. Lets [applyAll]
     * issue a shell command only for packages whose desired state differs from
     * the last applied state (de1984's diff-cache approach — one command per real
     * change, not one per app on every reconcile).
     */
    private val appliedPolicies = HashMap<String, Boolean>()

    override fun isAvailable(context: Context): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            Elevation.canRunShell(context)

    override suspend fun arm(): Boolean = mutex.withLock {
        val r = runShellOrNull(listOf("cmd", "connectivity", "set-chain3-enabled", "true"))
        val ok = r?.ok == true
        if (ok) {
            Diagnostics.log(TAG, "armed FIREWALL_CHAIN_OEM_DENY_3 (set-chain3-enabled true)")
        } else {
            Diagnostics.error(TAG, "arm failed: exit=${r?.exit} err=${r?.err?.trim()?.take(160)}")
        }
        ok
    }

    override suspend fun setAppBlocked(pkg: String, blocked: Boolean): Boolean = mutex.withLock {
        setAppBlockedLocked(pkg, blocked)
    }

    /** Caller must hold [mutex]. */
    private suspend fun setAppBlockedLocked(pkg: String, blocked: Boolean): Boolean {
        // enabled = !blocked : `set-package-networking-enabled true` ALLOWS,
        // `false` BLOCKS. This is POLICY (may this app talk), not routing.
        val enabled = (!blocked).toString()
        val r = runShellOrNull(
            listOf("cmd", "connectivity", "set-package-networking-enabled", enabled, pkg),
        )
        val ok = r?.ok == true
        if (ok) {
            appliedPolicies[pkg] = blocked
            Diagnostics.log(TAG, "policy $pkg → ${if (blocked) "BLOCK" else "ALLOW"} (all networks)")
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

            // Desired = every package in blockedPkgs is BLOCK; every package the
            // cache currently has as BLOCK but which left the set flips to ALLOW.
            val desired = HashMap<String, Boolean>(appliedPolicies.size + blockedPkgs.size)
            for ((p, wasBlocked) in appliedPolicies) {
                if (wasBlocked) desired[p] = false // previously blocked → now allow
            }
            for (p in blockedPkgs) desired[p] = true

            for ((pkg, shouldBlock) in desired) {
                if (appliedPolicies[pkg] == shouldBlock) continue // no change → no command
                changed++
                if (!setAppBlockedLocked(pkg, shouldBlock)) failed++
            }
            Diagnostics.log(TAG, "applyAll: ${blockedPkgs.size} blocked, $changed changed, $failed failed")
            FirewallBackend.ApplyResult(changed = changed, failed = failed)
        }

    override suspend fun reset() = mutex.withLock {
        val r = runShellOrNull(listOf("cmd", "connectivity", "set-chain3-enabled", "false"))
        if (r?.ok != true) {
            Diagnostics.error(TAG, "reset (disarm) reported exit=${r?.exit}")
        }
        appliedPolicies.clear()
        Diagnostics.log(TAG, "reset: chain disarmed, applied cache cleared")
    }

    /**
     * Run a privileged argv through the suite broker, returning null on any
     * not-elevated / bind failure rather than throwing. Never surfaces a raw
     * throwable to the caller.
     */
    private suspend fun runShellOrNull(cmd: List<String>) =
        runCatching { Elevation.runShell(appContext, cmd, COMMAND_TIMEOUT_MS) }.getOrNull()

    companion object {
        private const val TAG = "firewall.policy.CM"
        private const val COMMAND_TIMEOUT_MS = 15_000L
    }
}
