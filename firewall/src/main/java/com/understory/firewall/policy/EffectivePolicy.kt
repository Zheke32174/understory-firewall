package com.understory.firewall.policy

import android.content.Context

/**
 * Pure computation of the EFFECTIVE blocked set — the exact set of packages the
 * backend should have dropped right now — from the persisted policy inputs plus
 * live screen state. No I/O, no shell, no coroutines: a testable function the
 * [BackendManager] calls before every reconcile.
 *
 * Precedence (last word wins, in this order):
 *   1. Default policy seeds the base:
 *        ALLOW_ALL  → base = the explicit [blocked] set (blacklist).
 *        BLOCK_ALL  → base = every installed non-exempt app MINUS the explicit
 *                     [allowed] set (whitelist / lockdown).
 *   2. Conditional flags ADD to the block set when their condition holds:
 *        screen-off packages are added while the screen is OFF.
 *        background packages are added while the screen is OFF too — see the
 *        honesty note below; we do not have a true per-app foreground signal
 *        without extra permission, so "background" is approximated by screen-off.
 *   3. Exemptions REMOVE unconditionally: a VPN provider / system-critical /
 *      shared-uid-contagion package is filtered out LAST, so nothing above can
 *      ever place Tailscale (or core networking) into the effective set.
 *
 * HONESTY: "block in background" is approximated by screen-off. A precise
 * per-app foreground check would need usage-access polling on a timer; that is
 * out of scope for this stage and would drain battery. The UI states the
 * approximation plainly. This is still the all-networks OEM_DENY_3 toggle — no
 * per-network granularity ([FirewallBackend.supportsGranularControl] = false).
 */
object EffectivePolicy {

    /**
     * @param installedPackages every installed package the UI enumerated. Needed
     *   only for BLOCK_ALL (to know what "everything" is); pass an empty set for
     *   ALLOW_ALL and it is ignored.
     * @param screenOn the live screen state; false means the screen-off /
     *   background conditional flags are active.
     */
    fun compute(
        context: Context,
        defaultPolicy: DefaultPolicy,
        blocked: Set<String>,
        allowed: Set<String>,
        screenOff: Set<String>,
        background: Set<String>,
        installedPackages: Set<String>,
        screenOn: Boolean,
    ): Set<String> {
        // 1. Base from default policy.
        val base: MutableSet<String> = when (defaultPolicy) {
            DefaultPolicy.ALLOW_ALL -> blocked.toMutableSet()
            DefaultPolicy.BLOCK_ALL -> (installedPackages - allowed).toMutableSet()
        }

        // 2. Conditional flags — only while the screen is off. Both screen-off
        // and background flags collapse to the same screen-off trigger (see the
        // honesty note); adding both is harmless (set union).
        if (!screenOn) {
            base += screenOff
            base += background
        }

        // 3. Exemptions removed LAST and unconditionally. This is the safety
        // invariant: no combination of default policy + flags can survive this
        // filter for a VPN provider / system-critical package.
        return base.filterNot { UidExemptions.isExempt(context, it) }.toSet()
    }
}
