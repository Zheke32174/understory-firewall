package com.understory.godwall.apps

import android.content.Context

/**
 * The set of packages the user has asked to deny the network outright.
 *
 * Kept separate from the DNS-layer rules in
 * [com.understory.godwall.core.AppPolicy] because it is a different kind of
 * claim with a different reach and a different requirement. Blackhole and bypass
 * are enforced by Godwall's own tunnel and work unprivileged; this set is
 * enforced by the platform firewall chain through [NetworkChainBackend] and does
 * nothing at all without a privileged shell from Yojimbo.
 *
 * Storing a package here therefore does NOT mean it is denied. The Apps screen
 * reads [NetworkChainBackend.unavailableReason] alongside this set and says so.
 * [UidExemptions] is applied on the way in, so a protected package can never
 * enter the set in the first place.
 */
object DeniedApps {

    private const val PREF = "godwall_denied_apps"
    private const val KEY = "denied"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun all(ctx: Context): Set<String> = p(ctx).getStringSet(KEY, emptySet())?.toSet() ?: emptySet()

    fun set(ctx: Context, pkg: String, denied: Boolean) {
        if (denied && UidExemptions.isExempt(ctx, pkg)) return
        val cur = (p(ctx).getStringSet(KEY, emptySet()) ?: emptySet()).toMutableSet()
        if (denied) cur += pkg else cur -= pkg
        p(ctx).edit().putStringSet(KEY, cur).apply()
    }

    /** Packages in the set that are also currently installed and non-exempt. */
    fun effective(ctx: Context): Set<String> = all(ctx).filterNot { UidExemptions.isExempt(ctx, it) }.toSet()
}
