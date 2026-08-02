package com.understory.godwall.ward

import android.content.Context

/**
 * Lockdown — RethinkDNS's universal rule "Block all except bypassed apps and IPs", reduced to
 * the reach Godwall actually has.
 *
 * In Rethink lockdown is a universal firewall rule evaluated before every other rule: everything
 * is denied unless the app carries the "bypass universal" disposition. Godwall's unprivileged
 * enforcement point is the DNS path inside its own tun, so here lockdown means: **every name
 * lookup that reaches Godwall is answered with the block response**, whatever the blocklist says.
 *
 * Apps the user excluded from the tunnel (`AppPolicy.bypassed`) are unaffected — not as a special
 * case in the rule, but because their traffic never enters the tun in the first place. That is
 * the same set Rethink's "bypass universal" names, arrived at structurally.
 *
 * The copy on the button says this in those words. Lockdown here is not a packet-level kill;
 * an app that already knows an address can still reach it. When a privileged shell is attached,
 * the packet-level tier is [com.understory.godwall.apps.NetworkChainBackend], which is separate
 * and is what the FIREWALL mode tier drives.
 */
object Lockdown {

    private const val PREF = "godwall_ward"
    private const val KEY = "lockdown"

    @Volatile
    private var cache: Boolean? = null

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun isEnabled(ctx: Context): Boolean {
        cache?.let { return it }
        val v = p(ctx).getBoolean(KEY, false)
        cache = v
        return v
    }

    fun setEnabled(ctx: Context, on: Boolean) {
        cache = on
        p(ctx).edit().putBoolean(KEY, on).apply()
    }

    /** Hot-path read for the DNS loop; warms from prefs once. */
    fun cached(ctx: Context): Boolean = cache ?: isEnabled(ctx)
}
