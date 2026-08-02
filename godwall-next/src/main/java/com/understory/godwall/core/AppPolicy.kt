package com.understory.godwall.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

/**
 * Per-app egress policy. Two independent sets, because they are two different questions and
 * conflating them is how a firewall lies to its user:
 *
 *  - **Blackholed** — every DNS query from this app is answered with the block response. The app
 *    keeps its INTERNET permission and can still reach a literal IP, so this is *name-based*
 *    denial and the UI must not call it "no internet".
 *  - **Bypassed** — the app is excluded from the tun entirely (`addDisallowedApplication`), so
 *    Godwall never sees its traffic at all. For apps that break under a VPN, and for Godwall's
 *    own siblings.
 *
 * Both are honest about their reach. Neither claims to be a packet firewall, because without
 * a privileged shell Godwall does not have one.
 */
object AppPolicy {

    private const val PREFS = "godwall_app_policy"
    private const val K_BLACKHOLE = "blackhole"
    private const val K_BYPASS = "bypass"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun blackholed(ctx: Context): Set<String> =
        p(ctx).getStringSet(K_BLACKHOLE, emptySet())?.toSet() ?: emptySet()

    fun bypassed(ctx: Context): Set<String> =
        p(ctx).getStringSet(K_BYPASS, emptySet())?.toSet() ?: emptySet()

    fun setBlackholed(ctx: Context, pkg: String, on: Boolean) = mutate(ctx, K_BLACKHOLE, pkg, on)

    fun setBypassed(ctx: Context, pkg: String, on: Boolean) = mutate(ctx, K_BYPASS, pkg, on)

    private fun mutate(ctx: Context, key: String, pkg: String, on: Boolean) {
        val cur = (p(ctx).getStringSet(key, emptySet()) ?: emptySet()).toMutableSet()
        if (on) cur.add(pkg) else cur.remove(pkg)
        p(ctx).edit().putStringSet(key, cur).apply()
    }

    data class Entry(
        val packageName: String,
        val label: String,
        val system: Boolean,
        val hasInternet: Boolean,
        val blackholed: Boolean,
        val bypassed: Boolean,
    )

    /**
     * Installed apps that can actually reach the network, newest-relevant first.
     *
     * Apps without INTERNET are filtered out rather than listed as "allowed": a row offering to
     * block an app that cannot make a request is noise that makes the real rows harder to find.
     */
    fun installed(ctx: Context): List<Entry> {
        val pm = ctx.packageManager
        val black = blackholed(ctx)
        val bypass = bypassed(ctx)
        val flags = PackageManager.GET_PERMISSIONS
        return runCatching {
            pm.getInstalledPackages(flags)
                .asSequence()
                .filter { it.packageName != ctx.packageName }
                .mapNotNull { pkgInfo ->
                    val ai = pkgInfo.applicationInfo ?: return@mapNotNull null
                    val internet = pkgInfo.requestedPermissions
                        ?.contains(android.Manifest.permission.INTERNET) == true
                    if (!internet) return@mapNotNull null
                    Entry(
                        packageName = pkgInfo.packageName,
                        label = runCatching { pm.getApplicationLabel(ai).toString() }
                            .getOrDefault(pkgInfo.packageName),
                        system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                        hasInternet = true,
                        blackholed = pkgInfo.packageName in black,
                        bypassed = pkgInfo.packageName in bypass,
                    )
                }
                // Anything the user has already acted on floats to the top; the rest sort by
                // label so the list is scannable.
                .sortedWith(
                    compareByDescending<Entry> { it.blackholed || it.bypassed }
                        .thenBy { it.system }
                        .thenBy { it.label.lowercase() },
                )
                .toList()
        }.getOrDefault(emptyList())
    }
}
