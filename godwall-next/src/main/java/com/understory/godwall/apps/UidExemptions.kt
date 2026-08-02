package com.understory.godwall.apps

import android.content.Context
import android.content.pm.PackageManager
import android.os.Process
import com.understory.security.Diagnostics

/**
 * The exemption gate. Every block request funnels through [isExempt], so an
 * exempt package can only ever be allowed, whatever the UI or a stored set says.
 *
 * Three exemption classes, any one of which exempts:
 *   (a) the package hosts a service guarded by android.permission.BIND_VPN_SERVICE
 *       — that is how Android identifies a VPN provider (they DECLARE the
 *       permission on the service; they do not request it);
 *   (b) uid below [Process.FIRST_APPLICATION_UID], or a named networking-core
 *       package — blocking these can take the device off the network entirely;
 *   (c) any package sharing a Linux uid with (a) or (b), because Android network
 *       policy is uid-keyed and blocking one member blocks the whole uid.
 *
 * Class (a) matters differently here than it did in the old build. There, it was
 * described as what protects the incumbent tunnel from being cut off. In Godwall
 * the VPN provider it must not cut off IS US: Godwall holds the slot, and a rule
 * that severed our own uid would take the DNS filter and the mesh node down with
 * it. [context.packageName] is exempted explicitly for the same reason.
 *
 * Fail-safe direction: any error while classifying resolves to exempt. A false
 * exemption leaves one app reachable; a false non-exemption can take the device
 * or Godwall itself off the network.
 */
object UidExemptions {

    private const val TAG = "godwall.apps.UidExemptions"

    private const val VPN_SERVICE_PERMISSION = "android.permission.BIND_VPN_SERVICE"

    private val FIRST_APP_UID = Process.FIRST_APPLICATION_UID

    private val ALWAYS_EXEMPT_PACKAGES = setOf(
        "android",
        "com.android.systemui",
        "com.android.networkstack",
        "com.android.networkstack.tethering",
        "com.google.android.networkstack",
        "com.android.server.telecom",
        "com.android.phone",
        "com.android.providers.downloads",
        "com.android.vpndialogs",
    )

    /** True if [pkg] must never be blocked. Cheap, synchronous, defensive. */
    fun isExempt(context: Context, pkg: String): Boolean {
        if (pkg.isBlank()) return true
        if (pkg in ALWAYS_EXEMPT_PACKAGES) return true
        if (pkg == context.packageName) return true

        return try {
            val pm = context.packageManager
            val uid = runCatching { pm.getApplicationInfo(pkg, 0).uid }.getOrNull()
                ?: return true
            if (uid < FIRST_APP_UID) return true

            val siblings = runCatching { pm.getPackagesForUid(uid)?.toList() }
                .getOrNull()
                ?.takeIf { it.isNotEmpty() }
                ?: listOf(pkg)

            siblings.any { s -> s in ALWAYS_EXEMPT_PACKAGES || hasVpnService(pm, s) }
        } catch (t: Throwable) {
            Diagnostics.error(TAG, "isExempt($pkg) threw ${t.javaClass.simpleName} — exempting")
            true
        }
    }

    /** Why a package is protected, for the row's supporting line. */
    fun reason(context: Context, pkg: String): String = when {
        pkg == context.packageName -> "Godwall itself"
        pkg in ALWAYS_EXEMPT_PACKAGES -> "core networking"
        else -> {
            val pm = context.packageManager
            val uid = runCatching { pm.getApplicationInfo(pkg, 0).uid }.getOrNull()
            when {
                uid != null && uid < FIRST_APP_UID -> "platform uid"
                uid != null && (pm.getPackagesForUid(uid) ?: emptyArray()).any { hasVpnService(pm, it) } ->
                    "VPN provider"
                else -> "protected"
            }
        }
    }

    private fun hasVpnService(pm: PackageManager, pkg: String): Boolean = try {
        @Suppress("DEPRECATION")
        val info = pm.getPackageInfo(pkg, PackageManager.GET_SERVICES)
        info.services?.any { it.permission == VPN_SERVICE_PERMISSION } ?: false
    } catch (t: Throwable) {
        Diagnostics.error(TAG, "hasVpnService($pkg) threw ${t.javaClass.simpleName}")
        false
    }
}
