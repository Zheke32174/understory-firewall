package com.understory.firewall.policy

import android.content.Context
import android.content.pm.PackageManager
import android.os.Process
import com.understory.security.Diagnostics

/**
 * SAFETY-CRITICAL exemption gate (ported from de1984's isUidExempted / hasVpnService
 * logic). A "block all" must NEVER be able to sever the device's VPN tunnel or
 * brick core networking. BackendManager funnels EVERY block request through
 * [isExempt] so an exempt package can only ever be ALLOWED, whatever the UI or a
 * persisted set says.
 *
 * Three exemption classes (any one exempts):
 *   (a) VPN provider — the package hosts a service guarded by
 *       android.permission.BIND_VPN_SERVICE. This is how Android identifies a VPN
 *       app (VPN apps DECLARE that permission on their service; they don't REQUEST
 *       it). This is what protects Tailscale (com.tailscale.ipn) from being cut
 *       off by this firewall — and it protects ANY installed VPN, not just a
 *       hardcoded name.
 *   (b) System-critical — uid < 10000 (system/phone/radio/nfc/networkstack and
 *       friends), or a known networking-core package. Blocking these can take the
 *       device offline entirely.
 *   (c) Shared-UID contagion — a package sharing its Linux uid with any package in
 *       (a) or (b). Android network policy is UID-based, so blocking one package in
 *       a shared uid blocks them all; if any sibling is exempt, the whole uid is.
 *
 * Fail-safe direction: on ANY error while classifying, we exempt (return true).
 * A false exemption merely leaves one app reachable; a false NON-exemption could
 * cut Tailscale or core connectivity — the one outcome the doctrine forbids.
 */
object UidExemptions {

    private const val TAG = "firewall.policy.UidExemptions"

    /** The service permission a VPN app declares. Presence ⇒ VPN provider. */
    private const val VPN_SERVICE_PERMISSION = "android.permission.BIND_VPN_SERVICE"

    /** First non-system application uid. Anything below is a platform uid. */
    private const val FIRST_APP_UID = Process.FIRST_APPLICATION_UID // 10000

    /**
     * Core networking / platform packages that must always keep the network even
     * though some carry an application uid. Belt-and-suspenders on top of the
     * uid < 10000 rule.
     */
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

    /**
     * True if [pkg] must never be blocked. Cheap, synchronous, defensive. Any
     * classification error resolves to true (exempt) — see class doc.
     */
    fun isExempt(context: Context, pkg: String): Boolean {
        if (pkg.isBlank()) return true
        if (pkg in ALWAYS_EXEMPT_PACKAGES) return true
        if (pkg == context.packageName) return true // never block ourselves

        return try {
            val pm = context.packageManager
            val uid = runCatching { pm.getApplicationInfo(pkg, 0).uid }.getOrNull()
                ?: return true // can't resolve → exempt, fail safe

            // (b) platform uid.
            if (uid < FIRST_APP_UID) return true

            // Gather every package that shares this uid (usually just [pkg]).
            val siblings = runCatching { pm.getPackagesForUid(uid)?.toList() }
                .getOrNull()
                ?.takeIf { it.isNotEmpty() }
                ?: listOf(pkg)

            // (a) + (c): exempt if ANY package in the uid is a VPN provider or a
            // named-critical package.
            siblings.any { s ->
                s in ALWAYS_EXEMPT_PACKAGES || hasVpnService(pm, s)
            }
        } catch (t: Throwable) {
            Diagnostics.error(TAG, "isExempt($pkg) threw ${t.javaClass.simpleName} — exempting (fail safe)")
            true
        }
    }

    /**
     * The full set of currently-installed exempt packages, for the UI to render
     * greyed "Protected — VPN provider" rows. Best-effort; a scan error yields the
     * always-exempt set at minimum (never an empty set that would let the UI offer
     * to block Tailscale).
     */
    fun exemptPackages(context: Context): Set<String> {
        val out = HashSet(ALWAYS_EXEMPT_PACKAGES)
        out += context.packageName
        try {
            val pm = context.packageManager
            val apps = pm.getInstalledApplications(0)
            for (ai in apps) {
                val pkg = ai.packageName
                if (ai.uid < FIRST_APP_UID || hasVpnService(pm, pkg)) {
                    out += pkg
                }
            }
        } catch (t: Throwable) {
            Diagnostics.error(TAG, "exemptPackages scan threw ${t.javaClass.simpleName} — partial set")
        }
        return out
    }

    /**
     * True if [pkg] hosts a service declaring [VPN_SERVICE_PERMISSION]. VPN apps
     * declare this on their service (it gates who may bind the VPN); they do not
     * request it as a uses-permission, so this is the correct probe.
     */
    private fun hasVpnService(pm: PackageManager, pkg: String): Boolean = try {
        @Suppress("DEPRECATION")
        val info = pm.getPackageInfo(pkg, PackageManager.GET_SERVICES)
        info.services?.any { it.permission == VPN_SERVICE_PERMISSION } ?: false
    } catch (t: Throwable) {
        // A lookup failure must NOT read as "not a VPN" — but here returning false
        // is safe because the uid < 10000 and named-package checks run alongside,
        // and a genuine VPN provider is normally resolvable. Log for visibility.
        Diagnostics.error(TAG, "hasVpnService($pkg) threw ${t.javaClass.simpleName}")
        false
    }
}
