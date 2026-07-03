package com.understory.firewall

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import com.understory.security.Diagnostics

/**
 * One-shot capability scan: which installed apps hold remote-admin-class
 * permissions that would let them control the device, read its screen,
 * see your notifications, or watch which apps you launch?
 *
 * The scan is intentionally conservative — we only flag *granted*
 * capabilities (active a11y service, active notification listener,
 * AppOps mode == ALLOWED), not "declares the permission in its
 * manifest." A long list of theoretical risks would be noise; the
 * short list of currently-active grants is actionable.
 *
 * Findings drive two surfaces:
 *
 *  1. AuditScreen, where the user reviews and either revokes the
 *     capability (deep link into the corresponding system settings
 *     page) or adds the app to the firewall blocklist.
 *  2. The first-run gate, which on the firewall's very first arm
 *     offers to block every detected app at once. Opt-in, never
 *     automatic.
 */
data class AuditFinding(
    val packageName: String,
    val label: String,
    val capabilities: List<RiskCapability>,
    /**
     * Capabilities we could NOT confirm one way or the other (AppOps
     * returned MODE_DEFAULT and the manifest-permission fallback was also
     * inconclusive). Rendered as "unknown", NEVER as clean (CD-4d). A
     * finding with only unknown caps still surfaces so the user isn't
     * shown a false green.
     */
    val unknownCapabilities: List<RiskCapability> = emptyList(),
) {
    /** True if this finding carries at least one confirmed granted cap. */
    val hasConfirmed: Boolean get() = capabilities.isNotEmpty()
}

enum class RiskCapability(
    val display: String,
    val explanation: String,
    /**
     * Settings action that takes the user to the system page where
     * this capability is granted/revoked. The audit screen surfaces
     * this so the user can revoke at the source rather than only
     * compensating via the firewall's network blocklist.
     */
    val revokeAction: String?,
    /**
     * Severity weight on a 0–100 scale, used to rank findings in the
     * audit. The weights aren't a quantitative claim — they're an
     * ordering: device-admin and accessibility (full device/screen
     * control) > notification listener and overlay (read-secrets +
     * tap-jacking substrate) > usage-stats and install-pkgs (foreground
     * surveillance + silent payloads) > manage-storage (read every
     * file, but only files — no execution surface).
     *
     * The audit's primary sort uses max-severity-within-finding, so
     * one device-admin app outranks an app holding three lower-tier
     * caps. That's the right ordering for "what should I look at
     * first" — the headline-risk finding goes to the top.
     */
    val severity: Int,
) {
    DeviceAdmin(
        display = "Device admin",
        explanation = "Can lock the device, wipe data, force password change, " +
            "and disable the camera. Granted via Settings → Security → Device " +
            "admin apps.",
        revokeAction = Settings.ACTION_SECURITY_SETTINGS,
        severity = 100,
    ),
    AccessibilityService(
        display = "Accessibility service",
        explanation = "Can read every screen and click anywhere on your " +
            "behalf — a complete remote-control surface, by design. " +
            "Granted via Settings → Accessibility → Installed services.",
        revokeAction = Settings.ACTION_ACCESSIBILITY_SETTINGS,
        severity = 100,
    ),
    NotificationListener(
        display = "Notification access",
        explanation = "Can read every notification including 2FA codes and " +
            "message previews from any app. Granted via Settings → Notifications " +
            "→ Notification access (or Special app access).",
        revokeAction = Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS,
        severity = 70,
    ),
    SystemOverlay(
        display = "Display over other apps",
        explanation = "Can draw on top of other apps — the substrate for " +
            "tap-jacking. A malicious overlay can sit invisibly above your " +
            "real UI and steal taps. Granted via Settings → Apps → Special " +
            "app access → Display over other apps.",
        revokeAction = Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
        severity = 70,
    ),
    UsageStats(
        display = "Usage access",
        explanation = "Can see which apps you launch and for how long. Often " +
            "used to detect when sensitive apps are in the foreground. Granted " +
            "via Settings → Apps → Special app access → Usage access.",
        revokeAction = Settings.ACTION_USAGE_ACCESS_SETTINGS,
        severity = 40,
    ),
    InstallPackages(
        display = "Install unknown apps",
        explanation = "Can install other APKs without going through Play. An " +
            "app holding this can pull down a payload and silently install it. " +
            "Granted per-source via Settings → Apps → Special app access → " +
            "Install unknown apps.",
        revokeAction = Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
        severity = 40,
    ),
    ManageStorage(
        display = "All files access",
        explanation = "Can read and write every file on shared storage, " +
            "including documents from other apps. Granted via Settings → " +
            "Apps → Special app access → All files access.",
        revokeAction = Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION,
        severity = 30,
    );
}

object RemoteAdminAudit {
    /**
     * Run a full scan and return findings sorted by severity (number
     * of granted capabilities, descending). Apps with zero granted
     * capabilities are omitted entirely — the audit is a list of
     * *risky* apps, not an inventory of all apps.
     *
     * Cost: one PackageManager pass, plus a handful of AppOps queries
     * per app. On a typical device with ~150 user-visible packages
     * this is sub-100ms — fine to call from a LaunchedEffect.
     */
    fun scan(ctx: Context): List<AuditFinding> {
        val pm = ctx.packageManager
        val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
        val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        val a11y = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager

        // Each per-source catch logs to Diagnostics so a partial scan
        // (e.g. AccessibilityManager unavailable on this build) shows
        // up in the in-app diagnostics screen rather than silently
        // returning a too-small finding set. Silent failure is the
        // worst possible mode for a security feature: the user sees
        // "audit clean" and concludes there's nothing to do.
        val deviceAdmins: Set<String> = runCatching {
            dpm?.activeAdmins.orEmpty().mapNotNullTo(HashSet()) { it.packageName }
        }.getOrElse {
            Diagnostics.error(
                "firewall.RemoteAdminAudit",
                "deviceAdmins scan failed: ${it.javaClass.simpleName}: ${it.message}",
            )
            emptySet()
        }

        val a11yServices: Set<String> = runCatching {
            a11y?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .orEmpty()
                .mapNotNullTo(HashSet()) { it.resolveInfo?.serviceInfo?.packageName }
        }.getOrElse {
            Diagnostics.error(
                "firewall.RemoteAdminAudit",
                "a11yServices scan failed: ${it.javaClass.simpleName}: ${it.message}",
            )
            emptySet()
        }

        val notifListeners: Set<String> = parseColonComponentList(
            runCatching {
                Settings.Secure.getString(ctx.contentResolver, "enabled_notification_listeners")
            }.getOrElse {
                Diagnostics.error(
                    "firewall.RemoteAdminAudit",
                    "notifListeners read failed: ${it.javaClass.simpleName}: ${it.message}",
                )
                null
            }
        )

        val findings = mutableListOf<AuditFinding>()
        val installed = runCatching {
            pm.getInstalledApplications(0)
        }.getOrElse {
            Diagnostics.error(
                "firewall.RemoteAdminAudit",
                "getInstalledApplications failed: ${it.javaClass.simpleName}: ${it.message} " +
                    "— audit will be empty. Check that QUERY_ALL_PACKAGES is granted in the manifest.",
            )
            emptyList()
        }

        for (ai in installed) {
            if (ai.packageName == ctx.packageName) continue
            val caps = mutableListOf<RiskCapability>()
            val unknown = mutableListOf<RiskCapability>()
            if (ai.packageName in deviceAdmins) caps += RiskCapability.DeviceAdmin
            if (ai.packageName in a11yServices) caps += RiskCapability.AccessibilityService
            if (ai.packageName in notifListeners) caps += RiskCapability.NotificationListener
            if (ops != null) {
                // Tri-state: on MODE_DEFAULT fall through to a manifest-
                // permission check for the ops that have a paired runtime/
                // special permission (usage-stats, overlay). Others stay
                // AppOps-only.
                when (opTri(ops, pm, AppOpsManager.OPSTR_GET_USAGE_STATS,
                    "android.permission.PACKAGE_USAGE_STATS", ai.uid, ai.packageName)) {
                    OpTri.Granted -> caps += RiskCapability.UsageStats
                    OpTri.Unknown -> unknown += RiskCapability.UsageStats
                    OpTri.NotGranted -> {}
                }
                when (opTri(ops, pm, AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                    "android.permission.SYSTEM_ALERT_WINDOW", ai.uid, ai.packageName)) {
                    OpTri.Granted -> caps += RiskCapability.SystemOverlay
                    OpTri.Unknown -> unknown += RiskCapability.SystemOverlay
                    OpTri.NotGranted -> {}
                }
                // OPSTR_REQUEST_INSTALL_PACKAGES / OPSTR_MANAGE_EXTERNAL_STORAGE
                // are @hide in the public android.jar. Inline the documented
                // op-strings (stable across our minSdk 33 range). No paired
                // permission fallback needed — these read cleanly.
                when (opTri(ops, pm, "android:request_install_packages",
                    "android.permission.REQUEST_INSTALL_PACKAGES", ai.uid, ai.packageName)) {
                    OpTri.Granted -> caps += RiskCapability.InstallPackages
                    OpTri.Unknown -> unknown += RiskCapability.InstallPackages
                    OpTri.NotGranted -> {}
                }
                when (opTri(ops, pm, "android:manage_external_storage",
                    "android.permission.MANAGE_EXTERNAL_STORAGE", ai.uid, ai.packageName)) {
                    OpTri.Granted -> caps += RiskCapability.ManageStorage
                    OpTri.Unknown -> unknown += RiskCapability.ManageStorage
                    OpTri.NotGranted -> {}
                }
            }
            if (caps.isNotEmpty() || unknown.isNotEmpty()) {
                findings += AuditFinding(
                    packageName = ai.packageName,
                    label = runCatching { ai.loadLabel(pm).toString() }
                        .getOrElse { ai.packageName },
                    capabilities = caps,
                    unknownCapabilities = unknown,
                )
            }
        }
        Diagnostics.log(
            "firewall.RemoteAdminAudit",
            "scan complete: ${findings.size} app(s) with granted capabilities " +
                "(out of ${installed.size} installed)",
        )
        // Sort: max severity within finding (so a single device-admin
        // app outranks one with three lower-tier caps), then count
        // (ties broken by "more caps is more concerning"), then name.
        return findings.sortedWith(
            compareByDescending<AuditFinding> { f ->
                f.capabilities.maxOfOrNull { it.severity } ?: 0
            }
                .thenByDescending { it.capabilities.size }
                .thenBy { it.label.lowercase() }
        )
    }

    /** Tri-state result of an AppOps grant check (§5.4 fix, A5/D10). */
    private enum class OpTri { Granted, NotGranted, Unknown }

    /**
     * Tri-state grant check with a MODE_DEFAULT → manifest-permission
     * fallback. AppOps MODE_ALLOWED ⇒ Granted; MODE_IGNORED/ERRORED ⇒
     * NotGranted. On MODE_DEFAULT (the op has no explicit user decision)
     * we consult [pm.checkPermission] for the paired [manifestPerm]:
     * GRANTED ⇒ Granted, DENIED ⇒ NotGranted. A query that throws or
     * remains ambiguous returns Unknown — rendered honestly, never "clean."
     */
    @Suppress("DEPRECATION")
    private fun opTri(
        ops: AppOpsManager,
        pm: PackageManager,
        op: String,
        manifestPerm: String,
        uid: Int,
        pkg: String,
    ): OpTri {
        // Per-call exceptions are logged at debug level: a SecurityException
        // for one op on one package is normal on some OEM builds and would
        // flood diagnostics if elevated to error.
        val mode = runCatching { ops.checkOpNoThrow(op, uid, pkg) }
            .getOrElse {
                Diagnostics.log(
                    "firewall.RemoteAdminAudit",
                    "checkOpNoThrow($op, $pkg) threw: ${it.javaClass.simpleName}",
                )
                return OpTri.Unknown
            }
        return when (mode) {
            AppOpsManager.MODE_ALLOWED -> OpTri.Granted
            AppOpsManager.MODE_IGNORED, AppOpsManager.MODE_ERRORED -> OpTri.NotGranted
            else -> {
                // MODE_DEFAULT (or an unexpected mode): defer to the paired
                // manifest permission's grant state.
                val perm = runCatching { pm.checkPermission(manifestPerm, pkg) }
                    .getOrElse {
                        return OpTri.Unknown
                    }
                when (perm) {
                    PackageManager.PERMISSION_GRANTED -> OpTri.Granted
                    PackageManager.PERMISSION_DENIED -> OpTri.NotGranted
                    else -> OpTri.Unknown
                }
            }
        }
    }

    /**
     * Parse a colon-separated list of `package/component` entries — the
     * format Settings.Secure uses for enabled_notification_listeners (and
     * historically for enabled_accessibility_services, though we use the
     * AccessibilityManager API for that). Returns the package-name set.
     */
    private fun parseColonComponentList(s: String?): Set<String> {
        if (s.isNullOrBlank()) return emptySet()
        return s.split(":").mapNotNullTo(HashSet()) { entry ->
            val slash = entry.indexOf('/')
            if (slash > 0) entry.substring(0, slash).takeIf { it.isNotEmpty() } else null
        }
    }
}
