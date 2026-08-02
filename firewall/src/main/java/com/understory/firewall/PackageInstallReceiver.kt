package com.understory.firewall

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.understory.firewall.policy.BackendManager
import com.understory.security.Diagnostics
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Watches for newly installed apps and surfaces them (De1984 / Fyrypt "notify
 * on new app install"). On [Intent.ACTION_PACKAGE_ADDED] for a genuinely new,
 * non-system, third-party package it:
 *   1. optionally auto-blocks the app's network access via [BackendManager]
 *      (our superior variant — RethinkDNS's "block newly installed apps"), and
 *   2. posts a [NewAppNotifier] card routing into the per-app firewall.
 *
 * Skips: package REPLACEMENTS (updates), our own package, and system apps —
 * a new-app watch that fires on every OTA-shipped system app is just noise.
 */
class PackageInstallReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_PACKAGE_ADDED) return
        // EXTRA_REPLACING true ⇒ this is an update, not a new install.
        if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
        val pkg = intent.data?.schemeSpecificPart ?: return
        if (pkg == context.packageName) return
        if (!FirewallSettings.isNewAppNotifyEnabled(context) &&
            !FirewallSettings.isNewAppAutoBlockEnabled(context)
        ) return

        val pm = context.packageManager
        val appInfo = runCatching {
            pm.getApplicationInfo(pkg, 0)
        }.getOrNull() ?: return
        // System apps (and their updates) are not user installs — skip.
        val isSystem = (appInfo.flags and
            (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
        if (isSystem) return

        val label = runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(pkg)
        val autoBlock = FirewallSettings.isNewAppAutoBlockEnabled(context)
        Diagnostics.log("firewall.PackageInstallReceiver", "new app: $pkg (autoBlock=$autoBlock)")

        val notify = FirewallSettings.isNewAppNotifyEnabled(context)
        val appCtx = context.applicationContext

        if (!autoBlock) {
            if (notify) NewAppNotifier.notifyInstalled(appCtx, pkg, label, autoBlocked = false)
            return
        }

        // Auto-block needs a suspend backend call — do it off the main thread, then notify with
        // the real outcome. goAsync keeps the receiver alive for the short block.
        val pending = goAsync()
        CoroutineScope(Dispatchers.Default).launch {
            val blocked = runCatching {
                val mgr = BackendManager.get(appCtx)
                if (!mgr.isAvailable()) return@runCatching false
                mgr.setBlocked(pkg, true) in setOf(
                    BackendManager.SetBlockedOutcome.APPLIED,
                    BackendManager.SetBlockedOutcome.UNCHANGED,
                )
            }.getOrDefault(false)
            if (notify) NewAppNotifier.notifyInstalled(appCtx, pkg, label, autoBlocked = blocked)
            runCatching { pending.finish() }
        }
    }
}
