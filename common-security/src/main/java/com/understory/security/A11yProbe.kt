package com.understory.security

import android.content.Context
import android.provider.Settings
import android.view.accessibility.AccessibilityManager

/**
 * A malicious accessibility service can read text on screen and inject taps.
 * That defeats every visual hardening we apply, including FLAG_SECURE.
 *
 * We can't block accessibility services from app code. What we CAN do is detect
 * any non-system service is enabled and surface a warning so the user knows the
 * threat surface they're operating under. The IME path bypasses a11y interaction
 * entirely; the autofill path is also resistant because the value is filled via
 * IPC, not via on-screen text.
 */
object A11yProbe {

    data class State(val enabled: Boolean, val activeServiceCount: Int)

    fun check(ctx: Context): State {
        val mgr = ctx.getSystemService(AccessibilityManager::class.java)
            ?: return State(enabled = false, activeServiceCount = 0)
        if (!mgr.isEnabled) return State(enabled = false, activeServiceCount = 0)
        val list = mgr.getEnabledAccessibilityServiceList(
            android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
        )
        // Best effort filter to surface only third-party services. We treat
        // anything not under Google's, Samsung's, or the Android system
        // package prefixes as third-party.
        val knownSystemPrefixes = listOf(
            "com.google.android.",
            "com.android.",
            "com.samsung.android.",
            "android.",
        )
        val thirdParty = list.count { svc ->
            val pkg = svc.resolveInfo?.serviceInfo?.packageName ?: ""
            knownSystemPrefixes.none { pkg.startsWith(it) }
        }
        return State(enabled = true, activeServiceCount = thirdParty)
    }

    /**
     * Surface to the user via Settings — they decide. We don't refuse.
     */
    fun openA11ySettings(ctx: Context) {
        runCatching {
            ctx.startActivity(android.content.Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }
    }
}
