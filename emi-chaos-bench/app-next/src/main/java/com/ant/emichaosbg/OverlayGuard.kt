package com.ant.emichaosbg

import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject

/**
 * WHO CAN DRAW OVER THIS APP, AND WHO CAN READ IT.
 *
 * This is the surviving THIRD of the old TapjackGuard. The rest of that class was
 * deleted rather than ported, and it is worth naming why, because the deleted part
 * was producing a manufactured all-clear:
 *
 *   - `protect(View)` was @Deprecated and had no callers.
 *   - `observe(MotionEvent)` had ZERO callers — the Activity never overrode
 *     dispatchTouchEvent, so it was never invoked.
 *   - `setBlocking()` returned false unconditionally and never wrote its field.
 *   - Consequently `filteredTouches` was permanently 0, and the Security screen
 *     rendered "Obscured taps: 0" for a detector that had never observed a single
 *     touch. A zero from something that never looked reads exactly like a zero
 *     from something that looked and found nothing. That is the one thing a
 *     counter-surveillance readout must never do.
 *
 * What remains genuinely works and is what carried the value:
 *   - [status] enumerates the apps that hold SYSTEM_ALERT_WINDOW *and have it
 *     granted*, via AppOpsManager.unsafeCheckOpNoThrow — i.e. the set of apps that
 *     COULD tapjack this one — and the enabled accessibility services from
 *     Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, which can read every screen
 *     and inject input and are the usual home of stalkerware.
 *   - [openOverlaySettings] / [openAccessibilitySettings] are one-tap routes to
 *     revoke either.
 *
 * LIVE overlay detection — "is something drawn over this app RIGHT NOW" — comes
 * from [OverlayWatch], the accessibility service, and only when the user has
 * enabled it. That is stated on the screen rather than implied.
 *
 * Holding the overlay permission is not wrongdoing: screen recorders, chat heads
 * and colour filters all use it legitimately. This is a list to recognise, not an
 * accusation.
 */
class OverlayGuard(private val ctx: Context) {

    fun status(): String {
        val o = JSONObject()

        val overlays = JSONArray()
        try {
            val pm = ctx.packageManager
            val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
            @Suppress("DEPRECATION")
            val pkgs = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            for (p in pkgs) {
                val perms = p.requestedPermissions ?: continue
                if (!perms.contains(android.Manifest.permission.SYSTEM_ALERT_WINDOW)) continue
                val ai = p.applicationInfo ?: continue
                val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                val granted = try {
                    if (ops != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                        ops.unsafeCheckOpNoThrow(
                            "android:system_alert_window", ai.uid, p.packageName
                        ) == AppOpsManager.MODE_ALLOWED
                    else Settings.canDrawOverlays(ctx)
                } catch (_: Throwable) { false }
                if (!granted) continue
                overlays.put(JSONObject()
                    .put("pkg", p.packageName)
                    .put("label", try { pm.getApplicationLabel(ai).toString() }
                        catch (_: Throwable) { p.packageName })
                    .put("system", system))
            }
            o.put("overlayReadable", true)
        } catch (_: Throwable) {
            // Package visibility can be restricted. Say so rather than reporting an empty list,
            // which would read as "nothing can draw over you".
            o.put("overlayReadable", false)
        }
        o.put("overlayApps", overlays)
        o.put("overlayCount", overlays.length())

        val a11y = JSONArray()
        try {
            val enabled = Settings.Secure.getString(
                ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
            val on = Settings.Secure.getInt(
                ctx.contentResolver, Settings.Secure.ACCESSIBILITY_ENABLED, 0) == 1
            o.put("a11yEnabled", on)
            if (enabled.isNotBlank()) {
                for (c in enabled.split(':')) {
                    if (c.isBlank()) continue
                    val pkg = c.substringBefore('/')
                    val label = try {
                        val ai = ctx.packageManager.getApplicationInfo(pkg, 0)
                        ctx.packageManager.getApplicationLabel(ai).toString()
                    } catch (_: Throwable) { pkg }
                    a11y.put(JSONObject()
                        .put("component", c)
                        .put("pkg", pkg)
                        .put("label", label)
                        .put("isThisApp", pkg == ctx.packageName))
                }
            }
        } catch (_: Throwable) {}
        o.put("a11yServices", a11y)
        o.put("a11yCount", a11y.length())

        // Live overlay picture, from the accessibility service — present only if enabled.
        o.put("liveWatch", runCatching { JSONObject(OverlayWatch.status()) }
            .getOrDefault(JSONObject().put("enabled", false)))
        o.put("checkedAt", System.currentTimeMillis())
        return o.toString()
    }

    /** Opens the system screen where overlay permission is granted or revoked per app. */
    fun openOverlaySettings(): Boolean = try {
        ctx.startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (_: Throwable) { false }

    /** Opens the system accessibility screen so an unexpected service can be turned off. */
    fun openAccessibilitySettings(): Boolean = try {
        ctx.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (_: Throwable) { false }
}
