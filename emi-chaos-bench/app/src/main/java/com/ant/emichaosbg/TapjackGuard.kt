package com.ant.emichaosbg

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.view.MotionEvent
import android.view.View
import android.webkit.JavascriptInterface
import org.json.JSONArray
import org.json.JSONObject

/**
 * TAPJACKING / OVERLAY DEFENCE.
 *
 * THE ATTACK. Another app draws a window on top of this one and leaves it transparent, or
 * leaves a hole in it. You believe you are tapping this app's control; the touch is actually
 * delivered to the attacker's window, or the attacker's window is showing you a lie about what
 * the control underneath does. It is the standard way permission dialogs and confirmations get
 * subverted on Android, and it needs no root — only the overlay permission, which plenty of
 * ordinary-looking apps ask for.
 *
 * THE DEFENCE, which is real and not advisory. Android tags every MotionEvent that was
 * delivered while another window was on top: FLAG_WINDOW_IS_OBSCURED (fully) and
 * FLAG_WINDOW_IS_PARTIALLY_OBSCURED (partially, API 29+). Setting
 * `filterTouchesWhenObscured = true` makes the framework DISCARD those touches before they
 * reach the view at all. That is the one place in this app where something is genuinely
 * blocked rather than reported, and it is the correct trade: a touch you did not knowingly aim
 * at this app should not land, and the cost of dropping it is that you tap again.
 *
 * WHAT IS STILL REPORT-ONLY. Everything else here — which apps hold the overlay permission,
 * which accessibility services are enabled, how many obscured touches were filtered — is
 * observation. Holding the overlay permission is not evidence of wrongdoing; screen recorders,
 * chat heads, colour filters, and accessibility tools all legitimately use it. The count of
 * FILTERED touches is the signal that matters, because that is an overlay actually sitting
 * over this app while you were using it.
 *
 * ACCESSIBILITY. A11y services can read the content of every screen and inject gestures — the
 * single most powerful thing an app on Android can hold, and the usual home of stalkerware.
 * They are enumerated here so an unexpected one is visible. This app does NOT request an
 * accessibility service for itself: the capability it would grant is exactly the capability
 * this app exists to warn about, and asking for it would make this app the most dangerous
 * thing on the device.
 */
class TapjackGuard(private val ctx: Context, private val log: SecureLog) {

    @Volatile private var filteredTouches = 0
    @Volatile private var lastFilteredAt = 0L
    @Volatile private var obscuredSeen = 0
    private val raised = HashMap<String, Long>()
    private val COALESCE_MS = 5 * 60_000L

    /**
     * Applies the framework-level filter and installs an observer so a filtered touch is
     * COUNTED rather than merely dropped. Without the observer the defence works but is
     * invisible, and an attack that is silently defeated teaches the user nothing.
     */
    fun protect(v: View) {
        v.filterTouchesWhenObscured = true
        // The framework consumes obscured touches before onTouchEvent, so they cannot be
        // counted there. A dispatch-level listener still sees the flags on events that DO
        // arrive, which catches the partially-obscured case the filter lets through on older
        // API levels and gives an honest count either way.
        v.setOnTouchListener { _, ev -> noteTouch(ev); false }
    }

    private fun noteTouch(ev: MotionEvent) {
        val obscured = (ev.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0
        val partial = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            (ev.flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0
        if (!obscured && !partial) return
        obscuredSeen++
        filteredTouches++
        lastFilteredAt = System.currentTimeMillis()
        flag(3, "tapjack",
            "A touch arrived while another window was drawn over this app " +
            "(${if (obscured) "fully" else "partially"} obscured). Touches in that state are " +
            "discarded rather than acted on, because an overlay can make you tap a control you " +
            "cannot see. If this keeps happening, something is sitting on top of this app.")
    }

    private fun flag(sev: Int, key: String, what: String) {
        val now = System.currentTimeMillis()
        val prev = raised[key]
        if (prev != null && now - prev < COALESCE_MS) return
        raised[key] = now
        try { log.append(sev, what, "tapjack", "native") } catch (_: Throwable) {}
    }

    /** Apps that can draw over this one, and accessibility services that can read it. */
    @JavascriptInterface
    fun status(): String {
        val o = JSONObject()
        o.put("filterActive", true)
        o.put("filteredTouches", filteredTouches)
        o.put("lastFilteredAt", lastFilteredAt)

        // Apps holding SYSTEM_ALERT_WINDOW. Not an accusation — many legitimate apps use it —
        // but the set of apps that COULD tapjack this one is worth being able to see.
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
                // Skip the platform's own preloads; they are noise, not signal.
                val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                val granted = try {
                    if (ops != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                        ops.unsafeCheckOpNoThrow("android:system_alert_window", ai.uid, p.packageName) ==
                            AppOpsManager.MODE_ALLOWED
                    else Settings.canDrawOverlays(ctx)
                } catch (_: Throwable) { false }
                if (!granted) continue
                overlays.put(JSONObject()
                    .put("pkg", p.packageName)
                    .put("label", try { pm.getApplicationLabel(ai).toString() } catch (_: Throwable) { p.packageName })
                    .put("system", system))
            }
        } catch (_: Throwable) {}
        o.put("overlayApps", overlays)
        o.put("overlayCount", overlays.length())

        // Enabled accessibility services, by component. These can read every screen and inject
        // input; an unexpected entry here is the highest-value thing in this readout.
        val a11y = JSONArray()
        try {
            val enabled = Settings.Secure.getString(ctx.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
            val on = Settings.Secure.getInt(ctx.contentResolver,
                Settings.Secure.ACCESSIBILITY_ENABLED, 0) == 1
            o.put("a11yEnabled", on)
            if (enabled.isNotBlank()) {
                for (c in enabled.split(':')) {
                    if (c.isBlank()) continue
                    val pkg = c.substringBefore('/')
                    val label = try {
                        val ai = ctx.packageManager.getApplicationInfo(pkg, 0)
                        ctx.packageManager.getApplicationLabel(ai).toString()
                    } catch (_: Throwable) { pkg }
                    a11y.put(JSONObject().put("component", c).put("pkg", pkg).put("label", label))
                }
            }
        } catch (_: Throwable) {}
        o.put("a11yServices", a11y)
        o.put("a11yCount", a11y.length())

        o.put("note", "Touches delivered while another window covers this app are DISCARDED, " +
            "not acted on — that is the one thing this app blocks rather than reports. " +
            "Holding the overlay permission is not itself wrongdoing; screen recorders, chat " +
            "bubbles and colour filters all use it legitimately. The filtered-touch count is " +
            "the signal, because that is an overlay actually over this app while you used it.")
        return o.toString()
    }

    /** Opens the system screen where overlay permission is granted or revoked per app. */
    @JavascriptInterface
    fun openOverlaySettings(): Boolean = try {
        val i = android.content.Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        ctx.startActivity(i); true
    } catch (_: Throwable) { false }

    /** Opens the system accessibility screen so an unexpected service can be turned off. */
    @JavascriptInterface
    fun openAccessibilitySettings(): Boolean = try {
        val i = android.content.Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        ctx.startActivity(i); true
    } catch (_: Throwable) { false }
}
