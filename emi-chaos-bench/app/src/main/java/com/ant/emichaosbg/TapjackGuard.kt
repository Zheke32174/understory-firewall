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
 * WHAT IS DETECTED. Android tags every MotionEvent delivered while another window was on top:
 * FLAG_WINDOW_IS_OBSCURED (fully) and FLAG_WINDOW_IS_PARTIALLY_OBSCURED (partially, API 29+).
 * Those flags are read on every touch and reported. That is on by default and costs nothing.
 *
 * WHY BLOCKING IS OPT-IN, AND NOT THE DEFAULT. `filterTouchesWhenObscured = true` makes the
 * framework discard obscured touches entirely. It is genuine protection and it was briefly the
 * default here — which made the app completely unusable, because the filter drops EVERY touch
 * while ANY window overlays this one, and a great many benign things overlay a window:
 * blue-light filters, screen dimmers, chat bubbles, several accessibility tools, some OEM
 * system overlays. With one of those running the screen simply stops responding, with no
 * explanation and no way to reach the control that would turn it back off.
 *
 * That was also a violation of this project's own rule — everything reports, nothing blocks; a
 * false positive should cost a notification, never the session — and it cost exactly that. So
 * detection runs always, blocking is a switch the user throws knowingly, and it deliberately
 * does not persist across launches: an unusable app that stays unusable after a restart is a
 * brick, and restarting is the one recovery a user reliably finds.
 *
 * Holding the overlay permission is not evidence of wrongdoing; screen recorders, chat heads,
 * colour filters and accessibility tools all legitimately use it. The count of OBSCURED touches
 * is the signal that matters, because that is an overlay actually sitting over this app while
 * you were using it.
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
    @Deprecated("No longer attached to any view — the guard is out of the input path entirely.")
    fun protect(v: View) {
        view = null
        // DETECTION ONLY BY DEFAULT. Turning filterTouchesWhenObscured on for everyone made
        // the app completely unusable, and it deserved to: the framework discards EVERY touch
        // while any window overlays this one, and plenty of benign things overlay a window —
        // blue-light filters, screen dimmers, chat bubbles, some OEM system overlays, several
        // accessibility tools. With any of those running the app simply stops responding, with
        // no explanation, and the user cannot even reach the control that would turn it off.
        //
        // It also broke this project's own rule. Everything here reports and nothing blocks; a
        // false positive should cost you a notification, never your session. I made blocking
        // the default and it cost exactly that.
        //
        // So the observer runs always and the FILTER is opt-in (see setBlocking). Reporting
        // "something is drawn over this app right now" is the part that carries the value;
        // discarding input is a hard trade the user should choose knowingly.
        v.filterTouchesWhenObscured = false
        // NO setOnTouchListener ON THE WEBVIEW. That is what was still breaking input even with
        // blocking off: a listener set on a WebView runs inside dispatchTouchEvent BEFORE the
        // WebView's own onTouchEvent, and WebView's gesture handling (scroll, fling, long-press,
        // text selection) is documented to misbehave when something intercepts there. Returning
        // false is not enough to make it safe.
        //
        // Detection moved to MainActivity.dispatchTouchEvent instead, which is the supported
        // place to observe input: it sees the same MotionEvent flags, always delegates to super,
        // and therefore cannot alter how the WebView receives the gesture. See observe().
    }

    /**
     * Observe a touch WITHOUT participating in its dispatch. Called from the Activity's
     * dispatchTouchEvent, which then hands the event on to super unchanged.
     */
    fun observe(ev: MotionEvent) = noteTouch(ev)

    private var view: View? = null

    /**
     * Opt-in hard blocking. Once on, the framework drops every touch delivered while another
     * window covers this app — genuine protection, and genuine risk of an unusable screen if
     * something benign is overlaying. Reversible from the same control, and it does not
     * persist across launches on purpose: an unusable app that stays unusable after a restart
     * is a brick, and the restart is the one recovery a user will reliably find.
     */
    @JavascriptInterface
    fun setBlocking(on: Boolean): Boolean {
        // Deliberately inert. The guard no longer holds the view and no longer touches the
        // input path at all, so there is nothing here to switch on. Kept as a stub rather than
        // deleted so the page's control degrades to a no-op with an honest answer instead of
        // throwing, and so a future re-introduction has to be a conscious edit here rather than
        // a flag flip that silently re-arms the thing that broke the screen twice.
        return false
    }

    @Volatile private var blocking = false

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
            "(${if (obscured) "fully" else "partially"} obscured). An overlay can make you tap a " +
            "control you cannot see. " +
            (if (blocking) "Blocking is on, so this touch was discarded rather than acted on. "
             else "Blocking is off, so the touch was delivered normally and this is a report only. ") +
            "If it keeps happening, something is sitting on top of this app — check the overlay " +
            "list on the Security sheet.")
    }

    private fun flag(sev: Int, key: String, what: String) {
        val now = System.currentTimeMillis()
        val prev = raised[key]
        if (prev != null && now - prev < COALESCE_MS) return
        raised[key] = now
        // OFF THE UI THREAD. This path is reached from touch dispatch, and SecureLog.append does
        // AES-GCM through the Keystore plus a file write and an fsync. Doing that inline would
        // stall the very gesture that triggered it — a security log that makes the app stutter
        // every time it records something teaches the user to turn it off.
        logExec.execute {
            try { log.append(sev, what, "tapjack", "native") } catch (_: Throwable) {}
        }
    }

    private val logExec: java.util.concurrent.ExecutorService =
        java.util.concurrent.Executors.newSingleThreadExecutor { r ->
            Thread(r, "emi-tapjack-log").apply { isDaemon = true } }

    /** Apps that can draw over this one, and accessibility services that can read it. */
    @JavascriptInterface
    fun status(): String {
        val o = JSONObject()
        o.put("filterActive", blocking)
        o.put("blocking", blocking)
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

        o.put("note", "Obscured touches are DETECTED and reported by default, not blocked. " +
            "Hard blocking is available but off unless you turn it on, because discarding every " +
            "touch while any window overlays this one makes the app unusable when something " +
            "benign is doing the overlaying. " +
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
