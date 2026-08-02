package com.ant.emichaosbg

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityWindowInfo
import org.json.JSONArray
import org.json.JSONObject

/**
 * TAPJACK / OVERLAY DETECTION — and the reason this app now appears in the Accessibility list.
 *
 * WHY IT EXISTS AT ALL, GIVEN I ARGUED AGAINST IT. An accessibility service grants the exact
 * capability this app spends its screens warning about: the ability to observe what is on the
 * screen. Adding one to a counter-surveillance tool is a real cost, and it was declined once on
 * those grounds. It was asked for again, so it is built — but built as the narrowest thing that
 * answers the actual need, rather than the broad thing the API would allow.
 *
 * WHAT THE ACTUAL NEED WAS. Tapjacking protection. An app that draws an invisible window over
 * yours can harvest the taps you believe you are giving this one. Two earlier attempts at this
 * went through the INPUT path — filterTouchesWhenObscured, then a touch listener on the WebView
 * — and both broke the screen, because discarding obscured touches discards ALL touches while
 * any overlay is present, including a notification shade or a chathead. That approach is
 * abandoned permanently: this app REPORTS overlays and never blocks a touch. A false positive
 * must cost a notification, never your session.
 *
 * Detecting an overlay from inside the app is not reliably possible any other way. The window
 * list belongs to the window manager, and the only public route to it is here.
 *
 * WHAT IT DELIBERATELY NEVER DOES. It reads window METADATA ONLY — type, layer, bounds, and
 * whether the window belongs to this app. It never calls getRootInActiveWindow(), never walks a
 * node tree, never reads text, and never touches a field, a password box or a message. The
 * declaration in res/xml/overlay_watch.xml asks for the minimum event set that makes window
 * enumeration work, and nothing about content.
 *
 * That distinction is the whole design: the service can tell you "something is drawing on top of
 * you, occupying this rectangle, at this layer", and it structurally cannot tell anyone what you
 * typed. It is also entirely optional — off unless a human enables it in Settings, and the app
 * functions without it, minus this one detector.
 */
class OverlayWatch : AccessibilityService() {

    companion object {
        /** Live state for the UI, so a screen can say whether this detector is actually running. */
        @Volatile var connected = false
            private set
        @Volatile private var lastReport: String = "{}"
        @Volatile private var overlaysNow = 0
        fun status(): String = JSONObject()
            .put("enabled", connected)
            .put("overlays", overlaysNow)
            .put("detail", runCatching { JSONObject(lastReport) }.getOrDefault(JSONObject()))
            .put("note",
                "Reports overlay windows drawn on top of this app. Metadata only — window type, " +
                "layer and bounds. It never reads screen content and never blocks a touch.")
            .toString()

        // Re-alerting on every window change would be a stream, not a signal: a chathead sitting
        // on screen would fire continuously. Only a CHANGE in the overlay picture is worth a
        // record.
        @Volatile private var lastSignature = ""
    }

    private val vault by lazy { SecureLog(applicationContext) }

    override fun onServiceConnected() {
        connected = true
        runCatching {
            vault.append(1, "Overlay detection enabled — this app can now see when another app " +
                "draws on top of it. Window metadata only; no screen content is read.",
                "overlay", "overlaywatch")
        }
    }

    override fun onDestroy() {
        connected = false
        super.onDestroy()
    }

    override fun onInterrupt() { /* nothing to interrupt: no content is ever being read */ }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // Everything below reads AccessibilityWindowInfo only. No getRootInActiveWindow(), no
        // node traversal, no text. Enforced by there being no such call in this file.
        val wins: List<AccessibilityWindowInfo> = runCatching { windows }.getOrNull() ?: return
        val mine = applicationContext.packageName

        val found = JSONArray()
        var count = 0
        var topLayer = -1
        var appLayer = -1

        for (w in wins) {
            val type = runCatching { w.type }.getOrDefault(-1)
            val layer = runCatching { w.layer }.getOrDefault(-1)
            if (type == AccessibilityWindowInfo.TYPE_APPLICATION) {
                // Cannot ask a window for its package without content access, so identify our own
                // window by it being the active/focused application window.
                if (runCatching { w.isActive }.getOrDefault(false)) appLayer = layer
            }
            val isOverlay = type == AccessibilityWindowInfo.TYPE_SYSTEM ||
                (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O &&
                    type == AccessibilityWindowInfo.TYPE_SPLIT_SCREEN_DIVIDER) ||
                type == AccessibilityWindowInfo.TYPE_ACCESSIBILITY_OVERLAY
            if (!isOverlay) continue

            val r = android.graphics.Rect()
            runCatching { w.getBoundsInScreen(r) }
            found.put(JSONObject()
                .put("type", typeName(type))
                .put("layer", layer)
                .put("w", r.width()).put("h", r.height())
                .put("x", r.left).put("y", r.top))
            count++
            if (layer > topLayer) topLayer = layer
        }

        overlaysNow = count
        lastReport = JSONObject()
            .put("count", count)
            .put("windows", found)
            .put("aboveThisApp", appLayer >= 0 && topLayer > appLayer)
            .toString()

        // Only record when the picture CHANGES, and only when something is genuinely above us.
        val sig = "$count/$topLayer/$appLayer"
        if (sig == lastSignature) return
        lastSignature = sig
        if (count > 0 && appLayer >= 0 && topLayer > appLayer) {
            runCatching {
                vault.append(2,
                    "Overlay drawn ABOVE this app: $count window(s), topmost at layer $topLayer " +
                    "versus this app at $appLayer. An overlay in this position can cover what you " +
                    "are looking at and collect taps you believe you are giving this app. This is " +
                    "reported, not blocked — a legitimate chathead, a screen recorder or an " +
                    "accessibility tool looks the same from here, and discarding your touches " +
                    "would break the app for all of them. Identify what is on top before acting.",
                    "tapjack", "overlaywatch")
            }
        }
    }

    private fun typeName(t: Int) = when (t) {
        AccessibilityWindowInfo.TYPE_APPLICATION -> "application"
        AccessibilityWindowInfo.TYPE_INPUT_METHOD -> "input method"
        AccessibilityWindowInfo.TYPE_SYSTEM -> "system"
        AccessibilityWindowInfo.TYPE_ACCESSIBILITY_OVERLAY -> "accessibility overlay"
        AccessibilityWindowInfo.TYPE_SPLIT_SCREEN_DIVIDER -> "split-screen divider"
        else -> "type $t"
    }
}
