package com.ant.emichaosbg

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.webkit.JavascriptInterface
import org.json.JSONArray
import org.json.JSONObject

/**
 * `window.EMIPriv` — the privileged-access fallback chain.
 *
 * The important thing about these tiers is that **they are not interchangeable**, and
 * pretending otherwise would produce a UI that lies to the user:
 *
 *  ┌───────────────┬──────────────────────────┬─────────────────────────────────────────┐
 *  │ Tier          │ Runs as                  │ What it can actually do here            │
 *  ├───────────────┼──────────────────────────┼─────────────────────────────────────────┤
 *  │ Shizuku       │ adb shell UID (2000)     │ The read-only `dumpsys` diagnostics     │
 *  │               │ or root                  │ allowlist. THIS TIER ONLY.              │
 *  │ Dhizuku       │ Dhizuku's own app UID,   │ DevicePolicyManager delegation only.    │
 *  │               │ which IS device owner    │ CANNOT run the dumpsys allowlist —      │
 *  │               │                          │ its process API spawns inside a normal  │
 *  │               │                          │ app process, so shell commands come     │
 *  │               │                          │ back no more privileged than ours.      │
 *  │ Device Owner  │ this app, as DO          │ Same DPM powers, directly, no third-    │
 *  │ (self)        │                          │ party app in the trust path.            │
 *  │ ADB           │ the human               │ Instructions. No runtime capability.     │
 *  └───────────────┴──────────────────────────┴─────────────────────────────────────────┘
 *
 * So "Dhizuku as a fallback for Shizuku" is only half true and the UI says so: if Shizuku
 * goes away, the *diagnostics* go away with it — nothing else can serve them. What Dhizuku
 * and device-owner provide instead is the **resilience** tier, which Shizuku genuinely
 * cannot: `setUserControlDisabledPackages` (API 30+) is the one supported mechanism on
 * stock Android that makes an app resistant to being silently force-stopped.
 *
 * Dhizuku is reached by reflection rather than a compile-time dependency. That is a
 * deliberate call: the Dhizuku-API artifact pins bytecode/compileSdk floors (2.6.0 needs
 * compileSdk 37; this app targets 34), and reflection means a device without Dhizuku
 * installed costs us nothing and degrades to "not available" instead of a missing-class
 * crash at startup.
 */
class PrivilegeBridge(private val ctx: Context) {

    private val adminComponent = ComponentName(ctx, EmiDeviceAdminReceiver::class.java)
    private fun dpm() = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager

    // ---- Device owner / admin (self) ------------------------------------------------
    private fun isDeviceOwner(): Boolean =
        try { dpm()?.isDeviceOwnerApp(ctx.packageName) == true } catch (_: Exception) { false }

    private fun isAdminActive(): Boolean =
        try { dpm()?.isAdminActive(adminComponent) == true } catch (_: Exception) { false }

    // ---- Dhizuku (reflection; no compile-time dependency) ----------------------------
    private fun dhizukuClass(): Class<*>? =
        try { Class.forName("com.rosan.dhizuku.api.Dhizuku") } catch (_: Throwable) { null }

    private fun dhizukuInstalled(): Boolean =
        try {
            ctx.packageManager.getPackageInfo("com.rosan.dhizuku", 0); true
        } catch (_: Exception) { false }

    private fun dhizukuPermission(): Boolean {
        val c = dhizukuClass() ?: return false
        return try {
            // init(Context) first — the no-arg overload resolves its Context through a
            // hidden ActivityThread API that is subject to non-SDK restrictions.
            runCatching { c.getMethod("init", Context::class.java).invoke(null, ctx) }
            c.getMethod("isPermissionGranted").invoke(null) as? Boolean ?: false
        } catch (_: Throwable) { false }
    }

    /** Which tiers exist right now, and what each is actually good for. */
    @JavascriptInterface
    fun getTiers(): String {
        val arr = JSONArray()

        fun tier(id: String, name: String, available: Boolean, active: Boolean, can: String, cannot: String, how: String) {
            arr.put(JSONObject().apply {
                put("id", id); put("name", name)
                put("available", available); put("active", active)
                put("can", can); put("cannot", cannot); put("how", how)
            })
        }

        val shizukuOk = try {
            ctx.packageManager.getPackageInfo("moe.shizuku.privileged.api", 0); true
        } catch (_: Exception) { false }

        tier("shizuku", "Shizuku", shizukuOk, shizukuOk,
            "Read-only dumpsys diagnostics (telephony, connectivity, SMS stack, carrier config)",
            "Cannot make the app force-stop-proof",
            "Install Shizuku, start it via wireless debugging or root, then grant this app permission in Shizuku.")

        val dhInstalled = dhizukuInstalled()
        val dhPerm = if (dhInstalled) dhizukuPermission() else false
        tier("dhizuku", "Dhizuku", dhInstalled, dhPerm,
            "Device-policy delegation: force-stop protection, uninstall block",
            "Cannot run the dumpsys diagnostics — its process API runs inside a normal app UID, so shell output is no more privileged than ours",
            "Install Dhizuku, make it device owner over adb, then grant this app permission in Dhizuku.")

        val doSelf = isDeviceOwner()
        tier("deviceowner", "Device owner (self)", true, doSelf,
            "Force-stop protection (API 30+), uninstall block — no third-party app in the trust path",
            "Cannot run dumpsys diagnostics",
            "On a device with no accounts added: adb shell dpm set-device-owner com.ant.emichaosbg/.EmiDeviceAdminReceiver")

        tier("admin", "Device admin (self)", true, isAdminActive(),
            "Disables the Settings uninstall/force-stop buttons for this app",
            "UI-level only — adb can still stop the app",
            "Settings → Security → Device admin apps → enable EMI Chaos Bench.")

        tier("adb", "ADB (manual)", true, false,
            "Whatever you run yourself",
            "Nothing at runtime — this tier is instructions, not a capability",
            "adb shell, with the device connected or over wireless debugging.")

        val o = JSONObject()
        o.put("tiers", arr)
        o.put("sdkInt", Build.VERSION.SDK_INT)
        o.put("pkg", ctx.packageName)
        o.put("adminComponent", adminComponent.flattenToShortString())
        // The single most useful capability question, answered plainly.
        o.put("forceStopProtectionPossible", Build.VERSION.SDK_INT >= 30 && (doSelf || dhPerm))
        o.put("forceStopProtected", isUserControlDisabled())
        o.put("diagnosticsPossible", shizukuOk)
        return o.toString()
    }

    private fun isUserControlDisabled(): Boolean {
        if (Build.VERSION.SDK_INT < 30) return false
        return try {
            dpm()?.getUserControlDisabledPackages(adminComponent)?.contains(ctx.packageName) == true
        } catch (_: Exception) { false }
    }

    /**
     * The reinforcement itself: ask the device-policy layer to stop letting this package be
     * force-stopped. Only possible as device owner; returns a JSON explanation either way
     * rather than a bare boolean, because "it didn't work" has several very different causes
     * and the user needs to know which one they hit.
     */
    @JavascriptInterface
    fun enableForceStopProtection(enable: Boolean): String {
        val o = JSONObject()
        if (Build.VERSION.SDK_INT < 30) {
            return o.put("ok", false).put("reason", "Needs Android 11 (API 30) or newer — setUserControlDisabledPackages doesn't exist below that.").toString()
        }
        if (!isDeviceOwner()) {
            return o.put("ok", false).put("reason", "This app is not device owner. Either provision it over adb, or install Dhizuku (which is device owner) and grant this app permission there.").toString()
        }
        return try {
            val d = dpm() ?: return o.put("ok", false).put("reason", "DevicePolicyManager unavailable").toString()
            val list = if (enable) listOf(ctx.packageName) else emptyList()
            d.setUserControlDisabledPackages(adminComponent, list)
            runCatching { d.setUninstallBlocked(adminComponent, ctx.packageName, enable) }
            o.put("ok", true).put("protected", enable)
                .put("reason", if (enable)
                    "Force-stop and uninstall are now blocked for this package. Undoing it takes a deliberate privileged action, not a background tap."
                else "Protection released.").toString()
        } catch (e: SecurityException) {
            o.put("ok", false).put("reason", "Refused by the policy layer: ${e.message}").toString()
        } catch (e: Exception) {
            o.put("ok", false).put("reason", "Failed: ${e.message}").toString()
        }
    }

    /** Opens the system device-admin settings so the user can activate admin themselves. */
    @JavascriptInterface
    fun requestDeviceAdmin(): Boolean = try {
        val i = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
        i.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent)
        i.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
            ctx.getString(R.string.admin_request_explanation))
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        ctx.startActivity(i); true
    } catch (_: Exception) { false }

    /** Asks Dhizuku for permission, if it's installed. No-op otherwise. */
    @JavascriptInterface
    fun requestDhizuku(): String {
        val o = JSONObject()
        if (!dhizukuInstalled()) return o.put("ok", false).put("reason", "Dhizuku is not installed.").toString()
        val c = dhizukuClass()
            ?: return o.put("ok", false).put("reason", "Dhizuku is installed but its API classes aren't reachable from this build.").toString()
        return try {
            runCatching { c.getMethod("init", Context::class.java).invoke(null, ctx) }
            if (c.getMethod("isPermissionGranted").invoke(null) as? Boolean == true) {
                return o.put("ok", true).put("reason", "Already granted.").toString()
            }
            // requestPermission takes a listener interface; invoke reflectively with a proxy.
            val listenerCls = Class.forName("com.rosan.dhizuku.api.DhizukuRequestPermissionListener")
            val proxy = java.lang.reflect.Proxy.newProxyInstance(
                listenerCls.classLoader, arrayOf(listenerCls)
            ) { _, _, _ -> null }
            c.getMethod("requestPermission", listenerCls).invoke(null, proxy)
            o.put("ok", true).put("reason", "Requested — confirm in the Dhizuku dialog (it auto-denies after ~15s).").toString()
        } catch (e: Throwable) {
            o.put("ok", false).put("reason", "Dhizuku request failed: ${e.message}").toString()
        }
    }

    /** The exact adb line for this build, so the user doesn't have to construct it. */
    @JavascriptInterface
    fun adbCommand(): String =
        "adb shell dpm set-device-owner ${ctx.packageName}/.EmiDeviceAdminReceiver"
}
