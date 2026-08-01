package com.ant.emichaosbg

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.webkit.JavascriptInterface
import org.json.JSONArray
import androidx.core.content.ContextCompat
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
 *  │ Self-dump     │ this app, holding DUMP   │ The SAME read-only service dumps, in    │
 *  │ (adb-granted) │ granted over adb         │ process. PERSISTENT across reboot, no   │
 *  │               │                          │ helper app needed. No DPM powers.       │
 *  │ ADB           │ the human                │ Grants the tiers above.                 │
 *  └───────────────┴──────────────────────────┴─────────────────────────────────────────┘
 *
 * So "Dhizuku as a fallback for Shizuku" is only half true and the UI says so: Dhizuku
 * cannot serve the diagnostics at all. What CAN serve them without Shizuku is the
 * self-dump tier: android.permission.DUMP is declared signature|privileged|**development**,
 * and that development flag means `adb shell pm grant` works on it for an ordinary app.
 * Once granted it persists across reboot with no helper process — which makes it the
 * strongest *durable* diagnostics tier, not a last resort. What Dhizuku
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

    // ---- Dhizuku (real client API) ----------------------------------------------------
    // NOTE: this used to be reflection-only, which could never have worked. The class
    // com.rosan.dhizuku.api.Dhizuku lives in the CLIENT library that a consuming app bundles
    // — it is not exported by the Dhizuku app — so Class.forName() in our own process always
    // returned null and the tier reported "absent" no matter what the user had installed.
    private var dhizukuInited = false

    private fun dhizukuInstalled(): Boolean =
        try { ctx.packageManager.getPackageInfo("com.rosan.dhizuku", 0); true }
        catch (_: Exception) { false }

    private fun dhizukuInit(): Boolean {
        if (dhizukuInited) return true
        return try {
            // Always the Context overload: the no-arg one resolves its Context through a
            // hidden ActivityThread API subject to non-SDK restrictions.
            dhizukuInited = com.rosan.dhizuku.api.Dhizuku.init(ctx)
            dhizukuInited
        } catch (_: Throwable) { false }
    }

    private fun dhizukuPermission(): Boolean {
        if (!dhizukuInstalled()) return false
        if (!dhizukuInit()) return false
        return try { com.rosan.dhizuku.api.Dhizuku.isPermissionGranted() }
        catch (_: Throwable) { false }
    }

    /**
     * DevicePolicyManager acting with DHIZUKU's identity, since Dhizuku (not this app) is the
     * device owner. The admin ComponentName must therefore be Dhizuku's own, and the binder
     * has to be routed through Dhizuku's process — a plain local DevicePolicyManager would be
     * rejected because we are not the owner.
     */
    private fun dhizukuDpm(): Pair<DevicePolicyManager, ComponentName>? {
        if (!dhizukuPermission()) return null
        return try {
            val owner = com.rosan.dhizuku.api.Dhizuku.getOwnerComponent() ?: return null
            val smClass = Class.forName("android.os.ServiceManager")
            val raw = smClass.getMethod("getService", String::class.java)
                .invoke(null, Context.DEVICE_POLICY_SERVICE) as? android.os.IBinder ?: return null
            val wrapped = com.rosan.dhizuku.api.Dhizuku.binderWrapper(raw)
            val stub = Class.forName("android.app.admin.IDevicePolicyManager\$Stub")
            val iface = stub.getMethod("asInterface", android.os.IBinder::class.java)
                .invoke(null, wrapped)
            val ifaceCls = Class.forName("android.app.admin.IDevicePolicyManager")
            val ctor = DevicePolicyManager::class.java.getDeclaredConstructor(Context::class.java, ifaceCls)
            ctor.isAccessible = true
            val dpm = ctor.newInstance(ctx, iface) as DevicePolicyManager
            Pair(dpm, owner)
        } catch (_: Throwable) { null }
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

        // The self-dump tier. Listed BEFORE the manual-adb row because it is not a fallback
        // of last resort — for diagnostics it is the strongest *persistent* tier there is.
        val dumpOk = hasDumpPermission()
        tier("selfdump", "Self-dump (adb-granted DUMP)", true, dumpOk,
            "Read-only service dumps in this app's own process — persistent, survives reboot, needs no helper app running",
            "Cannot make the app force-stop-proof",
            "adb shell pm grant ${ctx.packageName} android.permission.DUMP")

        tier("adb", "ADB (manual)", true, false,
            "Grants the tiers above — it is how self-dump and device owner are enabled in the first place",
            "Nothing by itself at runtime",
            "adb shell, with the device connected or over wireless debugging.")

        val o = JSONObject()
        o.put("tiers", arr)
        o.put("sdkInt", Build.VERSION.SDK_INT)
        o.put("pkg", ctx.packageName)
        o.put("adminComponent", adminComponent.flattenToShortString())
        // The single most useful capability question, answered plainly.
        o.put("forceStopProtectionPossible", Build.VERSION.SDK_INT >= 30 && (doSelf || dhPerm))
        o.put("forceStopProtected", isUserControlDisabled())
        o.put("diagnosticsPossible", shizukuOk || dumpOk)
        o.put("selfDump", dumpOk)
        o.put("dumpGrantCmd", "adb shell pm grant ${ctx.packageName} android.permission.DUMP")
        return o.toString()
    }

    private fun isUserControlDisabled(): Boolean {
        if (Build.VERSION.SDK_INT < 30) return false
        return try {
            val via = dhizukuDpm()
            if (via != null) via.first.getUserControlDisabledPackages(via.second).contains(ctx.packageName)
            else dpm()?.getUserControlDisabledPackages(adminComponent)?.contains(ctx.packageName) == true
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
        // Prefer Dhizuku: it is the tier a normal user can actually get, and it does not
        // require turning THIS app into the device owner (a one-shot, account-hostile,
        // factory-reset-to-undo operation most people should not do for a masking app).
        val viaDhizuku = dhizukuDpm()
        if (viaDhizuku == null && !isDeviceOwner()) {
            return o.put("ok", false).put("reason",
                if (!dhizukuInstalled()) "Install Dhizuku and grant this app permission in it. (Making this app itself the device owner also works but is a far more invasive step — it needs a device with no accounts and a factory reset to undo.)"
                else if (!dhizukuPermission()) "Dhizuku is installed but hasn't granted this app permission yet — tap 'Request Dhizuku'."
                else "Dhizuku granted permission but its device-policy channel could not be reached."
            ).toString()
        }
        return try {
            val d: DevicePolicyManager
            val admin: ComponentName
            if (viaDhizuku != null) { d = viaDhizuku.first; admin = viaDhizuku.second; o.put("via", "dhizuku") }
            else { d = dpm() ?: return o.put("ok", false).put("reason", "DevicePolicyManager unavailable").toString()
                   admin = adminComponent; o.put("via", "device-owner") }
            val list = if (enable) listOf(ctx.packageName) else emptyList()
            d.setUserControlDisabledPackages(admin, list)
            runCatching { d.setUninstallBlocked(admin, ctx.packageName, enable) }
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
        if (!dhizukuInit()) return o.put("ok", false).put("reason", "Dhizuku is installed but its service isn't running — open Dhizuku once and make sure it is active as device owner.").toString()
        return try {
            if (com.rosan.dhizuku.api.Dhizuku.isPermissionGranted()) {
                return o.put("ok", true).put("reason", "Already granted.").toString()
            }
            com.rosan.dhizuku.api.Dhizuku.requestPermission(
                object : com.rosan.dhizuku.api.DhizukuRequestPermissionListener() {
                    override fun onRequestPermission(grantResult: Int) { /* polled by refresh */ }
                }
            )
            o.put("ok", true).put("reason", "Requested — confirm in the Dhizuku dialog (it auto-denies after ~15s).").toString()
        } catch (e: Throwable) {
            o.put("ok", false).put("reason", "Dhizuku request failed: ${e.message}").toString()
        }
    }

    /** The exact adb line for this build, so the user doesn't have to construct it. */
    @JavascriptInterface
    fun adbCommand(): String =
        "adb shell dpm set-device-owner ${ctx.packageName}/.EmiDeviceAdminReceiver"

    // ---- SELF-DUMP tier ---------------------------------------------------------------
    // The one genuinely persistent diagnostics tier, and the reason "ADB" is not merely an
    // instructions screen.
    //
    // android.permission.DUMP is declared signature|privileged|**development**. That third
    // flag is the whole point: `development` permissions can be granted to an ordinary
    // third-party app with `adb shell pm grant`. Once granted it STICKS — it survives reboot
    // and needs no helper process running, which Shizuku (started over adb) does not.
    //
    // With it held, the app can read the same service dumps the Shizuku allowlist reads,
    // but IN ITS OWN PROCESS: get the service binder from ServiceManager and call dump()
    // against a pipe. No shell, no third-party app in the trust path, nothing to keep alive.
    private fun hasDumpPermission(): Boolean =
        ContextCompat.checkSelfPermission(ctx, "android.permission.DUMP") == PackageManager.PERMISSION_GRANTED

    /** Read-only service dumps, in-process. Same fixed allowlist discipline as Shizuku's. */
    private val DUMP_ALLOWLIST = mapOf(
        "telephony_registry" to Pair("telephony.registry", arrayOf<String>()),
        "connectivity" to Pair("connectivity", arrayOf<String>()),
        "sms_service" to Pair("isms", arrayOf<String>()),
        "carrier_config" to Pair("carrier_config", arrayOf<String>())
    )

    @JavascriptInterface
    fun selfDump(key: String): String {
        if (!hasDumpPermission()) return "error: DUMP permission not granted. Run: adb shell pm grant ${ctx.packageName} android.permission.DUMP"
        val entry = DUMP_ALLOWLIST[key] ?: return "error: '$key' is not on the read-only allowlist"
        return try {
            val sm = Class.forName("android.os.ServiceManager")
            val binder = sm.getMethod("getService", String::class.java)
                .invoke(null, entry.first) as? android.os.IBinder
                ?: return "error: service '${entry.first}' not found"
            val pipe = android.os.ParcelFileDescriptor.createPipe()
            val read = pipe[0]; val write = pipe[1]
            val out = StringBuilder()
            val reader = Thread {
                try {
                    android.os.ParcelFileDescriptor.AutoCloseInputStream(read).use { ins ->
                        val buf = ByteArray(8192)
                        var n: Int
                        while (ins.read(buf).also { n = it } > 0) {
                            out.append(String(buf, 0, n))
                            if (out.length > 200_000) break
                        }
                    }
                } catch (_: Exception) {}
            }
            reader.start()
            try { binder.dump(write.fileDescriptor, entry.second) } finally {
                try { write.close() } catch (_: Exception) {}
            }
            reader.join(5000)
            val s = out.toString()
            if (s.length > 20_000) s.substring(0, 20_000) + "\n...(truncated)" else s
        } catch (e: Exception) {
            "error: ${e.message}"
        }
    }
}
