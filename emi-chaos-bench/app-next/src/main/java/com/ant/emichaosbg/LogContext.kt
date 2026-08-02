package com.ant.emichaosbg

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import org.json.JSONObject

/**
 * Device context captured AT THE MOMENT a finding is recorded.
 *
 * WHY. A log line saying "ultrasonic band shows sustained modulated energy" is a fact without a
 * situation. Reading it back a week later, the questions that actually decide whether it
 * mattered are the ones the bare line cannot answer: was the screen off? was the phone
 * charging, and plugged into what? was it on Wi-Fi or cellular? was the masker even running,
 * or is this the idle baseline? was the device hot enough for the sensors to be drifting?
 * Recording the answer alongside the finding is the difference between a log you can reason
 * from and a list of timestamps.
 *
 * It also makes correlation possible across entries — "every one of these happened while
 * charging on the same network" is a pattern; "these happened" is not.
 *
 * WHAT IS DELIBERATELY NOT IN HERE. No location, no SSID, no BSSID, no cell identity, no
 * IMEI/serial, no account. The vault is encrypted and local, but a counter-surveillance log is
 * exactly the file most worth stealing, and a precise location history is the single most
 * damaging thing it could contain. Network TYPE is recorded ("wifi"/"cellular"); which network
 * is not. Findings that genuinely need an identifier already carry it in their own message,
 * where it is a deliberate choice rather than blanket collection.
 *
 * Cheap by construction: no I/O, no blocking calls, everything from already-resident system
 * state, and every field individually guarded so a manufacturer quirk degrades one value to
 * null instead of costing the whole record.
 */
object LogContext {

    /** Process start, so an entry can be placed relative to when the app came up. */
    private val processStart = SystemClock.elapsedRealtime()

    fun capture(ctx: Context): JSONObject {
        val o = JSONObject()
        // How long this process has been alive when the finding landed. Distinguishes
        // "happened the instant we started looking" from "happened after six hours of quiet".
        runCatching { o.put("upMs", SystemClock.elapsedRealtime() - processStart) }
        runCatching { o.put("bootMs", SystemClock.elapsedRealtime()) }

        runCatching {
            val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
            bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)?.let {
                if (it in 0..100) o.put("battery", it)
            }
        }
        runCatching {
            @Suppress("DEPRECATION")
            val st = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            if (st != null) {
                val plug = st.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1)
                o.put("charging", plug > 0)
                o.put("plugged", when (plug) {
                    BatteryManager.BATTERY_PLUGGED_AC -> "ac"
                    BatteryManager.BATTERY_PLUGGED_USB -> "usb"
                    BatteryManager.BATTERY_PLUGGED_WIRELESS -> "wireless"
                    0 -> "none"
                    else -> "unknown"
                })
                // Battery temperature in tenths of a degree C. The thermal state the sensor
                // fusion was operating under — drift rises with heat, so this is the context
                // that says whether a sensor-derived finding deserves weight.
                val t = st.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE)
                if (t != Int.MIN_VALUE) o.put("battTempC", t / 10.0)
            }
        }

        runCatching {
            val pm = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager
            // Screen off is the interesting case: a finding while the phone was face-down and
            // idle is a different claim from one while it was being used.
            o.put("screenOn", pm?.isInteractive ?: true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                o.put("dozing", pm?.isDeviceIdleMode ?: false)
            o.put("powerSave", pm?.isPowerSaveMode ?: false)
        }

        runCatching {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val caps = cm?.getNetworkCapabilities(cm.activeNetwork)
            // TYPE only. Which network it was is deliberately not recorded — see the class note.
            o.put("net", when {
                caps == null -> "none"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "bluetooth"
                else -> "other"
            })
            if (caps != null) o.put("metered",
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
        }

        // Was the masker actually running? Decides whether a finding is a live observation or
        // an idle-baseline one, which changes what it means entirely.
        runCatching { o.put("masking", com.ant.emichaosbg.core.Sentinel.isMasking) }

        runCatching {
            val pi = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
            o.put("appVer", pi.versionName ?: "?")
        }
        runCatching {
            o.put("sdk", Build.VERSION.SDK_INT)
            o.put("device", (Build.MANUFACTURER + " " + Build.MODEL).take(48))
        }
        return o
    }

    /** Flat one-line summary for CSV columns and compact display. */
    fun summarise(c: JSONObject?): String {
        if (c == null) return ""
        val bits = ArrayList<String>()
        c.optInt("battery", -1).let { if (it >= 0) bits.add("batt $it%") }
        if (c.has("charging")) bits.add(if (c.optBoolean("charging")) "charging" else "on battery")
        if (c.has("screenOn")) bits.add(if (c.optBoolean("screenOn")) "screen on" else "screen off")
        c.optString("net", "").let { if (it.isNotBlank()) bits.add(it) }
        if (c.has("masking")) bits.add(if (c.optBoolean("masking")) "masking" else "idle")
        c.optDouble("battTempC", Double.NaN).let { if (!it.isNaN()) bits.add("${it}C") }
        return bits.joinToString(", ")
    }
}
