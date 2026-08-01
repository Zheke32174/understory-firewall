package com.ant.emichaosbg

import android.Manifest
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.Build
import android.os.HardwarePropertiesManager
import android.os.Handler
import android.os.Looper
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoWcdma
import android.telephony.SignalStrength
import android.telephony.TelephonyManager
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.max
import kotlin.math.min

/**
 * `window.EMIBridge` — the native input surface for the WebView masker.
 *
 * All methods are INPUT/OUTPUT-LOCAL only:
 *   - sensors (gyro / magnetometer / accelerometer) are read and normalised to -1..1,
 *   - BLE is *scanned* to enumerate nearby accessory beacons and forward tracker-fingerprint
 *     bytes (manufacturer data / service UUIDs) for JS-side heuristics — never advertised or jammed,
 *   - Wi-Fi scan results are read (cached/throttled) for rogue-AP heuristics — never actively probed beyond a normal scan request,
 *   - telephony/connectivity signal and cell generation/neighbor-count are read for entropy and IMSI-catcher heuristics,
 *   - battery/CPU temperature are read for the thermal-anomaly channel,
 *   - the vibrator drives haptics,
 *   - a media-playback foreground service keeps the audio alive when backgrounded.
 *
 * The app has no RF transmit path of any kind. See also [ShizukuBridge] for the separate,
 * fully optional privileged-diagnostics channel.
 */
class EmiBridge(private val ctx: Context, private val web: WebView) : SensorEventListener {

    private val main = Handler(Looper.getMainLooper())
    private val sensorManager = ctx.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    private val vibrator: Vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        (ctx.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager).defaultVibrator
    } else {
        @Suppress("DEPRECATION") ctx.getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
    }

    // Latest normalised sensor snapshot, polled by JS via getSensors().
    private val snap = HashMap<String, Double>()
    private var sensing = false
    private var scanner: BluetoothLeScanner? = null

    // ---- sensors --------------------------------------------------------

    @JavascriptInterface
    fun startSensors() {
        if (sensing) return
        sensing = true
        main.post {
            reg(Sensor.TYPE_GYROSCOPE)
            reg(Sensor.TYPE_ACCELEROMETER)
            reg(Sensor.TYPE_LINEAR_ACCELERATION)
            reg(Sensor.TYPE_MAGNETIC_FIELD)
            reg(Sensor.TYPE_ROTATION_VECTOR)
        }
    }

    @JavascriptInterface
    fun stopSensors() {
        sensing = false
        main.post { sensorManager.unregisterListener(this) }
    }

    private fun reg(type: Int) {
        sensorManager.getDefaultSensor(type)?.let {
            sensorManager.registerListener(this, it, SensorManager.SENSOR_DELAY_GAME)
        }
    }

    private fun n(v: Float, scale: Float) = max(-1.0, min(1.0, (v / scale).toDouble()))

    override fun onSensorChanged(e: SensorEvent) {
        when (e.sensor.type) {
            Sensor.TYPE_GYROSCOPE -> {
                snap["gx"] = n(e.values[0], 8f); snap["gy"] = n(e.values[1], 8f); snap["gz"] = n(e.values[2], 8f)
            }
            Sensor.TYPE_ACCELEROMETER -> {
                snap["ax"] = n(e.values[0], 9.8f); snap["ay"] = n(e.values[1], 9.8f); snap["az"] = n(e.values[2], 9.8f)
            }
            Sensor.TYPE_LINEAR_ACCELERATION -> {
                val m = Math.sqrt((e.values[0] * e.values[0] + e.values[1] * e.values[1] + e.values[2] * e.values[2]).toDouble())
                snap["shake"] = max(-1.0, min(1.0, m / 12.0))
            }
            Sensor.TYPE_MAGNETIC_FIELD -> {
                val m = Math.sqrt((e.values[0] * e.values[0] + e.values[1] * e.values[1] + e.values[2] * e.values[2]).toDouble())
                snap["magS"] = max(-1.0, min(1.0, m / 60.0 * 2 - 1))
            }
            Sensor.TYPE_ROTATION_VECTOR -> {
                val R = FloatArray(9); val o = FloatArray(3)
                SensorManager.getRotationMatrixFromVector(R, e.values)
                SensorManager.getOrientation(R, o)
                snap["mag"] = (o[0] / Math.PI) // -1..1 heading
                snap["ox"] = (o[0] / Math.PI); snap["oy"] = (o[1] / (Math.PI / 2)); snap["oz"] = (o[2] / (Math.PI / 2))
            }
        }
    }

    override fun onAccuracyChanged(s: Sensor?, a: Int) {}

    @JavascriptInterface
    fun getSensors(): String {
        // fold in a cheap network/cell entropy read each poll
        readNetwork()
        return JSONObject(snap as Map<*, *>).toString()
    }

    private fun readNetwork() {
        try {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val caps = cm.getNetworkCapabilities(cm.activeNetwork)
            if (caps != null) {
                val down = caps.linkDownstreamBandwidthKbps / 1000.0
                snap["net"] = max(-1.0, min(1.0, down / 20.0 * 2 - 1))
                val cell = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                if (cell && ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
                    val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
                    @Suppress("DEPRECATION")
                    val lvl = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) tm.signalStrength?.level ?: 0 else 0
                    snap["rtt"] = (lvl / 4.0) * 2 - 1
                }
            }
        } catch (_: SecurityException) {
        } catch (_: Exception) {
        }
    }

    // ---- thermal + cell heuristics (read-only entropy / anomaly inputs) -

    private var lastCellGen = 5 // start optimistic; only ever flags a real observed drop

    /** Battery temperature (always available, no permission) + best-effort CPU zone temps. */
    @JavascriptInterface
    fun getThermals(): String {
        val o = JSONObject()
        try {
            val batIntent = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            val tenthsC = batIntent?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1) ?: -1
            if (tenthsC >= 0) o.put("batteryC", tenthsC / 10.0)
        } catch (_: Exception) {}
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val hpm = ctx.getSystemService(Context.HARDWARE_PROPERTIES_SERVICE) as? HardwarePropertiesManager
                val temps = hpm?.getDeviceTemperatures(
                    HardwarePropertiesManager.DEVICE_TEMPERATURE_CPU,
                    HardwarePropertiesManager.TEMPERATURE_CURRENT
                )
                if (temps != null && temps.isNotEmpty()) {
                    val arr = JSONArray(); temps.forEach { arr.put(it) }
                    o.put("cpuC", arr)
                }
            }
        } catch (_: Exception) { /* most OEMs restrict this to system apps — degrade silently */ }
        return o.toString()
    }

    /** Unprivileged cell heuristics: generation, neighbor count, and a downgrade flag. */
    @JavascriptInterface
    fun getCellInfo(): String {
        val o = JSONObject()
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            o.put("error", "no_location_permission"); return o.toString()
        }
        try {
            val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            @Suppress("DEPRECATION") val cells = tm.allCellInfo ?: emptyList()
            var servingGen = 0; var neighborCount = 0; var registeredCount = 0
            for (c in cells) {
                val gen = when (c) {
                    is CellInfoNr -> 5; is CellInfoLte -> 4; is CellInfoWcdma -> 3; is CellInfoGsm -> 2
                    else -> 0
                }
                if (c.isRegistered) { registeredCount++; if (gen > servingGen) servingGen = gen } else neighborCount++
            }
            o.put("generation", servingGen)
            o.put("neighborCount", neighborCount)
            o.put("registeredCount", registeredCount)
            o.put("networkType", tm.networkType)
            // Heuristic, not proof: a same-session drop from 3G+ down to 2G is the one
            // pattern worth surfacing on its own. Sustained 2G in a 2G-only area is normal
            // and will not keep re-flagging since lastCellGen only remembers 3G+ history.
            val downgraded = servingGen in 1..2 && lastCellGen >= 3
            o.put("downgrade", downgraded)
            o.put("isolated", registeredCount > 0 && neighborCount == 0)
            if (servingGen >= 3) lastCellGen = servingGen
        } catch (_: SecurityException) {
            o.put("error", "security_exception")
        } catch (_: Exception) {
            o.put("error", "unavailable")
        }
        return o.toString()
    }

    /** Cached Wi-Fi scan results — read-only, no active-scan trigger spam. */
    @JavascriptInterface
    fun wifiScan(): String {
        val arr = JSONArray()
        try {
            val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return arr.toString()
            if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED)
                return arr.toString()
            try { wm.startScan() } catch (_: Exception) { /* throttled — cached results below still useful */ }
            @Suppress("DEPRECATION")
            for (r in wm.scanResults) {
                val o = JSONObject()
                o.put("ssid", r.SSID ?: ""); o.put("bssid", r.BSSID ?: "")
                o.put("level", r.level); o.put("freq", r.frequency)
                o.put("caps", r.capabilities ?: "")
                arr.put(o)
            }
        } catch (_: SecurityException) {
        } catch (_: Exception) {}
        return arr.toString()
    }

    // ---- BLE scan (read-only enumeration, with tracker-fingerprint data) -

    @JavascriptInterface
    fun bleScan() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED
        ) return
        val bm = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager ?: return
        scanner = bm.adapter?.bluetoothLeScanner ?: return
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        try { scanner?.startScan(null, settings, scanCb) } catch (_: SecurityException) {}
    }

    @JavascriptInterface
    fun bleStop() {
        try { scanner?.stopScan(scanCb) } catch (_: Exception) {}
    }

    private fun bytesToHex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private val scanCb = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val o = JSONObject()
            try {
                o.put("id", result.device.address)
                o.put("address", result.device.address)
                o.put("name", result.scanRecord?.deviceName ?: "device")
                o.put("rssi", result.rssi)
                // Fingerprint data for JS-side tracker heuristics (AirTag/SmartTag/Tile/etc).
                // We just forward raw manufacturer-id -> hex-bytes; matching lives in JS so new
                // tracker signatures can be added without a native rebuild.
                val mfg = result.scanRecord?.manufacturerSpecificData
                if (mfg != null && mfg.size() > 0) {
                    val m = JSONObject()
                    for (i in 0 until mfg.size()) {
                        val id = mfg.keyAt(i); val data = mfg.valueAt(i)
                        if (data != null) m.put(id.toString(), bytesToHex(data))
                    }
                    o.put("mfg", m)
                }
                val uuids = result.scanRecord?.serviceUuids
                if (uuids != null && uuids.isNotEmpty()) {
                    val u = JSONArray(); uuids.forEach { u.put(it.toString()) }
                    o.put("svcUuids", u)
                }
                o.put("connectable", result.isConnectable)
            } catch (_: SecurityException) {}
            postJs("window.__emiBleReport(${JSONArray().put(o)})")
        }
    }

    // ---- haptics --------------------------------------------------------

    @JavascriptInterface
    fun vibrate(ms: Int) {
        val d = ms.toLong().coerceIn(1, 500)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            vibrator.vibrate(VibrationEffect.createOneShot(d, VibrationEffect.DEFAULT_AMPLITUDE))
        else @Suppress("DEPRECATION") vibrator.vibrate(d)
    }

    @JavascriptInterface
    fun vibratePattern(json: String) {
        try {
            val arr = JSONArray(json)
            val pat = LongArray(arr.length()) { arr.getLong(it) }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                vibrator.vibrate(VibrationEffect.createWaveform(pat, -1))
            else @Suppress("DEPRECATION") vibrator.vibrate(pat, -1)
        } catch (_: Exception) {}
    }

    // ---- background foreground-service control --------------------------

    @JavascriptInterface
    fun setForeground(on: Boolean) {
        val i = Intent(ctx, MaskerService::class.java)
        if (on) ContextCompat.startForegroundService(ctx, i) else ctx.stopService(i)
    }

    private fun postJs(js: String) = main.post { web.evaluateJavascript(js, null) }

    fun shutdown() {
        stopSensors(); bleStop(); setForeground(false)
    }
}
