package com.ant.emichaosbg

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
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
import android.location.GnssStatus
import android.location.LocationManager
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
import android.app.ActivityManager
import android.app.usage.UsageStatsManager
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import android.telephony.CellIdentityGsm
import android.telephony.CellIdentityLte
import android.telephony.CellIdentityNr
import android.telephony.CellIdentityWcdma
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoWcdma
import android.telephony.SignalStrength
import android.telephony.TelephonyManager
import android.view.accessibility.AccessibilityManager
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
            reg(Sensor.TYPE_PRESSURE)
            reg(Sensor.TYPE_LIGHT)
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
            Sensor.TYPE_PRESSURE -> {
                // deviation from standard sea-level pressure (1013.25 hPa), ±50hPa -> ±1;
                // JS tracks its own rolling baseline for anomaly purposes (raw altitude/
                // weather changes are normal — a sudden step is the interesting part)
                snap["baro"] = n(e.values[0] - 1013.25f, 50f)
            }
            Sensor.TYPE_LIGHT -> {
                val lux = e.values[0].toDouble().coerceAtLeast(0.0)
                snap["light"] = max(-1.0, min(1.0, (Math.log10(lux + 1.0) / 5.0) * 2 - 1)) // log scale, ~1..100000 lux
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
    private var lastBatteryPct = -1.0
    private var lastBatteryReadAt = 0L

    /** Battery temperature + drain rate (always available, no permission) + best-effort CPU zone temps. */
    @JavascriptInterface
    fun getThermals(): String {
        val o = JSONObject()
        try {
            val batIntent = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            val tenthsC = batIntent?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1) ?: -1
            if (tenthsC >= 0) o.put("batteryC", tenthsC / 10.0)
            val level = batIntent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
            val scale = batIntent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
            val plugged = (batIntent?.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) ?: 0) != 0
            if (level >= 0 && scale > 0) {
                val pct = level * 100.0 / scale
                o.put("batteryPct", pct)
                o.put("charging", plugged)
                val now = System.currentTimeMillis()
                if (!plugged && lastBatteryPct >= 0 && now > lastBatteryReadAt) {
                    val minutes = (now - lastBatteryReadAt) / 60000.0
                    if (minutes > 0.05) {
                        val ratePerHour = (lastBatteryPct - pct) / minutes * 60.0
                        o.put("drainPctPerHour", ratePerHour)
                    }
                }
                lastBatteryPct = pct; lastBatteryReadAt = now
            }
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

    // ---- Cell guard: serving-cell identity + channel/band telemetry (receive-only) -------
    // Everything here comes from TelephonyManager.allCellInfo — the same passive read the
    // IMSI-catcher heuristic already uses, just not thrown away after counting. The extra
    // fields (cell id, PCI, TAC, ARFCN/EARFCN/NRARFCN, band list, operator MCC/MNC) are what
    // let the JS side notice *which* channel the phone was moved to and whether the carrier
    // stayed the same — the signature of a forced re-selection onto an attacker's cell.
    //
    // This method does not, and will not, CHANGE any of it. Selecting a band or network mode
    // programmatically needs MODIFY_PHONE_STATE (privileged) or a WRITE_SECURE_SETTINGS poke
    // at the modem's preferred-network-mode; both are outside this app, and a masker silently
    // reconfiguring the radio is exactly the failure mode you don't want when someone needs to
    // dial emergency services. `openNetworkModeSettings()` below hands that decision to the
    // user, with the readout here as context. See ETHICS.md.
    @JavascriptInterface
    fun getCellGuardStatus(): String {
        val o = JSONObject()
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            o.put("error", "no_location_permission"); return o.toString()
        }
        try {
            val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            @Suppress("DEPRECATION") val cells = tm.allCellInfo ?: emptyList()
            val neighbors = JSONArray()
            var serving: JSONObject? = null
            for (c in cells) {
                val e = JSONObject()
                val gen: Int
                when (c) {
                    is CellInfoNr -> {
                        gen = 5
                        (c.cellIdentity as? CellIdentityNr)?.let { id ->
                            e.put("nci", id.nci); e.put("pci", id.pci); e.put("tac", id.tac)
                            e.put("arfcn", id.nrarfcn)
                            e.put("mcc", id.mccString ?: ""); e.put("mnc", id.mncString ?: "")
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                e.put("bands", JSONArray(id.bands.toList()))
                            }
                        }
                    }
                    is CellInfoLte -> {
                        gen = 4
                        val id = c.cellIdentity
                        e.put("ci", id.ci); e.put("pci", id.pci); e.put("tac", id.tac)
                        e.put("arfcn", id.earfcn)
                        e.put("mcc", id.mccString ?: ""); e.put("mnc", id.mncString ?: "")
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            e.put("bands", JSONArray(id.bands.toList()))
                        }
                    }
                    is CellInfoWcdma -> {
                        gen = 3
                        val id = c.cellIdentity
                        e.put("ci", id.cid); e.put("pci", id.psc); e.put("tac", id.lac)
                        e.put("arfcn", id.uarfcn)
                        e.put("mcc", id.mccString ?: ""); e.put("mnc", id.mncString ?: "")
                    }
                    is CellInfoGsm -> {
                        gen = 2
                        val id = c.cellIdentity
                        e.put("ci", id.cid); e.put("pci", id.bsic); e.put("tac", id.lac)
                        e.put("arfcn", id.arfcn)
                        e.put("mcc", id.mccString ?: ""); e.put("mnc", id.mncString ?: "")
                    }
                    else -> gen = 0
                }
                e.put("gen", gen)
                e.put("dbm", try { c.cellSignalStrength.dbm } catch (_: Exception) { 0 })
                if (c.isRegistered && serving == null) serving = e else neighbors.put(e)
            }
            if (serving != null) o.put("serving", serving)
            o.put("neighbors", neighbors)
            o.put("operator", tm.networkOperatorName ?: "")
            o.put("operatorNumeric", tm.networkOperator ?: "")
            o.put("simOperatorNumeric", tm.simOperator ?: "")
            // Whether the modem is currently parked somewhere emergency-only ("limited service"):
            // a real signature of a cell that accepted the phone but won't carry normal traffic.
            o.put("emergencyOnly", try {
                @Suppress("DEPRECATION") (tm.networkOperator.isNullOrEmpty() && tm.simState == TelephonyManager.SIM_STATE_READY)
            } catch (_: Exception) { false })
            o.put("dataState", try { @Suppress("DEPRECATION") tm.dataState } catch (_: Exception) { -1 })
        } catch (_: SecurityException) {
            o.put("error", "security_exception")
        } catch (_: Exception) {
            o.put("error", "unavailable")
        }
        return o.toString()
    }

    /** Opens the OS's own network-mode / mobile-network settings so the USER can change
     *  band/network preference themselves. The app never writes it. */
    @JavascriptInterface
    fun openNetworkModeSettings(): Boolean {
        return try {
            val i = Intent(Settings.ACTION_NETWORK_OPERATOR_SETTINGS)
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(i); true
        } catch (_: Exception) {
            try {
                val i2 = Intent(Settings.ACTION_WIRELESS_SETTINGS)
                i2.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                ctx.startActivity(i2); true
            } catch (_: Exception) { false }
        }
    }

    // ---- Background resilience / self-protection state (read-only introspection) ---------
    // Reports how well-protected this process currently is against being silently killed or
    // throttled: foreground service, battery-optimisation exemption, app-standby bucket,
    // notification permission, and build-level flags. Reporting only — the one action offered
    // (`requestBatteryExemption`) is the standard user-consent system dialog.
    @JavascriptInterface
    fun getResilienceStatus(): String {
        val o = JSONObject()
        try {
            val pm = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager
            o.put("batteryExempt", if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && pm != null)
                pm.isIgnoringBatteryOptimizations(ctx.packageName) else true)

            val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            o.put("bgRestricted", if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && am != null)
                am.isBackgroundRestricted else false)

            val usm = ctx.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            val bucket = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && usm != null)
                try { usm.appStandbyBucket } catch (_: Exception) { -1 } else -1
            o.put("standbyBucket", bucket)
            o.put("standbyBucketName", when (bucket) {
                10 -> "active"; 20 -> "working_set"; 30 -> "frequent"
                40 -> "rare"; 45 -> "restricted"; else -> "unknown"
            })

            o.put("foregroundService", MaskerService.isRunning)
            o.put("notificationsAllowed",
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                    ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
                else true)

            val ai = ctx.applicationInfo
            o.put("debuggable", (ai.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
            o.put("allowBackup", (ai.flags and android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP) != 0)
            o.put("sdkInt", Build.VERSION.SDK_INT)
        } catch (_: Exception) {
            o.put("error", "unavailable")
        }
        return o.toString()
    }

    /** Fires the standard system dialog asking the user to exempt this app from battery
     *  optimisation. User-consented; the app cannot grant this to itself. */
    @JavascriptInterface
    fun requestBatteryExemption(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
        return try {
            val i = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
            i.data = Uri.parse("package:${ctx.packageName}")
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(i); true
        } catch (_: Exception) {
            try {
                val i2 = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                i2.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                ctx.startActivity(i2); true
            } catch (_: Exception) { false }
        }
    }

    /** Opens this app's own system settings page (permissions / special app access), the
     *  screen where an appops-level change would have to be made deliberately by a human. */
    @JavascriptInterface
    fun openAppSettings(): Boolean {
        return try {
            val i = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
            i.data = Uri.parse("package:${ctx.packageName}")
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(i); true
        } catch (_: Exception) { false }
    }

    // ---- GNSS satellite status (real satellite telemetry, receive-only) -----------------
    // Android's GnssStatus API exposes what the Web Geolocation API doesn't: how many
    // satellites the receiver actually sees, which constellations, and per-satellite signal
    // strength (CN0). This is genuine satellite-signal data — nothing is transmitted; GNSS
    // receivers are receive-only by nature (a phone doesn't talk back to GPS satellites).

    private var gnssCb: GnssStatus.Callback? = null
    @Volatile private var lastGnss: GnssStatus? = null

    @JavascriptInterface
    fun startGnss() {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) return
        if (gnssCb != null) return
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as? LocationManager ?: return
        val cb = object : GnssStatus.Callback() {
            override fun onSatelliteStatusChanged(status: GnssStatus) { lastGnss = status }
        }
        gnssCb = cb
        main.post {
            try { lm.registerGnssStatusCallback(cb, main) } catch (_: SecurityException) {} catch (_: Exception) {}
        }
    }

    @JavascriptInterface
    fun stopGnss() {
        val cb = gnssCb ?: return
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as? LocationManager ?: return
        try { lm.unregisterGnssStatusCallback(cb) } catch (_: Exception) {}
        gnssCb = null; lastGnss = null
    }

    private fun constellationName(c: Int): String = when (c) {
        GnssStatus.CONSTELLATION_GPS -> "GPS"
        GnssStatus.CONSTELLATION_GLONASS -> "GLONASS"
        GnssStatus.CONSTELLATION_GALILEO -> "Galileo"
        GnssStatus.CONSTELLATION_BEIDOU -> "BeiDou"
        GnssStatus.CONSTELLATION_QZSS -> "QZSS"
        GnssStatus.CONSTELLATION_SBAS -> "SBAS"
        GnssStatus.CONSTELLATION_IRNSS -> "IRNSS"
        else -> "other"
    }

    @JavascriptInterface
    fun getGnssStatus(): String {
        val o = JSONObject()
        val st = lastGnss ?: return o.also { it.put("count", 0) }.toString()
        val n = st.satelliteCount
        var used = 0; var cn0Sum = 0.0
        val byConst = HashMap<String, Int>()
        for (i in 0 until n) {
            if (st.usedInFix(i)) used++
            cn0Sum += st.getCn0DbHz(i)
            val name = constellationName(st.getConstellationType(i))
            byConst[name] = (byConst[name] ?: 0) + 1
        }
        o.put("count", n)
        o.put("used", used)
        o.put("avgCn0", if (n > 0) cn0Sum / n else 0.0)
        val cJson = JSONObject(); byConst.forEach { (k, v) -> cJson.put(k, v) }
        o.put("constellations", cJson)
        return o.toString()
    }

    /**
     * On-device compromise indicators — a DIFFERENT class of signal than RF: not "is
     * something nearby listening" but "is something already on this phone doing so."
     * Both reads are plain, unprivileged PackageManager/AccessibilityManager queries — no
     * special permission, no ability to see WHAT other apps do, just counts. A high count
     * isn't proof of anything (legitimate accessibility tools and camera/mic apps exist) —
     * same "heuristic, look closer" framing as everywhere else in this bridge.
     */

    /** Ground truth for the mic diagnostics panel: whether Android itself currently holds
     *  RECORD_AUDIO granted, independent of whatever getUserMedia() just did. If this says
     *  true but getUserMedia() still failed, that's WebView's own per-origin denial cache
     *  (see MainActivity.kt's onResume reload fix) or a WebView-level constraint issue, not
     *  a real Android permission problem — this reading is what tells the two apart. */
    @JavascriptInterface
    fun getMicPermissionState(): String {
        val o = JSONObject()
        o.put("recordAudioGranted", ContextCompat.checkSelfPermission(ctx, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED)
        o.put("sdkInt", Build.VERSION.SDK_INT)
        o.put("device", "${Build.MANUFACTURER} ${Build.MODEL}")
        try {
            val wv = android.webkit.WebView.getCurrentWebViewPackage()
            if (wv != null) o.put("webviewProvider", "${wv.packageName} ${wv.versionName}")
        } catch (_: Exception) {}
        return o.toString()
    }

    @JavascriptInterface
    fun getCompromiseIndicators(): String {
        val o = JSONObject()
        try {
            val am = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            val enabled = am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            o.put("accessibilityServices", enabled?.size ?: 0)
            if (enabled != null && enabled.isNotEmpty()) {
                val names = JSONArray()
                enabled.forEach { names.put(it.resolveInfo?.serviceInfo?.packageName ?: "?") }
                o.put("accessibilityServiceNames", names)
            }
        } catch (_: Exception) { o.put("accessibilityServices", -1) }
        try {
            val pm = ctx.packageManager
            fun countHolding(vararg perms: String): Int =
                pm.getPackagesHoldingPermissions(perms, 0).size
            o.put("appsWithMicAccess", countHolding(Manifest.permission.RECORD_AUDIO))
            o.put("appsWithCameraAccess", countHolding(Manifest.permission.CAMERA))
            o.put("appsWithLocationAccess", countHolding(Manifest.permission.ACCESS_FINE_LOCATION))
        } catch (_: Exception) {}
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

    /** Already-paired devices — a plain read of the adapter's own bond list, not a scan.
     *  No new permission beyond BLUETOOTH_CONNECT (already requested for scanning). */
    @JavascriptInterface
    fun getBondedDevices(): String {
        val arr = JSONArray()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED
        ) return arr.toString()
        try {
            val bm = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager ?: return arr.toString()
            val bonded = bm.adapter?.bondedDevices ?: emptySet()
            for (d in bonded) {
                val o = JSONObject()
                o.put("address", d.address)
                o.put("name", d.name ?: "device")
                o.put("bondState", "bonded")
                arr.put(o)
            }
        } catch (_: SecurityException) {
        } catch (_: Exception) {}
        return arr.toString()
    }

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

    // ---- LAN device inventory ("who's on my network") --------------------
    // Reads /proc/net/arp — the kernel's own ARP table, populated passively by normal
    // network traffic on the currently-connected LAN. This is NOT ARP spoofing/poisoning:
    // nothing is sent, nothing is injected, no other device's traffic is touched or
    // redirected. It only reads what the OS already knows about who has recently
    // communicated on this network — the same category of read as `ip neigh` or `arp -a`.

    @JavascriptInterface
    fun getLanDevices(): String {
        val arr = JSONArray()
        try {
            val lines = java.io.File("/proc/net/arp").readLines()
            for (line in lines.drop(1)) {
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size < 6) continue
                val ip = parts[0]; val flags = parts[2]; val mac = parts[3]; val dev = parts[5]
                if (flags != "0x2") continue // 0x2 = ATF_COMPLETE — a real, resolved entry
                if (mac == "00:00:00:00:00:00") continue
                val o = JSONObject()
                o.put("ip", ip); o.put("mac", mac); o.put("iface", dev)
                arr.put(o)
            }
        } catch (_: Exception) { /* some OEM builds restrict /proc/net/arp — degrade to empty */ }
        return arr.toString()
    }

    // ---- BLE GATT inspection (device-type fingerprinting) ----------------
    // Briefly connects to a device the user picked from the scan list, reads its GATT
    // service/characteristic UUIDs, then disconnects. This is a normal BLE GATT client
    // connection (the same thing any companion app does to talk to a device) — it reads
    // the device's advertised capability tree, it does not read/write application data,
    // pair, bond, or send any command beyond service discovery.

    private var activeGatt: BluetoothGatt? = null
    private var gattTarget: String? = null

    @JavascriptInterface
    fun bleInspectGatt(address: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED
        ) { postJs(gattResultJs(address, null, "no_permission")); return }
        main.post {
            try {
                activeGatt?.let { try { it.close() } catch (_: Exception) {} }
                val bm = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
                val device = bm?.adapter?.getRemoteDevice(address)
                if (device == null) { postJs(gattResultJs(address, null, "device_not_found")); return@post }
                gattTarget = address
                activeGatt = device.connectGatt(ctx, false, gattCallback)
            } catch (e: SecurityException) {
                postJs(gattResultJs(address, null, "security_exception"))
            } catch (e: Exception) {
                postJs(gattResultJs(address, null, e.message ?: "connect_failed"))
            }
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                try { gatt.discoverServices() } catch (_: SecurityException) {}
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                try { gatt.close() } catch (_: Exception) {}
                if (activeGatt === gatt) activeGatt = null
            }
        }
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val arr = JSONArray()
            try {
                for (svc in gatt.services) {
                    val so = JSONObject(); so.put("uuid", svc.uuid.toString())
                    val chars = JSONArray(); for (c in svc.characteristics) chars.put(c.uuid.toString())
                    so.put("characteristics", chars); arr.put(so)
                }
            } catch (_: SecurityException) {}
            postJs(gattResultJs(gattTarget ?: "", arr, null))
            try { gatt.disconnect() } catch (_: Exception) {}
        }
    }

    private fun gattResultJs(address: String, services: JSONArray?, error: String?): String {
        val o = JSONObject().put("address", address)
        if (services != null) o.put("services", services)
        if (error != null) o.put("error", error)
        return "window.__emiGattResult && window.__emiGattResult(${JSONObject.quote(o.toString())})"
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
        stopSensors(); bleStop(); setForeground(false); stopGnss()
        try { activeGatt?.close() } catch (_: Exception) {}
    }
}
