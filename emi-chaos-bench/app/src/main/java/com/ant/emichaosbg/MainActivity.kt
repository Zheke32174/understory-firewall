package com.ant.emichaosbg

import android.Manifest
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.webkit.PermissionRequest
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat

/**
 * Thin WebView host for the EMI Chaos Bench masker.
 *
 * The whole app is the local asset [assets/index.html]; this shell only:
 *   - configures the WebView (JS, DOM storage, gesture-free media playback, geolocation),
 *   - grants the sensor/BLE/location runtime permissions the JS asks for, and
 *   - exposes [EmiBridge] as `window.EMIBridge` so the page can read gyroscope,
 *     magnetometer, BLE accessory RSSI, cell/network state and drive precise haptics.
 *
 * Nothing here transmits or radiates. The radios and sensors are read as INPUTS only.
 */
class MainActivity : ComponentActivity() {

    private lateinit var webView: WebView
    private lateinit var bridge: EmiBridge
    private lateinit var shizuku: ShizukuBridge

    private val permLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { /* JS re-queries on tick */ }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        requestRuntimePermissions()

        webView = WebView(this)
        bridge = EmiBridge(this, webView)
        shizuku = ShizukuBridge(this, webView)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            mediaPlaybackRequiresUserGesture = false
            setGeolocationEnabled(true)
            // Everything is bundled in the APK; no remote loads are ever needed.
            allowFileAccess = true
            allowContentAccess = false
            cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
        }

        // Only ever serve the bundled asset. Any http(s) navigation is refused.
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(v: WebView, req: WebResourceRequest): Boolean {
                val url = req.url.toString()
                return !url.startsWith("file:///android_asset/")
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            // Grant the Generic Sensor / getUserMedia(audio) permissions the page requests.
            // Mic capture (RESOURCE_AUDIO_CAPTURE) still requires the native RECORD_AUDIO
            // runtime permission underneath — requested above — or the browser-level grant
            // here is a no-op and getUserMedia rejects. Analysis stays fully in-process; VAD
            // never records to disk or leaves the device.
            override fun onPermissionRequest(request: PermissionRequest) {
                request.grant(request.resources)
            }
            override fun onGeolocationPermissionsShowPrompt(
                origin: String?, callback: android.webkit.GeolocationPermissions.Callback?
            ) {
                val ok = ContextCompat.checkSelfPermission(
                    this@MainActivity, Manifest.permission.ACCESS_FINE_LOCATION
                ) == PackageManager.PERMISSION_GRANTED
                callback?.invoke(origin, ok, false)
            }
        }

        webView.addJavascriptInterface(bridge, "EMIBridge")
        webView.addJavascriptInterface(shizuku, "EMIShizuku")
        webView.loadUrl("file:///android_asset/index.html")

        setContentView(webView)
        keepScreenFriendly()
    }

    private fun requestRuntimePermissions() {
        val wanted = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.READ_PHONE_STATE
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            wanted += Manifest.permission.BLUETOOTH_SCAN
            wanted += Manifest.permission.BLUETOOTH_CONNECT
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            wanted += Manifest.permission.POST_NOTIFICATIONS
        }
        val missing = wanted.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) permLauncher.launch(missing.toTypedArray())
    }

    private fun keepScreenFriendly() {
        window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LAYOUT_STABLE
    }

    override fun onDestroy() {
        bridge.shutdown()
        shizuku.shutdown()
        webView.destroy()
        super.onDestroy()
    }
}
