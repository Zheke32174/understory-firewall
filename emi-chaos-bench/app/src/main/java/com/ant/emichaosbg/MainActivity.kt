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
import android.webkit.WebResourceResponse
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
    private lateinit var tamperGuard: TamperGuard
    private lateinit var tapjack: TapjackGuard
    private var pageLoaded = false
    private var wasMicGranted = false

    // BUG FIX: this used to fire loadUrl() immediately after *requesting* permissions,
    // without waiting for the async result. If the WebView finished loading and the user
    // tapped "Mic" before the OS dialog resolved, getUserMedia() ran while RECORD_AUDIO was
    // still ungranted, WebView denied it, and — critically — Chromium's WebView caches that
    // per-origin denial for the rest of the page's lifetime. Granting the permission
    // afterward did nothing until the whole app was killed and relaunched. Fix: don't load
    // the page until the permission round-trip has actually completed, and if mic
    // permission changes state after that (e.g. granted later via system Settings while
    // backgrounded), reload the WebView on resume so it gets a clean shot at getUserMedia.
    private val permLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
            wasMicGranted = isGranted(Manifest.permission.RECORD_AUDIO)
            loadPageOnce()
        }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        webView = WebView(this)
        bridge = EmiBridge(this, webView)
        shizuku = ShizukuBridge(this, webView)
        tamperGuard = TamperGuard(this)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            mediaPlaybackRequiresUserGesture = false
            setGeolocationEnabled(true)
            // Everything is bundled in the APK; no remote loads are ever needed.
            allowFileAccess = true
            allowContentAccess = false
            cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
            // Stated rather than inherited. Both default to false on current API levels, but
            // they are the two settings that turn "a page that can be injected" into "a page
            // that can read every file this app can reach", so they are worth being explicit
            // and permanent about. The page gets its bundled assets through the native
            // reader (EmiBridge.readAssetText), which is why it does not need these.
            allowFileAccessFromFileURLs = false
            allowUniversalAccessFromFileURLs = false
        }

        // Only ever serve the bundled asset. Any http(s) navigation is refused.
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(v: WebView, req: WebResourceRequest): Boolean {
                val url = req.url.toString()
                return !url.startsWith("file:///android_asset/")
            }
            /**
             * shouldOverrideUrlLoading only sees NAVIGATIONS. Subresource loads — an <img>,
             * a stylesheet, a script tag injected by something that got into the page — never
             * reach it. This closes that: any resource request that is not a bundled asset is
             * answered with an empty 403 instead of being fetched.
             */
            override fun shouldInterceptRequest(v: WebView, req: WebResourceRequest): WebResourceResponse? {
                val url = req.url.toString()
                if (url.startsWith("file:///android_asset/")) return null   // allow, load normally
                return WebResourceResponse("text/plain", "utf-8", 403, "blocked",
                    emptyMap(), java.io.ByteArrayInputStream(ByteArray(0)))
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            // Grant the Generic Sensor / getUserMedia(audio+video) permissions the page
            // requests — but only the ones whose underlying native runtime permission we
            // actually hold. Granting a resource we don't natively hold doesn't work anyway
            // and used to leave the JS promise in an ambiguous state; explicitly denying
            // gives it an immediate, clean rejection so the UI can show useful feedback.
            override fun onPermissionRequest(request: PermissionRequest) {
                // A PermissionRequest must be resolved with exactly ONE of grant()/deny() —
                // calling both (which the previous version of this method did whenever a
                // request asked for more than it could get, e.g. a hypothetical combined
                // audio+video capture where only one was natively granted) is invalid API
                // usage. Partial-grant isn't meaningful for getUserMedia anyway — the page
                // asked for a specific set of resources and needs all of them — so this is
                // all-or-nothing: grant only if every requested resource is natively held,
                // otherwise deny outright for a clean, immediate JS-side rejection.
                val allGranted = request.resources.all { res ->
                    when (res) {
                        PermissionRequest.RESOURCE_AUDIO_CAPTURE -> isGranted(Manifest.permission.RECORD_AUDIO)
                        PermissionRequest.RESOURCE_VIDEO_CAPTURE -> isGranted(Manifest.permission.CAMERA)
                        else -> true
                    }
                }
                if (allGranted) request.grant(request.resources) else request.deny()
            }
            override fun onGeolocationPermissionsShowPrompt(
                origin: String?, callback: android.webkit.GeolocationPermissions.Callback?
            ) {
                callback?.invoke(origin, isGranted(Manifest.permission.ACCESS_FINE_LOCATION), false)
            }
        }

        // The evidence store. Registered as its own interface rather than folded into
        // EMIBridge so its surface stays visibly four methods wide — append, read, count,
        // verify — with no delete anywhere on it.
        webView.addJavascriptInterface(VaultBridge(this), "EMIVault")
        // Native file export. The page's own Blob + <a download> path is a silent no-op in a
        // WebView — no DownloadListener, no exception, no file — which is why every export
        // button appeared to do nothing.
        webView.addJavascriptInterface(Exporter(this), "EMIExport")
        // Privilege-escalation / code-injection detection for THIS process. Read-only view:
        // the page can ask for a scan and read the result, but has no way to disable a check
        // or suppress a finding.
        webView.addJavascriptInterface(
            EscalationBridge(MaskerService.ensureEscalationGuard(this)), "EMIEscalation")
        // Tapjacking defence. protect() sets filterTouchesWhenObscured, which makes the
        // FRAMEWORK discard any touch delivered while another window covers this one — the one
        // place this app blocks rather than reports, because a tap you did not knowingly aim
        // here should not land. It also counts them, so a defeated attack is visible instead
        // of silent.
        tapjack = TapjackGuard(this, SecureLog(this))
        tapjack.protect(webView)
        webView.addJavascriptInterface(tapjack, "EMITapjack")
        // Rootless cellular security posture + IMSI-catcher heuristics (PrivacyCell in full,
        // the parts of AIMSICD/SnoopSnitch that do not need baseband diag).
        webView.addJavascriptInterface(
            CellSecurityBridge(MaskerService.ensureCellSecurity(this)), "EMICell")
        // Read-only view onto the SERVICE-owned native scan/detection engine. The page can
        // start it, stop it and look at it; it has no way to raise, edit, suppress or delete a
        // finding, because detection and recording happen on the far side of this boundary.
        webView.addJavascriptInterface(
            ScanBridge(this, MaskerService.ensureScanEngine(this)), "EMIScan")
        webView.addJavascriptInterface(bridge, "EMIBridge")
        webView.addJavascriptInterface(shizuku, "EMIShizuku")
        webView.addJavascriptInterface(tamperGuard, "EMITamper")
        webView.addJavascriptInterface(PrivilegeBridge(this), "EMIPriv")
        setContentView(webView)
        keepScreenFriendly()

        wasMicGranted = isGranted(Manifest.permission.RECORD_AUDIO)
        requestRuntimePermissions() // loads the page itself once this round-trip completes
    }

    private fun isGranted(perm: String) =
        ContextCompat.checkSelfPermission(this, perm) == PackageManager.PERMISSION_GRANTED

    private fun loadPageOnce() {
        if (pageLoaded) return
        pageLoaded = true
        webView.loadUrl("file:///android_asset/index.html")
    }

    private fun requestRuntimePermissions() {
        val wanted = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.CAMERA
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            wanted += Manifest.permission.BLUETOOTH_SCAN
            wanted += Manifest.permission.BLUETOOTH_CONNECT
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            wanted += Manifest.permission.POST_NOTIFICATIONS
        }
        val missing = wanted.filter { !isGranted(it) }
        if (missing.isEmpty()) { loadPageOnce(); return }
        permLauncher.launch(missing.toTypedArray())
    }

    private fun keepScreenFriendly() {
        window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LAYOUT_STABLE
    }

    override fun onResume() {
        super.onResume()
        if (!pageLoaded) return
        // Catches the case where the user backgrounded the app, flipped mic permission on
        // in system Settings (after an earlier in-app denial), and returned. WebView's
        // per-origin denial cache from the earlier attempt would otherwise persist for the
        // rest of this page instance's life, so give it a fresh one.
        val nowGranted = isGranted(Manifest.permission.RECORD_AUDIO)
        if (nowGranted && !wasMicGranted) {
            wasMicGranted = true
            webView.reload()
        }
    }

    override fun onDestroy() {
        bridge.shutdown()
        shizuku.shutdown()
        webView.destroy()
        super.onDestroy()
    }
}
