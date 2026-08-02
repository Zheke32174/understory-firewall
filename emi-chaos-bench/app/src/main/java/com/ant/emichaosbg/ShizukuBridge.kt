package com.ant.emichaosbg

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.webkit.JavascriptInterface
import android.webkit.WebView
import org.json.JSONObject
import rikka.shizuku.Shizuku

/**
 * `window.EMIShizuku` — optional, best-effort bridge to a user-installed Shizuku app.
 *
 * Shizuku (https://shizuku.rikka.app) lets a normal app request elevated (adb-shell or
 * root) privilege *only if the user has separately installed Shizuku and explicitly
 * grants it*. Nothing here works, or is even visible, unless the user has done that
 * themselves — the whole panel degrades to "unavailable" with zero side effects.
 *
 * What it's for: EFF's Rayhunter (https://github.com/EFForg/rayhunter) is the real,
 * maintained tool for actual IMSI-catcher detection via the modem's /dev/diag
 * interface — this bridge does not attempt to reimplement that. What it DOES provide
 * is a read-only diagnostic peek (see [ShizukuUserService.ALLOWLIST]) for users who
 * want more visibility than the unprivileged TelephonyManager heuristics in
 * [EmiBridge.getCellInfo] can offer, entirely optional and entirely read-only.
 */
class ShizukuBridge(private val ctx: Context, private val web: WebView) {

    private val main = Handler(Looper.getMainLooper())
    private var diagService: IShizukuDiagService? = null
    private var bound = false
    private val userServiceArgs by lazy {
        Shizuku.UserServiceArgs(ComponentName(ctx, ShizukuUserService::class.java))
            .daemon(false)
            .processNameSuffix("diag")
            .debuggable(false)
            .version(1)
    }

    private val permissionListener = Shizuku.OnRequestPermissionResultListener { _, grantResult ->
        postJs(
            "window.__emiShizukuPermission && window.__emiShizukuPermission(" +
                (grantResult == PackageManager.PERMISSION_GRANTED) + ")"
        )
    }

    init {
        try {
            Shizuku.addRequestPermissionResultListener(permissionListener)
        } catch (_: Throwable) { /* Shizuku not on the classpath at runtime — stay inert */ }
    }

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            diagService = IShizukuDiagService.Stub.asInterface(binder)
            bound = true
        }
        override fun onServiceDisconnected(name: ComponentName?) {
            diagService = null; bound = false
        }
    }

    @JavascriptInterface
    fun status(): String {
        val o = JSONObject()
        return try {
            val alive = Shizuku.pingBinder()
            o.put("available", alive)
            if (alive) {
                o.put("version", Shizuku.getVersion())
                o.put("granted", Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED)
                o.put("preV11", Shizuku.isPreV11())
            }
            o.toString()
        } catch (_: Throwable) {
            o.put("available", false); o.put("error", "shizuku_not_installed"); o.toString()
        }
    }

    @JavascriptInterface
    fun requestPermission() {
        try {
            if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                Shizuku.requestPermission(4210)
            }
        } catch (_: Throwable) { /* no-op without Shizuku */ }
    }

    @JavascriptInterface
    fun runDiagnostic(key: String) {
        main.post {
            try {
                if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                    postJs(resultJs(key, null, "permission not granted"))
                    return@post
                }
                if (!bound || diagService == null) {
                    Shizuku.bindUserService(userServiceArgs, conn)
                    // Give the remote process a moment to spin up, then retry once.
                    main.postDelayed({ runDiagnosticNow(key) }, 700)
                } else {
                    runDiagnosticNow(key)
                }
            } catch (e: Throwable) {
                postJs(resultJs(key, null, e.message ?: "shizuku error"))
            }
        }
    }

    private fun runDiagnosticNow(key: String) {
        try {
            val svc = diagService
            if (svc == null) { postJs(resultJs(key, null, "diag service not bound")); return }
            val out = svc.runDiagnostic(key)
            postJs(resultJs(key, out, null))
        } catch (e: Throwable) {
            postJs(resultJs(key, null, e.message ?: "diag call failed"))
        }
    }

    private fun resultJs(key: String, out: String?, err: String?): String {
        val o = JSONObject().put("key", key)
        if (out != null) o.put("out", out)
        if (err != null) o.put("error", err)
        return "window.__emiShizukuResult && window.__emiShizukuResult(${JSONObject.quote(o.toString())})"
    }

    private fun postJs(js: String) = main.post { web.evaluateJavascript(js, null) }

    fun shutdown() {
        try { if (bound) Shizuku.unbindUserService(userServiceArgs, conn, true) } catch (_: Throwable) {}
        try { Shizuku.removeRequestPermissionResultListener(permissionListener) } catch (_: Throwable) {}
    }
}
