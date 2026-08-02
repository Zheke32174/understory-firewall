package com.understory.godwall.mesh

import android.content.Context
import android.net.VpnService
import com.understory.security.Diagnostics
import libtailscale.Application
import libtailscale.Libtailscale
import org.json.JSONArray
import org.json.JSONObject

/**
 * The real tailnet data plane, fulfilling [Mesh.Backend].
 *
 * Compiled only when libtailscale.aar is supplied to the build. When this class
 * exists, Godwall genuinely runs a Tailscale node in its own process and its own
 * VPN slot; when it does not, [Mesh] reports ABSENT and nothing pretends.
 *
 * Direction of control: **Go drives.** [Libtailscale.start] boots tailscaled and
 * returns an [Application]; [Libtailscale.requestVPN] hands Go an IPNService it
 * calls back into when it wants a tun (see IpnBridge.kt). Everything Godwall asks
 * of the node — apply preferences, request a login, read state — goes the other
 * way through the node's local API, which is what [localApi] wraps.
 *
 * Preferences are applied with a real `PATCH /localapi/v0/prefs` carrying a
 * masked-prefs document: each field is sent alongside its `…Set` flag, which is
 * how the local API distinguishes "set this to false" from "leave it alone". A
 * refused patch is recorded in [error] and surfaces on the Mesh screen — it is
 * never swallowed into a config screen that claims to have saved something the
 * node never received.
 */
class LibtailscaleBackend(
    private val vpnService: VpnService,
) : Mesh.Backend {

    @Volatile private var app: Application? = null
    @Volatile private var ipnService: GodwallIpnService? = null
    @Volatile private var error: String = ""
    @Volatile private var prefsNote: String = ""

    override fun start(ctx: Context, cfg: Mesh.NodeConfig): Boolean {
        if (app != null) {
            applyPrefs(cfg)
            return true
        }
        return try {
            error = ""
            val dataDir = java.io.File(ctx.filesDir, "tailscale").apply { mkdirs() }.absolutePath
            val fileRoot = java.io.File(ctx.filesDir, "tailscale-files").apply { mkdirs() }.absolutePath

            // The device name Go reports is read back out of GodwallAppContext, so
            // the hostname setting is applied here before the node boots.
            GodwallAppContext.setDeviceName(cfg.hostname)

            app = Libtailscale.start(
                dataDir,
                fileRoot,
                /* useDirectFileMode = */ false,
                GodwallAppContext(ctx.applicationContext),
            )

            val svc = GodwallIpnService(vpnService)
            ipnService = svc
            Libtailscale.requestVPN(svc)

            applyPrefs(cfg)
            Diagnostics.log(TAG, "tailnet node started (state dir: $dataDir)")
            true
        } catch (t: Throwable) {
            error = "${t.javaClass.simpleName}: ${t.message}"
            Diagnostics.error(TAG, "node start failed — $error")
            app = null
            ipnService = null
            false
        }
    }

    override fun stop(ctx: Context) {
        val svc = ipnService
        runCatching { if (svc != null) Libtailscale.serviceDisconnect(svc) }
            .onFailure { Diagnostics.error(TAG, "serviceDisconnect: ${it.message}") }
        ipnService = null
        app = null
        prefsNote = ""
        Diagnostics.log(TAG, "tailnet node stopped")
    }

    override fun status(ctx: Context): Mesh.Status {
        if (app == null) {
            return Mesh.Status(
                state = if (error.isBlank()) Mesh.State.STOPPED else Mesh.State.ERROR,
                detail = error.ifBlank { "Node stopped." },
            )
        }
        val resp = localApi("GET", "/localapi/v0/status", null)
            ?: return Mesh.Status(Mesh.State.ERROR, detail = "The node's local API did not answer.")
        if (resp.first !in 200..299) {
            return Mesh.Status(Mesh.State.ERROR, detail = "Local API returned HTTP ${resp.first}.")
        }
        return parseStatus(String(resp.second, Charsets.UTF_8), prefsNote)
    }

    /** Ask the control plane for an interactive login. Blocking. Returns a result line. */
    override fun requestLogin(): String {
        val r = localApi("POST", "/localapi/v0/login-interactive", ByteArray(0))
            ?: return "The node is not running."
        return if (r.first in 200..299) {
            "Login requested. The URL appears here once the control plane issues it."
        } else {
            "Login refused (HTTP ${r.first})."
        }
    }

    override fun logout(): String {
        val r = localApi("POST", "/localapi/v0/logout", ByteArray(0))
            ?: return "The node is not running."
        return if (r.first in 200..299) "Logged out." else "Logout refused (HTTP ${r.first})."
    }

    /**
     * Push [cfg] to the node as masked prefs. Records the outcome in [prefsNote]
     * so the Mesh screen can show whether the node accepted them.
     */
    private fun applyPrefs(cfg: Mesh.NodeConfig) {
        val doc = JSONObject()
            .put("ControlURL", cfg.loginServer.ifBlank { MeshSettings.DEFAULT_LOGIN_SERVER })
            .put("ControlURLSet", true)
            .put("Hostname", cfg.hostname)
            .put("HostnameSet", true)
            .put("RouteAll", cfg.acceptRoutes)
            .put("RouteAllSet", true)
            .put("CorpDNS", cfg.acceptDns)
            .put("CorpDNSSet", true)
            .put("WantRunning", true)
            .put("WantRunningSet", true)
        if (cfg.exitNode.isNotBlank()) {
            doc.put("ExitNodeIP", cfg.exitNode).put("ExitNodeIPSet", true)
        }
        doc.put(
            "AdvertiseRoutes",
            if (cfg.advertiseExit) JSONArray(listOf("0.0.0.0/0", "::/0")) else JSONArray(),
        ).put("AdvertiseRoutesSet", true)

        val r = localApi("PATCH", "/localapi/v0/prefs", doc.toString().toByteArray(Charsets.UTF_8))
        prefsNote = when {
            r == null -> "Preferences were not sent — the node is not running."
            r.first in 200..299 -> ""
            else -> "The node refused these preferences (HTTP ${r.first})."
        }

        // An auth key is a non-interactive login, so it is delivered as start
        // options rather than as a preference. The HTTP result is reported
        // verbatim: if this node build does not accept it, the user sees the
        // status code instead of a screen claiming the key was applied.
        if (cfg.authKey.isNotBlank()) {
            val body = JSONObject().put("AuthKey", cfg.authKey).toString()
            val a = localApi("POST", "/localapi/v0/start", body.toByteArray(Charsets.UTF_8))
            val keyNote = when {
                a == null -> "The auth key was not sent — the node is not running."
                a.first in 200..299 -> ""
                else -> "The node refused the auth key (HTTP ${a.first})."
            }
            if (keyNote.isNotBlank()) {
                prefsNote = (prefsNote + " " + keyNote).trim()
            }
        }
        if (prefsNote.isNotBlank()) Diagnostics.error(TAG, prefsNote)
    }

    /** One local-API call. Returns HTTP status and body, or null when Go is not up. */
    private fun localApi(method: String, path: String, body: ByteArray?): Pair<Int, ByteArray>? {
        val a = app ?: return null
        return try {
            val stream = body?.let { ByteArrayGoStream(it) }
            val resp = a.callLocalAPI(LOCAL_API_TIMEOUT_MS, method, path, stream)
            val status = resp.statusCode().toInt()
            val bytes = runCatching { resp.bodyBytes() }.getOrNull() ?: ByteArray(0)
            status to bytes
        } catch (t: Throwable) {
            error = "${t.javaClass.simpleName}: ${t.message}"
            Diagnostics.error(TAG, "localApi $method $path failed — $error")
            null
        }
    }

    private companion object {
        const val TAG = "godwall.mesh.Backend"
        const val LOCAL_API_TIMEOUT_MS = 10_000L

        /**
         * Read the fields we actually render out of the node's status document.
         * An unexpected shape degrades to RUNNING with the raw backend state
         * rather than throwing away a working node.
         */
        fun parseStatus(json: String, prefsNote: String): Mesh.Status = try {
            val o = JSONObject(json)
            val backendState = o.optString("BackendState", "")
            val authUrl = o.optString("AuthURL", "")
            val self = o.optJSONObject("Self")
            val ips = buildList {
                val arr = self?.optJSONArray("TailscaleIPs")
                if (arr != null) for (i in 0 until arr.length()) add(arr.optString(i))
            }.filter { it.isNotBlank() }
            val name = self?.optString("HostName", "").orEmpty()

            val state = when {
                backendState == "Running" -> Mesh.State.RUNNING
                backendState == "NeedsLogin" || authUrl.isNotBlank() -> Mesh.State.NEEDS_LOGIN
                backendState == "Starting" -> Mesh.State.STARTING
                backendState == "Stopped" || backendState == "NoState" -> Mesh.State.STOPPED
                else -> Mesh.State.RUNNING
            }
            val base = when (state) {
                Mesh.State.RUNNING ->
                    "Node running" + if (name.isBlank()) "." else " as $name."
                Mesh.State.NEEDS_LOGIN -> "The node needs a login to join a tailnet."
                Mesh.State.STARTING -> "Node starting."
                else -> "Backend state: ${backendState.ifBlank { "unknown" }}."
            }
            Mesh.Status(
                state = state,
                authUrl = authUrl,
                tailnetIps = ips,
                detail = if (prefsNote.isBlank()) base else "$base $prefsNote",
            )
        } catch (t: Throwable) {
            Mesh.Status(Mesh.State.ERROR, detail = "Could not read node status: ${t.javaClass.simpleName}")
        }
    }
}

/**
 * Feeds a byte array to Go one shot at a time. Go reads until [read] returns an
 * empty array, which is this binding's end-of-stream signal.
 */
internal class ByteArrayGoStream(private val payload: ByteArray) : libtailscale.InputStream {
    private var done = false

    override fun read(): ByteArray {
        if (done) return ByteArray(0)
        done = true
        return payload
    }

    override fun close() {
        done = true
    }
}
