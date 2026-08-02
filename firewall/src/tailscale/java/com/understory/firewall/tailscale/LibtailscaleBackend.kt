package com.understory.firewall.tailscale

import android.content.Context
import android.net.VpnService
import com.understory.security.Diagnostics
import libtailscale.Application
import libtailscale.IPNService
import libtailscale.Libtailscale
import libtailscale.VPNServiceBuilder

/**
 * The REAL Tailscale data plane, filling [TailscaleController.Backend].
 *
 * Compiled only when libtailscale.aar is supplied to the build, so when this class
 * exists the tailnet genuinely runs; when it does not, [TailscaleController] reports
 * NOT_LINKED and nothing pretends otherwise. That is the whole design of the seam.
 *
 * Direction of control, which is the thing to hold onto: **Go drives.** We call
 * [Libtailscale.start] once to get an [Application], then hand Go an [IPNService]
 * it can use to build a tun on demand. Go decides when the tunnel goes up.
 */
class LibtailscaleBackend(
    private val vpnService: VpnService,
) : TailscaleController.Backend {

    @Volatile private var app: Application? = null
    @Volatile private var state: TailscaleController.State = TailscaleController.State.STOPPED
    @Volatile private var detail: String = ""
    @Volatile private var ipnService: GodwallIpnService? = null

    override fun start(ctx: Context, cfg: TailscaleController.NodeConfig): Boolean {
        if (app != null) return true
        state = TailscaleController.State.STARTING
        return try {
            // tailscaled's own state lives under our private files dir; the Go side
            // owns the layout, we only supply the root.
            val dataDir = java.io.File(ctx.filesDir, "tailscale").apply { mkdirs() }.absolutePath
            val directFileRoot = java.io.File(ctx.filesDir, "tailscale-files")
                .apply { mkdirs() }.absolutePath

            val started = Libtailscale.start(
                dataDir,
                directFileRoot,
                /* useDirectFileMode = */ false,
                GodwallAppContext(ctx.applicationContext),
            )
            app = started

            val svc = GodwallIpnService(vpnService)
            ipnService = svc
            // Ask Go to bring the tunnel up; it calls back into svc.newBuilder().
            Libtailscale.requestVPN(svc)

            state = TailscaleController.State.RUNNING
            detail = "tailnet started (data dir: $dataDir)"
            Diagnostics.log(TAG, detail)
            true
        } catch (t: Throwable) {
            state = TailscaleController.State.ERROR
            detail = "${t.javaClass.simpleName}: ${t.message}"
            Diagnostics.error(TAG, "start failed — $detail")
            app = null
            false
        }
    }

    override fun stop(ctx: Context) {
        val svc = ipnService
        runCatching { if (svc != null) Libtailscale.serviceDisconnect(svc) }
            .onFailure { Diagnostics.error(TAG, "serviceDisconnect: ${it.message}") }
        ipnService = null
        app = null
        state = TailscaleController.State.STOPPED
        detail = ""
        Diagnostics.log(TAG, "tailnet stopped")
    }

    override fun status(ctx: Context): TailscaleController.Status =
        TailscaleController.Status(state = state, detail = detail)

    private companion object {
        const val TAG = "firewall.tailscale.Backend"
    }
}

/**
 * What Go holds to manipulate our VpnService. Every method is a small, literal
 * delegation — deliberately so, because Go is the one deciding policy here.
 */
internal class GodwallIpnService(
    private val service: VpnService,
) : IPNService {

    override fun id(): String = ID

    override fun newBuilder(): VPNServiceBuilder =
        GodwallVpnBuilder(service, service.Builder())

    /** Keep the tailnet's own sockets out of our tun, or they would route into themselves. */
    override fun protect(fd: Int): Boolean = service.protect(fd)

    override fun updateVpnStatus(up: Boolean) {
        Diagnostics.log(TAG, "tailnet vpn status: ${if (up) "up" else "down"}")
    }

    override fun disconnectVPN() {
        Diagnostics.log(TAG, "Go requested VPN disconnect")
    }

    override fun close() {
        Diagnostics.log(TAG, "Go closed the IPN service")
    }

    private companion object {
        const val TAG = "firewall.tailscale.IPNService"
        const val ID = "godwall"
    }
}
