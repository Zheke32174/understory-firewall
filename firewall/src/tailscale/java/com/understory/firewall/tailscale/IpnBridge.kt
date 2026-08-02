package com.understory.firewall.tailscale

import android.net.VpnService
import com.understory.security.Diagnostics
import libtailscale.ParcelFileDescriptor
import libtailscale.VPNServiceBuilder

/**
 * The Go→Java half of the Tailscale bridge.
 *
 * libtailscale is a gomobile-bound Go library: Go DRIVES the data plane and calls
 * back into these interfaces to get a tun. So Godwall's VpnService is what Go asks
 * to build and protect sockets — which is precisely why the tailnet can live inside
 * Godwall's own VPN slot instead of fighting it for the one Android allows.
 *
 * These are compiled ONLY when libtailscale.aar is supplied to the build (see
 * `hasLibtailscale` in build.gradle.kts), so the imports above are safe.
 */

private const val TAG = "firewall.tailscale.IpnBridge"

/**
 * Wraps [VpnService.Builder] for Go. Go calls these as it learns the tailnet's
 * addresses/routes/DNS, then [establish] to get the tun.
 *
 * [excludeRoute] is honoured via `VpnService.Builder.excludeRoute`, which needs
 * API 33 — our minSdk is 33, so it is always available and never silently dropped.
 */
internal class GodwallVpnBuilder(
    private val service: VpnService,
    private val builder: VpnService.Builder,
) : VPNServiceBuilder {

    override fun addAddress(addr: String, prefix: Int) {
        builder.addAddress(addr, prefix)
    }

    override fun addRoute(route: String, prefix: Int) {
        builder.addRoute(route, prefix)
    }

    override fun excludeRoute(route: String, prefix: Int) {
        builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName(route), prefix))
    }

    override fun addDNSServer(server: String) {
        builder.addDnsServer(server)
    }

    override fun addSearchDomain(domain: String) {
        builder.addSearchDomain(domain)
    }

    override fun setMTU(mtu: Int) {
        builder.setMtu(mtu)
    }

    override fun establish(): ParcelFileDescriptor? {
        val pfd = builder.establish() ?: run {
            // Null means the VPN slot was revoked or never granted. Say so; a silent
            // null here would surface to Go as an unexplained failure.
            Diagnostics.error(TAG, "establish() returned null — VPN permission revoked or slot taken")
            return null
        }
        Diagnostics.log(TAG, "tun established for tailnet")
        return GodwallPfd(pfd)
    }
}

/**
 * Hands the raw tun fd to Go.
 *
 * [detach] transfers OWNERSHIP: after this the Go side is responsible for closing
 * the descriptor, and the Java [android.os.ParcelFileDescriptor] must not close it.
 * `detachFd()` is exactly that contract, which is why it is used instead of `getFd()`.
 */
internal class GodwallPfd(
    private val pfd: android.os.ParcelFileDescriptor,
) : ParcelFileDescriptor {
    override fun detach(): Int = pfd.detachFd()
}
