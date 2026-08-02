package com.understory.godwall.mesh

import android.net.IpPrefix
import android.net.VpnService
import com.understory.godwall.core.GodwallVpnService
import com.understory.security.Diagnostics
import libtailscale.IPNService
import libtailscale.ParcelFileDescriptor
import libtailscale.VPNServiceBuilder
import java.net.InetAddress

/**
 * The Go→Java half of the bridge: what the Go data plane holds in order to get a
 * tun out of Godwall's VpnService.
 *
 * This is why the node lives inside Godwall's own VPN slot rather than competing
 * for it — Go does not open a tunnel, it asks US to, and we are already the app
 * holding the slot.
 */
internal class GodwallIpnService(
    private val service: VpnService,
) : IPNService {

    override fun id(): String = "godwall"

    override fun newBuilder(): VPNServiceBuilder = GodwallVpnBuilder(service, service.Builder())

    /** Keep the node's own sockets out of our tun, or they would route into themselves. */
    override fun protect(fd: Int): Boolean = service.protect(fd)

    override fun updateVpnStatus(up: Boolean) {
        Diagnostics.log(TAG, "tailnet tunnel ${if (up) "up" else "down"}")
        (service as? GodwallVpnService)?.onMeshTunnelStatus(up)
    }

    override fun disconnectVPN() {
        Diagnostics.log(TAG, "Go requested VPN disconnect")
        (service as? GodwallVpnService)?.onMeshTunnelStatus(false)
    }

    override fun close() {
        Diagnostics.log(TAG, "Go closed the IPN service")
    }

    private companion object {
        const val TAG = "godwall.mesh.IPNService"
    }
}

/**
 * Wraps [VpnService.Builder] for Go, which calls these as it learns the tailnet's
 * addresses, routes and DNS, then [establish] to get the descriptor.
 *
 * This is the ONE place a tun is minted while the mesh engine runs — the DNS
 * filter engine does not run concurrently and does not call establish() behind
 * this one's back. That was the concrete defect in the previous build: two data
 * planes each minting their own tun on the same service, the second silently
 * replacing the first.
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
        builder.excludeRoute(IpPrefix(InetAddress.getByName(route), prefix))
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
        builder.setSession(SESSION)
        val pfd = builder.establish()
        if (pfd == null) {
            Diagnostics.error(TAG, "establish() returned null — VPN consent was not granted or was revoked")
            return null
        }
        (service as? GodwallVpnService)?.onMeshTunEstablished()
        Diagnostics.log(TAG, "tun established for the tailnet")
        return GodwallPfd(pfd)
    }

    private companion object {
        const val TAG = "godwall.mesh.Builder"
        const val SESSION = "Godwall mesh"
    }
}

/**
 * Hands the raw tun fd to Go.
 *
 * `detachFd()` transfers OWNERSHIP: after this the Go side closes the
 * descriptor and the Java [android.os.ParcelFileDescriptor] must not. That is
 * exactly the contract Go expects, which is why it is not `getFd()`.
 */
internal class GodwallPfd(
    private val pfd: android.os.ParcelFileDescriptor,
) : ParcelFileDescriptor {
    override fun detach(): Int = pfd.detachFd()
}
