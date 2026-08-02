package com.understory.godwall.lan

import android.content.Context

/**
 * Persistent settings for LAN defence — the passive DHCP/ARP watches and the own-listener
 * deception layer.
 *
 * ## Why baselines are keyed by gateway address
 *
 * Both the rogue-DHCP watch and the ARP watch answer "did this change from what I trusted on
 * THIS network?", which needs a stable per-network key. The obvious keys are the Wi-Fi SSID and
 * BSSID — but since Android 10 reading either requires `ACCESS_FINE_LOCATION`, and LAN defence
 * asking for the location permission to notice a rogue DHCP server would be a worse trade than
 * the feature is worth. The gateway address ([android.net.DhcpInfo.gateway]) is readable with no
 * permission and is stable for the life of a lease, so it is the network key here. Its limit is
 * honest and stated in the UI: two different LANs that both use `192.168.1.1` share a baseline,
 * and an attacker who changes the gateway as well as the DHCP server moves to a fresh key. It
 * catches the common case — same LAN, a second DHCP server answering — and never claims more.
 *
 * ## Why deception defaults OFF while the watches default ON
 *
 * The DHCP and ARP watches only *read* state the platform already exposes; leaving them on costs
 * nothing and is the safe default (charter rule C: ship working defaults). The deception layer
 * *opens listening sockets*, which is an attack-surface decision the user is entitled to make
 * deliberately — a security app must not quietly start binding ports. So it ships off, with the
 * ports and profiles pre-filled so turning it on is one tap and never a configuration chore.
 */
object LanSettings {

    private const val PREFS = "godwall_lan"

    /** Separates the trusted DHCP server value inside a per-gateway preference entry. */
    private const val SEP = "|"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    // ---- Rogue-DHCP watch --------------------------------------------------------------

    fun dhcpWatchEnabled(ctx: Context): Boolean = p(ctx).getBoolean("dhcp_watch", true)

    fun setDhcpWatchEnabled(ctx: Context, v: Boolean) {
        p(ctx).edit().putBoolean("dhcp_watch", v).apply()
    }

    /** The DHCP server the user confirmed as legitimate for the LAN behind [gateway], or null. */
    fun trustedDhcpServer(ctx: Context, gateway: String): String? =
        p(ctx).getString("dhcp_trust$SEP$gateway", null)?.takeIf { it.isNotBlank() }

    /** Record [server] as the trusted DHCP server for the LAN behind [gateway]. */
    fun trustDhcpServer(ctx: Context, gateway: String, server: String) {
        p(ctx).edit().putString("dhcp_trust$SEP$gateway", server).apply()
    }

    /** Forget the trusted DHCP server for [gateway] — the next observation becomes first-seen. */
    fun forgetDhcpServer(ctx: Context, gateway: String) {
        p(ctx).edit().remove("dhcp_trust$SEP$gateway").apply()
    }

    // ---- ARP watch ---------------------------------------------------------------------

    fun arpWatchEnabled(ctx: Context): Boolean = p(ctx).getBoolean("arp_watch", true)

    fun setArpWatchEnabled(ctx: Context, v: Boolean) {
        p(ctx).edit().putBoolean("arp_watch", v).apply()
    }

    /** The gateway MAC learned as legitimate for the LAN behind [gateway], or null. */
    fun learnedGatewayMac(ctx: Context, gateway: String): String? =
        p(ctx).getString("arp_gw$SEP$gateway", null)?.takeIf { it.isNotBlank() }

    fun learnGatewayMac(ctx: Context, gateway: String, mac: String) {
        p(ctx).edit().putString("arp_gw$SEP$gateway", mac.lowercase()).apply()
    }

    fun forgetGatewayMac(ctx: Context, gateway: String) {
        p(ctx).edit().remove("arp_gw$SEP$gateway").apply()
    }

    // ---- Own-listener deception --------------------------------------------------------

    fun deceptionEnabled(ctx: Context): Boolean = p(ctx).getBoolean("deception", false)

    fun setDeceptionEnabled(ctx: Context, v: Boolean) {
        p(ctx).edit().putBoolean("deception", v).apply()
    }

    /**
     * The decoy ports, as a CSV. Defaults to [Deception.DEFAULT_PORTS]. Persisted as text so the
     * Advanced surface can edit it without a schema, and re-validated by [Deception] on every
     * start — a stored value is never trusted to still be in range or free of collisions.
     */
    fun decoyPorts(ctx: Context): List<Int> {
        val raw = p(ctx).getString("decoy_ports", null) ?: return Deception.DEFAULT_PORTS
        val parsed = raw.split(',').mapNotNull { it.trim().toIntOrNull() }
        return parsed.ifEmpty { Deception.DEFAULT_PORTS }
    }

    fun setDecoyPorts(ctx: Context, ports: List<Int>) {
        p(ctx).edit().putString("decoy_ports", ports.joinToString(",")).apply()
    }
}
