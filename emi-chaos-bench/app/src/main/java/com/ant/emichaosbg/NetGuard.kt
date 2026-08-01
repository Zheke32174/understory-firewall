package com.ant.emichaosbg

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.os.Build
import android.webkit.JavascriptInterface
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * LAN INTERCEPTION DETECTION — the defensive inverse of cSploit and Intercepter-NG.
 *
 * Those tools DO the attack: ARP poisoning to become the gateway, then sniffing or rewriting
 * everyone else's traffic. None of that is built here and none of it will be. What is built is
 * the detector for it, which is the half a counter-surveillance tool should carry: the same
 * knowledge pointed the other way.
 *
 * HOW ARP SPOOFING SHOWS UP FROM THE VICTIM'S SIDE. The attacker tells your phone "the gateway
 * is at MY mac address". Your kernel believes it and updates its ARP table. So the observable
 * signature is in a table this device already maintains for its own reasons:
 *
 *   - ONE MAC ADDRESS CLAIMING SEVERAL IPs. A poisoner impersonating the gateway (and often
 *     other hosts too) ends up bound to multiple addresses at once. Legitimate causes exist —
 *     a router that is also the DNS and DHCP server, a device with several interfaces bridged
 *     — so this is reported with its addresses rather than asserted as an attack.
 *   - THE GATEWAY'S MAC CHANGING while you stay on the same network. That is the moment of
 *     the takeover. Roaming between APs on a mesh does it legitimately, which is why the SSID
 *     and network handle are checked alongside.
 *
 * EVERYTHING HERE IS A READ. /proc/net/arp is the kernel's own table, populated by traffic
 * this device was already part of — the same category of read as `ip neigh` or `arp -a`. No
 * ARP is sent, no packet is injected, no host is probed, and no other device's traffic is
 * touched. That distinction is the whole point: the attack tools transmit, this does not.
 *
 * ALSO CHECKED — RESOLVER AND TUNNEL POSTURE, without any outbound probe. Whether DNS is going
 * somewhere unexpected, and whether a VPN is carrying the traffic, are read from
 * LinkProperties and NetworkCapabilities — local state the OS already holds. This deliberately
 * does NOT probe a remote resolver or fetch a canary URL to test for DPI: that would mean this
 * app generating traffic of its own, which is a posture it does not have and should not gain
 * silently.
 */
class NetGuard(private val ctx: Context, private val log: SecureLog) {

    private var lastGatewayMac: String? = null
    private var lastNetHandle: Long = 0
    private val raised = HashMap<String, Long>()
    private val COALESCE_MS = 5 * 60_000L
    private var lastReport: JSONObject? = null

    private fun flag(sev: Int, key: String, what: String) {
        val now = System.currentTimeMillis()
        val prev = raised[key]
        if (prev != null && now - prev < COALESCE_MS) return
        raised[key] = now
        try { log.append(sev, what, "net-guard", "native") } catch (_: Throwable) {}
    }

    @Synchronized
    fun scan(): String {
        val o = JSONObject()
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

        // ---- ARP table: read only, never written ----------------------------------------
        val entries = ArrayList<Triple<String, String, String>>()   // ip, mac, iface
        var arpReadable = true
        try {
            val lines = File("/proc/net/arp").readLines()
            for (line in lines.drop(1)) {
                val p = line.trim().split(Regex("\\s+"))
                if (p.size < 6) continue
                if (p[2] != "0x2") continue                      // ATF_COMPLETE only
                if (p[3] == "00:00:00:00:00:00") continue
                entries.add(Triple(p[0], p[3].lowercase(), p[5]))
            }
        } catch (_: Throwable) {
            // Android 10+ restricts /proc/net on many builds. Say so rather than reporting a
            // clean network we never actually looked at — a silent empty result reads as "all
            // good", which is the most dangerous thing a security readout can do.
            arpReadable = false
        }
        o.put("arpReadable", arpReadable)
        o.put("arpEntries", entries.size)

        val byMac = HashMap<String, MutableList<String>>()
        val arr = JSONArray()
        for ((ip, mac, iface) in entries) {
            byMac.getOrPut(mac) { ArrayList() }.add(ip)
            arr.put(JSONObject().put("ip", ip).put("mac", mac).put("iface", iface))
        }
        o.put("devices", arr)

        // One MAC holding several IPs — the shape ARP poisoning leaves behind.
        val dupes = JSONArray()
        for ((mac, ips) in byMac) {
            if (ips.size < 2) continue
            dupes.put(JSONObject().put("mac", mac).put("ips", JSONArray(ips)))
            flag(2, "arp-dup-$mac",
                "One device (MAC $mac) is answering for ${ips.size} different IP addresses on " +
                "this network: ${ips.joinToString(", ")}. That is the shape ARP poisoning leaves " +
                "behind — a machine impersonating the gateway ends up bound to several addresses " +
                "at once. It is also what a router that is simultaneously the DNS and DHCP " +
                "server looks like, so check whether those addresses are ones you expect from " +
                "your own router before treating it as an attack.")
        }
        o.put("duplicateMacs", dupes)

        // ---- Gateway MAC continuity -------------------------------------------------------
        var gwIp: String? = null
        var gwMac: String? = null
        var netHandle = 0L
        try {
            val net = cm?.activeNetwork
            netHandle = net?.networkHandle ?: 0L
            val lp: LinkProperties? = if (net != null) cm?.getLinkProperties(net) else null
            gwIp = lp?.routes?.firstOrNull { it.isDefaultRoute }?.gateway?.hostAddress
            if (gwIp != null) gwMac = entries.firstOrNull { it.first == gwIp }?.second
            o.put("gatewayIp", gwIp ?: "unknown")
            o.put("gatewayMac", gwMac ?: "unknown")

            // DNS servers actually in use, and whether Private DNS is on. Local read only.
            val dns = JSONArray()
            lp?.dnsServers?.forEach { dns.put(it.hostAddress) }
            o.put("dnsServers", dns)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                o.put("privateDns", lp?.isPrivateDnsActive ?: false)
                o.put("privateDnsName", lp?.privateDnsServerName ?: "")
            }
            o.put("iface", lp?.interfaceName ?: "")
        } catch (_: Throwable) {}

        // A gateway MAC change WHILE STAYING ON THE SAME NETWORK is the takeover moment.
        // Comparing the network handle as well keeps roaming and network switches from
        // firing it — a different network legitimately has a different gateway.
        if (gwMac != null) {
            val prev = lastGatewayMac
            if (prev != null && prev != gwMac && netHandle == lastNetHandle) {
                flag(3, "gw-mac-change",
                    "The gateway for this network changed hardware address from $prev to $gwMac " +
                    "while you stayed on the same network. That is what it looks like from the " +
                    "inside when something takes over as gateway in order to sit between you and " +
                    "the internet. A mesh handing you to a different access point can do it too, " +
                    "so weigh it against whether you moved.")
            }
            lastGatewayMac = gwMac
            lastNetHandle = netHandle
        }

        // ---- Tunnel posture ---------------------------------------------------------------
        try {
            val caps = cm?.getNetworkCapabilities(cm.activeNetwork)
            val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false
            o.put("vpn", vpn)
            // Not a warning either way. A VPN protects LAN traffic from exactly the attack
            // above; it also means something else terminates your traffic. Both are worth
            // knowing and neither is a finding.
            o.put("vpnNote", if (vpn)
                "A VPN is carrying this connection. That defeats LAN-level interception, since " +
                "the local network only sees the tunnel — but it also means whoever runs the " +
                "tunnel is the one who sees the traffic instead."
            else
                "No VPN on this connection. Traffic is exposed to whatever sits on the local " +
                "network path, which is what the ARP checks above are looking for.")
        } catch (_: Throwable) {}

        o.put("note", "Read-only. The kernel's own ARP table and the OS's own link properties " +
            "are inspected; nothing is sent, injected, probed or redirected. This is the " +
            "detector for LAN interception, not a tool for performing it.")
        o.put("checkedAt", System.currentTimeMillis())
        lastReport = o
        return o.toString()
    }

    fun cached(): String =
        (lastReport ?: JSONObject().put("ok", false).put("reason", "not yet run")).toString()
}

/** Read-only page view. No method here can silence a check or clear a finding. */
class NetGuardBridge(private val g: NetGuard) {
    @JavascriptInterface fun scan(): String = g.scan()
    @JavascriptInterface fun cached(): String = g.cached()
}
