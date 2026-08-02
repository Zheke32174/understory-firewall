package com.understory.godwall.subsystem.tor

import android.content.Context
import com.understory.godwall.subsystem.PrefixInstaller

/**
 * The `i2pd` (Purple I2P) daemon's configuration — every key from InviZible Pro's
 * `preferences_i2pd`, typed with the donor's exact default, plus the renderer that
 * turns it into a real `i2pd.conf`.
 *
 * Same discipline as [TorDaemonSettings]: nothing is stored that is not rendered
 * into a directive the daemon reads, so no control here is decorative.
 * [renderI2pdConf] over [DEFAULT] reproduces the same keys and values as the seeded
 * `assets/subsystem/i2pd.conf` (the regenerated form drops the teaching comments).
 * The data directory is NOT written here — it is passed on argv (`--datadir`) by the
 * ServiceSpec so the daemon and the Supervisor never disagree on where it lives.
 *
 * Pure data + pure functions; [I2pdStore] owns persistence.
 */
data class I2pdSettings(
    // ── Common settings (preferences_i2pd > "Common settings") ─────────────────
    val ipv4: Boolean = true,
    val ipv6: Boolean = true,
    val notransit: Boolean = false,
    val floodfill: Boolean = false,
    /** Bandwidth class: L/O/P/X or a KBps number. Donor default "L". */
    val bandwidth: String = "L",
    /** Max % of the bandwidth limit offered for transit, 0–100. */
    val share: Int = 20,
    val ssu2: Boolean = false,
    val ntcp2: Boolean = true,

    // ── HTTP proxy (preferences_i2pd > "HTTP proxy") ───────────────────────────
    val httpProxy: Boolean = true,
    val httpProxyPort: Int = 4444,
    val httpOutproxy: Boolean = false,
    val httpOutproxyAddress: String = "http://false.i2p",

    // ── SOCKS proxy (preferences_i2pd > "Socks proxy") ─────────────────────────
    val socksProxy: Boolean = true,
    val socksProxyPort: Int = 4447,
    val socksOutproxy: Boolean = false,
    val socksOutproxyAddress: String = "127.0.0.1",
    val socksOutproxyPort: Int = 9050,

    // ── Outbound proxy (preferences_i2pd > "Outbound proxy") ───────────────────
    val ntcpProxyEnabled: Boolean = false,
    val ntcpProxy: String = "http://127.0.0.1:8118",

    // ── Incoming connections (preferences_i2pd > "Incoming connections") ───────
    val allowIncoming: Boolean = false,
    val incomingHost: String = "127.0.0.1",
    val incomingPort: Int = 4567,

    // ── SAM interface (preferences_i2pd > "SAM interface") ─────────────────────
    val samInterface: Boolean = false,
    val samPort: Int = 7656,

    // ── Cryptography (preferences_i2pd > "Cryptography") ───────────────────────
    val elgamal: Boolean = true,

    // ── UPnP (preferences_i2pd > "UPNP") ───────────────────────────────────────
    val upnp: Boolean = true,

    // ── Reseeding (preferences_i2pd > "Reseeding") ─────────────────────────────
    val reseedVerify: Boolean = true,

    // ── Limits (preferences_i2pd > "Limits") ───────────────────────────────────
    val transitTunnels: Int = 10,
    val openFiles: Int = 500,
    val coreSize: Int = 0,

    // ── Address book (preferences_i2pd > "Address book") ───────────────────────
    val addressbookDefaultUrl: String =
        "http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/hosts.txt",
) {

    /** A full `i2pd.conf` for this configuration. Absolute log path against the prefix. */
    fun renderI2pdConf(): String {
        val p = PrefixInstaller.PREFIX
        val out = ArrayList<String>(64)
        out += "# Godwall subsystem — i2pd configuration (machine-generated from I2pdSettings;"
        out += "# the human-facing default with commentary is the seeded assets/subsystem/i2pd.conf)."
        out += ""
        out += "log = file"
        out += "logfile = $p/logs/i2pd.log"
        out += "loglevel = warn"
        out += ""
        out += "ipv4 = ${bool(ipv4)}"
        out += "ipv6 = ${bool(ipv6)}"
        out += "notransit = ${bool(notransit)}"
        out += "floodfill = ${bool(floodfill)}"
        out += "bandwidth = ${bandwidth.trim()}"
        out += "share = ${share.coerceIn(0, 100)}"
        if (allowIncoming) {
            // A published router advertises a reachable host/port; without this i2pd
            // stays a client-only node, which is the default.
            out += "host = ${incomingHost.trim()}"
            out += "port = ${incomingPort}"
        }
        out += ""
        out += "[ntcp2]"
        out += "enabled = ${bool(ntcp2)}"
        if (allowIncoming) out += "published = true"
        if (ntcpProxyEnabled && ntcpProxy.isNotBlank()) out += "proxy = ${ntcpProxy.trim()}"
        out += ""
        out += "[ssu2]"
        out += "enabled = ${bool(ssu2)}"
        out += ""
        out += "[http]"
        out += "enabled = true"
        out += "address = 127.0.0.1"
        out += "port = 7070"
        out += ""
        out += "[httpproxy]"
        out += "enabled = ${bool(httpProxy)}"
        out += "address = 127.0.0.1"
        out += "port = ${httpProxyPort}"
        if (httpOutproxy && httpOutproxyAddress.isNotBlank()) out += "outproxy = ${httpOutproxyAddress.trim()}"
        out += ""
        out += "[socksproxy]"
        out += "enabled = ${bool(socksProxy)}"
        out += "address = 127.0.0.1"
        out += "port = ${socksProxyPort}"
        if (socksOutproxy) {
            out += "outproxy.enabled = true"
            out += "outproxy = ${socksOutproxyAddress.trim()}"
            out += "outproxyport = ${socksOutproxyPort}"
        }
        out += ""
        out += "[sam]"
        out += "enabled = ${bool(samInterface)}"
        out += "address = 127.0.0.1"
        out += "port = ${samPort}"
        out += ""
        out += "[upnp]"
        out += "enabled = ${bool(upnp)}"
        out += ""
        out += "[reseed]"
        out += "verify = ${bool(reseedVerify)}"
        out += ""
        out += "[limits]"
        out += "transittunnels = ${transitTunnels}"
        out += "openfiles = ${openFiles}"
        out += "coresize = ${coreSize}"
        out += ""
        out += "[addressbook]"
        out += "defaulturl = ${addressbookDefaultUrl.trim()}"
        out += ""
        out += "[precomputation]"
        out += "elgamal = ${bool(elgamal)}"
        return out.joinToString("\n") + "\n"
    }

    private fun bool(b: Boolean): String = if (b) "true" else "false"

    companion object {
        val DEFAULT = I2pdSettings()
    }
}

/** Persistence for [I2pdSettings]. Saved regardless of whether the i2pd binary is present. */
object I2pdStore {

    private const val PREFS = "godwall_i2pd"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun snapshot(ctx: Context): I2pdSettings {
        val d = I2pdSettings.DEFAULT
        val s = p(ctx)
        return I2pdSettings(
            ipv4 = s.getBoolean("ipv4", d.ipv4),
            ipv6 = s.getBoolean("ipv6", d.ipv6),
            notransit = s.getBoolean("notransit", d.notransit),
            floodfill = s.getBoolean("floodfill", d.floodfill),
            bandwidth = s.getString("bandwidth", d.bandwidth) ?: d.bandwidth,
            share = s.getInt("share", d.share),
            ssu2 = s.getBoolean("ssu2", d.ssu2),
            ntcp2 = s.getBoolean("ntcp2", d.ntcp2),
            httpProxy = s.getBoolean("httpProxy", d.httpProxy),
            httpProxyPort = s.getInt("httpProxyPort", d.httpProxyPort),
            httpOutproxy = s.getBoolean("httpOutproxy", d.httpOutproxy),
            httpOutproxyAddress = s.getString("httpOutproxyAddress", d.httpOutproxyAddress) ?: d.httpOutproxyAddress,
            socksProxy = s.getBoolean("socksProxy", d.socksProxy),
            socksProxyPort = s.getInt("socksProxyPort", d.socksProxyPort),
            socksOutproxy = s.getBoolean("socksOutproxy", d.socksOutproxy),
            socksOutproxyAddress = s.getString("socksOutproxyAddress", d.socksOutproxyAddress) ?: d.socksOutproxyAddress,
            socksOutproxyPort = s.getInt("socksOutproxyPort", d.socksOutproxyPort),
            ntcpProxyEnabled = s.getBoolean("ntcpProxyEnabled", d.ntcpProxyEnabled),
            ntcpProxy = s.getString("ntcpProxy", d.ntcpProxy) ?: d.ntcpProxy,
            allowIncoming = s.getBoolean("allowIncoming", d.allowIncoming),
            incomingHost = s.getString("incomingHost", d.incomingHost) ?: d.incomingHost,
            incomingPort = s.getInt("incomingPort", d.incomingPort),
            samInterface = s.getBoolean("samInterface", d.samInterface),
            samPort = s.getInt("samPort", d.samPort),
            elgamal = s.getBoolean("elgamal", d.elgamal),
            upnp = s.getBoolean("upnp", d.upnp),
            reseedVerify = s.getBoolean("reseedVerify", d.reseedVerify),
            transitTunnels = s.getInt("transitTunnels", d.transitTunnels),
            openFiles = s.getInt("openFiles", d.openFiles),
            coreSize = s.getInt("coreSize", d.coreSize),
            addressbookDefaultUrl = s.getString("addressbookDefaultUrl", d.addressbookDefaultUrl) ?: d.addressbookDefaultUrl,
        )
    }

    fun save(ctx: Context, v: I2pdSettings) {
        p(ctx).edit()
            .putBoolean("ipv4", v.ipv4)
            .putBoolean("ipv6", v.ipv6)
            .putBoolean("notransit", v.notransit)
            .putBoolean("floodfill", v.floodfill)
            .putString("bandwidth", v.bandwidth.trim())
            .putInt("share", v.share.coerceIn(0, 100))
            .putBoolean("ssu2", v.ssu2)
            .putBoolean("ntcp2", v.ntcp2)
            .putBoolean("httpProxy", v.httpProxy)
            .putInt("httpProxyPort", v.httpProxyPort)
            .putBoolean("httpOutproxy", v.httpOutproxy)
            .putString("httpOutproxyAddress", v.httpOutproxyAddress.trim())
            .putBoolean("socksProxy", v.socksProxy)
            .putInt("socksProxyPort", v.socksProxyPort)
            .putBoolean("socksOutproxy", v.socksOutproxy)
            .putString("socksOutproxyAddress", v.socksOutproxyAddress.trim())
            .putInt("socksOutproxyPort", v.socksOutproxyPort)
            .putBoolean("ntcpProxyEnabled", v.ntcpProxyEnabled)
            .putString("ntcpProxy", v.ntcpProxy.trim())
            .putBoolean("allowIncoming", v.allowIncoming)
            .putString("incomingHost", v.incomingHost.trim())
            .putInt("incomingPort", v.incomingPort)
            .putBoolean("samInterface", v.samInterface)
            .putInt("samPort", v.samPort)
            .putBoolean("elgamal", v.elgamal)
            .putBoolean("upnp", v.upnp)
            .putBoolean("reseedVerify", v.reseedVerify)
            .putInt("transitTunnels", v.transitTunnels)
            .putInt("openFiles", v.openFiles)
            .putInt("coreSize", v.coreSize)
            .putString("addressbookDefaultUrl", v.addressbookDefaultUrl.trim())
            .apply()
    }
}
