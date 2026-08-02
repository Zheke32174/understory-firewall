package com.understory.godwall.subsystem.tor

import android.content.Context
import com.understory.godwall.subsystem.PrefixInstaller

/**
 * The `tor` daemon's own configuration — every key from InviZible Pro's
 * `preferences_tor`, typed, with the donor's exact default, plus the renderer that
 * turns it into a real `torrc` the daemon consumes.
 *
 * ## Why this is the engine behind those preferences, not a mirror of them
 *
 * A "SOCKS Port" toggle that stores 9050 and changes nothing is a dead control —
 * the exact failure this campaign removes. So the settings here are not decoration:
 * [renderTorrc] emits the directive tor actually reads, and
 * [AnonymityController.regenerateTorrc] writes that into the prefix. Change a value,
 * the daemon's behaviour changes. Nothing is stored that is not rendered.
 *
 * ## The seam with the shipped default
 *
 * `assets/subsystem/torrc` is the human-facing default (charter rule C) and is
 * seeded once. [renderTorrc] over [DEFAULT] reproduces the SAME directives and
 * values as that file (the regenerated form drops the teaching comments). They are
 * kept semantically in lock-step, never byte-identical — see the header of that
 * asset. Everything is written against the fixed prefix
 * [PrefixInstaller.PREFIX]; the paths are constants, so they can live in a plain
 * config file with no token expansion.
 *
 * ## What tor enforces here vs. what the datapath enforces
 *
 * The directives below (ports, isolation flags, node selection, circuit timing)
 * are enforced by the tor process itself once it runs. Which app's or site's
 * traffic is *steered into* those ports is a different, datapath-level question and
 * lives in [TorRoutingPolicy], gated separately and honestly. Keeping the two apart
 * is what lets each state its real reach.
 *
 * Pure data + pure functions: no Context is held, no I/O happens here. [TorDaemonStore]
 * owns persistence; the renderer is a total function of its input so it can be
 * reasoned about — and, off-device, tested — without a daemon or a shell.
 */
data class TorDaemonSettings(
    // ── Nodes (preferences_tor > "Nodes") ──────────────────────────────────────
    // Each switch gates whether the matching directive is emitted; the country
    // list is the codes it applies to (tor form: "{us},{de}"). A switch on with an
    // empty list emits nothing — an empty ExitNodes line would wedge tor.
    val excludeExitNodes: Boolean = false,
    val excludeExitNodesCountries: String = "",
    val exitNodes: Boolean = false,
    val exitNodesCountries: String = "",
    val excludeNodes: Boolean = false,
    val excludeNodesCountries: String = "",
    val entryNodes: Boolean = false,
    val entryNodesCountries: String = "",
    val strictNodes: Boolean = false,

    // ── Common settings (preferences_tor > "Common settings") ──────────────────
    val virtualAddrNetwork: String = "10.192.0.0/10",
    val hardwareAccel: Boolean = true,
    val avoidDiskWrites: Boolean = true,
    val connectionPadding: Boolean = true,
    val reducedConnectionPadding: Boolean = true,
    val fascistFirewall: Boolean = false,
    val newCircuitPeriod: Int = 30,
    val maxCircuitDirtiness: Int = 600,
    /** Minutes; tor requires at least 10. The donor default is 15. */
    val dormantClientTimeout: Int = 15,
    val enforceDistinctSubnets: Boolean = true,
    val trackHostExits: Boolean = false,
    val clientUseIPv4: Boolean = true,
    val clientUseIPv6: Boolean = true,

    // ── Isolation (preferences_tor > "Isolation settings") ─────────────────────
    // "Isolate By UID" keeps tor's default per-SOCKS-auth stream isolation on; the
    // datapath supplies each app distinct SOCKS credentials to realise it. Off ⇒
    // NoIsolateSOCKSAuth. Dest-addr / dest-port add the matching isolation flags.
    val isolateUid: Boolean = true,
    val isolateDestAddr: Boolean = false,
    val isolateDestPort: Boolean = false,

    // ── Proxy / listeners (preferences_tor > "Proxy") ──────────────────────────
    val socksEnabled: Boolean = true,
    val socksPort: Int = 9050,
    val httpTunnelEnabled: Boolean = false,
    val httpTunnelPort: Int = 8118,
    val transparentEnabled: Boolean = true,
    val transPort: Int = 9040,
    val dnsEnabled: Boolean = true,
    val dnsPort: Int = 5400,

    // ── Output SOCKS5 proxy (preferences_tor > "SOCKS proxy") ──────────────────
    val outputSocksEnabled: Boolean = false,
    val outputSocks: String = "127.0.0.1:1080",

    // ── Snowflake (preferences_tor > "Snowflake") ──────────────────────────────
    // Only consulted when a Snowflake bridge is active (see TorBridges); stored
    // here because these are preferences_tor keys.
    val snowflakeRendezvous: Int = 1,
    val snowflakeStun: String = "",

    // Fixed daemon ports that are not user preferences but must stay consistent.
    /** Loopback control port for NEWNYM ("New Tor identity"). */
    val controlPort: Int = 9051,
) {

    /**
     * A full `torrc` for this configuration. [bridgeLines] is the block
     * [TorBridges] renders for the active bridge set — empty when bridges are off
     * or their pluggable-transport binary is absent, so tor is never told to exec
     * a transport that is not there. Paths are absolute against [PrefixInstaller.PREFIX].
     */
    fun renderTorrc(bridgeLines: List<String> = emptyList()): String {
        val p = PrefixInstaller.PREFIX
        val out = ArrayList<String>(64)
        out += "# Godwall subsystem — tor daemon configuration (machine-generated"
        out += "# from TorDaemonSettings; the human-facing default with commentary is the"
        out += "# seeded assets/subsystem/torrc). Absolute paths against $p."
        out += ""
        // Foreground contract from ServiceSpec: RunAsDaemon 1 would detach the pid.
        out += "RunAsDaemon 0"
        out += "DataDirectory $p/home/tor"
        out += "Log notice file $p/logs/tor-notice.log"
        out += ""
        out += "GeoIPFile $p/usr/etc/tor/geoip"
        out += "GeoIPv6File $p/usr/etc/tor/geoip6"
        out += ""
        out += "VirtualAddrNetworkIPv4 ${virtualAddrNetwork.trim()}"
        out += "AutomapHostsOnResolve 1"
        out += ""

        // Common settings.
        out += "HardwareAccel ${bit(hardwareAccel)}"
        out += "AvoidDiskWrites ${bit(avoidDiskWrites)}"
        out += "ConnectionPadding ${bit(connectionPadding)}"
        out += "ReducedConnectionPadding ${bit(reducedConnectionPadding)}"
        if (fascistFirewall) out += "FascistFirewall 1"
        out += "NewCircuitPeriod ${newCircuitPeriod.coerceAtLeast(1)}"
        out += "MaxCircuitDirtiness ${maxCircuitDirtiness.coerceAtLeast(10)}"
        out += "DormantClientTimeout ${dormantClientTimeout.coerceAtLeast(10)} minutes"
        out += "DormantCanceledByStartup 1"
        out += "EnforceDistinctSubnets ${bit(enforceDistinctSubnets)}"
        if (trackHostExits) out += "TrackHostExits ."
        out += "ClientUseIPv4 ${bit(clientUseIPv4)}"
        out += "ClientUseIPv6 ${bit(clientUseIPv6)}"
        out += ""

        // Node selection. Only emitted when the switch is on AND a country list is
        // present — and, upstream, only offered at all when the GeoIP tables exist.
        nodeLine("ExcludeExitNodes", excludeExitNodes, excludeExitNodesCountries)?.let { out += it }
        nodeLine("ExitNodes", exitNodes, exitNodesCountries)?.let { out += it }
        nodeLine("ExcludeNodes", excludeNodes, excludeNodesCountries)?.let { out += it }
        nodeLine("EntryNodes", entryNodes, entryNodesCountries)?.let { out += it }
        if (strictNodes) out += "StrictNodes 1"
        if (out.last().isNotEmpty()) out += ""

        // Listeners with isolation flags.
        val isoTail = isolationFlags()
        if (socksEnabled) out += "SOCKSPort ${socksPort}${isoTail}"
        if (transparentEnabled) out += "TransPort ${transPort}${destIsolationFlags()}"
        if (dnsEnabled) out += "DNSPort ${dnsPort}${destIsolationFlags()}"
        if (httpTunnelEnabled) out += "HTTPTunnelPort $httpTunnelPort"
        if (outputSocksEnabled && outputSocks.isNotBlank()) out += "Socks5Proxy ${outputSocks.trim()}"
        out += ""

        out += "ControlPort $controlPort"
        out += "CookieAuthentication 1"

        if (bridgeLines.isNotEmpty()) {
            out += ""
            out += "# Bridges (active set rendered by TorBridges — PT binary verified present)."
            out += "UseBridges 1"
            out += bridgeLines
        }

        return out.joinToString("\n") + "\n"
    }

    /** SOCKSPort isolation tail. */
    private fun isolationFlags(): String {
        val flags = ArrayList<String>(3)
        if (!isolateUid) flags += "NoIsolateSOCKSAuth"
        if (isolateDestAddr) flags += "IsolateDestAddr"
        if (isolateDestPort) flags += "IsolateDestPort"
        return if (flags.isEmpty()) "" else " " + flags.joinToString(" ")
    }

    /** TransPort/DNSPort take only the destination isolation flags. */
    private fun destIsolationFlags(): String {
        val flags = ArrayList<String>(2)
        if (isolateDestAddr) flags += "IsolateDestAddr"
        if (isolateDestPort) flags += "IsolateDestPort"
        return if (flags.isEmpty()) "" else " " + flags.joinToString(" ")
    }

    private fun nodeLine(directive: String, enabled: Boolean, countries: String): String? {
        if (!enabled) return null
        val v = countries.trim()
        if (v.isEmpty()) return null
        return "$directive $v"
    }

    private fun bit(b: Boolean): Int = if (b) 1 else 0

    companion object {
        val DEFAULT = TorDaemonSettings()
    }
}

/**
 * Persistence for [TorDaemonSettings]. Saved whether or not the tor binary is in
 * this build — the same discipline as MeshSettings: a user's configuration is not
 * lost because the payload that would consume it is absent.
 */
object TorDaemonStore {

    private const val PREFS = "godwall_tor_daemon"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The current settings snapshot. Reads SharedPreferences — call off the main thread. */
    fun snapshot(ctx: Context): TorDaemonSettings {
        val d = TorDaemonSettings.DEFAULT
        val s = p(ctx)
        return TorDaemonSettings(
            excludeExitNodes = s.getBoolean("excludeExitNodes", d.excludeExitNodes),
            excludeExitNodesCountries = s.getString("excludeExitNodesCountries", d.excludeExitNodesCountries) ?: d.excludeExitNodesCountries,
            exitNodes = s.getBoolean("exitNodes", d.exitNodes),
            exitNodesCountries = s.getString("exitNodesCountries", d.exitNodesCountries) ?: d.exitNodesCountries,
            excludeNodes = s.getBoolean("excludeNodes", d.excludeNodes),
            excludeNodesCountries = s.getString("excludeNodesCountries", d.excludeNodesCountries) ?: d.excludeNodesCountries,
            entryNodes = s.getBoolean("entryNodes", d.entryNodes),
            entryNodesCountries = s.getString("entryNodesCountries", d.entryNodesCountries) ?: d.entryNodesCountries,
            strictNodes = s.getBoolean("strictNodes", d.strictNodes),
            virtualAddrNetwork = s.getString("virtualAddrNetwork", d.virtualAddrNetwork) ?: d.virtualAddrNetwork,
            hardwareAccel = s.getBoolean("hardwareAccel", d.hardwareAccel),
            avoidDiskWrites = s.getBoolean("avoidDiskWrites", d.avoidDiskWrites),
            connectionPadding = s.getBoolean("connectionPadding", d.connectionPadding),
            reducedConnectionPadding = s.getBoolean("reducedConnectionPadding", d.reducedConnectionPadding),
            fascistFirewall = s.getBoolean("fascistFirewall", d.fascistFirewall),
            newCircuitPeriod = s.getInt("newCircuitPeriod", d.newCircuitPeriod),
            maxCircuitDirtiness = s.getInt("maxCircuitDirtiness", d.maxCircuitDirtiness),
            dormantClientTimeout = s.getInt("dormantClientTimeout", d.dormantClientTimeout),
            enforceDistinctSubnets = s.getBoolean("enforceDistinctSubnets", d.enforceDistinctSubnets),
            trackHostExits = s.getBoolean("trackHostExits", d.trackHostExits),
            clientUseIPv4 = s.getBoolean("clientUseIPv4", d.clientUseIPv4),
            clientUseIPv6 = s.getBoolean("clientUseIPv6", d.clientUseIPv6),
            isolateUid = s.getBoolean("isolateUid", d.isolateUid),
            isolateDestAddr = s.getBoolean("isolateDestAddr", d.isolateDestAddr),
            isolateDestPort = s.getBoolean("isolateDestPort", d.isolateDestPort),
            socksEnabled = s.getBoolean("socksEnabled", d.socksEnabled),
            socksPort = s.getInt("socksPort", d.socksPort),
            httpTunnelEnabled = s.getBoolean("httpTunnelEnabled", d.httpTunnelEnabled),
            httpTunnelPort = s.getInt("httpTunnelPort", d.httpTunnelPort),
            transparentEnabled = s.getBoolean("transparentEnabled", d.transparentEnabled),
            transPort = s.getInt("transPort", d.transPort),
            dnsEnabled = s.getBoolean("dnsEnabled", d.dnsEnabled),
            dnsPort = s.getInt("dnsPort", d.dnsPort),
            outputSocksEnabled = s.getBoolean("outputSocksEnabled", d.outputSocksEnabled),
            outputSocks = s.getString("outputSocks", d.outputSocks) ?: d.outputSocks,
            snowflakeRendezvous = s.getInt("snowflakeRendezvous", d.snowflakeRendezvous),
            snowflakeStun = s.getString("snowflakeStun", d.snowflakeStun) ?: d.snowflakeStun,
        )
    }

    /** Persist a whole snapshot. Caller regenerates the torrc afterwards. */
    fun save(ctx: Context, v: TorDaemonSettings) {
        p(ctx).edit()
            .putBoolean("excludeExitNodes", v.excludeExitNodes)
            .putString("excludeExitNodesCountries", v.excludeExitNodesCountries.trim())
            .putBoolean("exitNodes", v.exitNodes)
            .putString("exitNodesCountries", v.exitNodesCountries.trim())
            .putBoolean("excludeNodes", v.excludeNodes)
            .putString("excludeNodesCountries", v.excludeNodesCountries.trim())
            .putBoolean("entryNodes", v.entryNodes)
            .putString("entryNodesCountries", v.entryNodesCountries.trim())
            .putBoolean("strictNodes", v.strictNodes)
            .putString("virtualAddrNetwork", v.virtualAddrNetwork.trim())
            .putBoolean("hardwareAccel", v.hardwareAccel)
            .putBoolean("avoidDiskWrites", v.avoidDiskWrites)
            .putBoolean("connectionPadding", v.connectionPadding)
            .putBoolean("reducedConnectionPadding", v.reducedConnectionPadding)
            .putBoolean("fascistFirewall", v.fascistFirewall)
            .putInt("newCircuitPeriod", v.newCircuitPeriod)
            .putInt("maxCircuitDirtiness", v.maxCircuitDirtiness)
            .putInt("dormantClientTimeout", v.dormantClientTimeout)
            .putBoolean("enforceDistinctSubnets", v.enforceDistinctSubnets)
            .putBoolean("trackHostExits", v.trackHostExits)
            .putBoolean("clientUseIPv4", v.clientUseIPv4)
            .putBoolean("clientUseIPv6", v.clientUseIPv6)
            .putBoolean("isolateUid", v.isolateUid)
            .putBoolean("isolateDestAddr", v.isolateDestAddr)
            .putBoolean("isolateDestPort", v.isolateDestPort)
            .putBoolean("socksEnabled", v.socksEnabled)
            .putInt("socksPort", v.socksPort)
            .putBoolean("httpTunnelEnabled", v.httpTunnelEnabled)
            .putInt("httpTunnelPort", v.httpTunnelPort)
            .putBoolean("transparentEnabled", v.transparentEnabled)
            .putInt("transPort", v.transPort)
            .putBoolean("dnsEnabled", v.dnsEnabled)
            .putInt("dnsPort", v.dnsPort)
            .putBoolean("outputSocksEnabled", v.outputSocksEnabled)
            .putString("outputSocks", v.outputSocks.trim())
            .putInt("snowflakeRendezvous", v.snowflakeRendezvous)
            .putString("snowflakeStun", v.snowflakeStun.trim())
            .apply()
    }
}
