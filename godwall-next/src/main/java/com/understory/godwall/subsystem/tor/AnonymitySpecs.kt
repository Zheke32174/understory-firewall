package com.understory.godwall.subsystem.tor

import com.understory.godwall.subsystem.ServiceConfigFile
import com.understory.godwall.subsystem.ServiceHealthProbe
import com.understory.godwall.subsystem.ServiceRestartPolicy
import com.understory.godwall.subsystem.ServiceSpec

/**
 * The declarative descriptions of the two Anonymity daemons, as [ServiceSpec]s the
 * Supervisor runs. No lifecycle logic lives here — the Supervisor owns "did it start,
 * is it alive, is its port bound". This file only states the facts that distinguish
 * tor and i2pd from every other supervised daemon: their binary, argv, seeded config
 * and the loopback ports that prove they are doing their job.
 *
 * The specs are built from the current [TorDaemonSettings] / [I2pdSettings] so the
 * health probes track the configured ports: change the SOCKS port in the settings and
 * the probe follows it, rather than checking a port the daemon no longer binds.
 *
 * ## The foreground contract
 *
 * Both daemons must run in the foreground (tor: `RunAsDaemon 0` in the torrc; i2pd:
 * foreground by default). The Supervisor tracks the pid the launch shell reported; a
 * double-fork would detach it and leave a live daemon nothing supervises. The shipped
 * configs honour this — see the torrc header.
 */
object AnonymitySpecs {

    const val TOR_ID = "tor"
    const val I2PD_ID = "i2pd"

    /** Prefix-relative binary paths the AnonymityController seeds into `usr/bin/`. */
    const val TOR_BINARY = "usr/bin/tor"
    const val I2PD_BINARY = "usr/bin/i2pd"

    /** Config asset paths (this WP owns them) and their prefix destinations. */
    const val TORRC_ASSET = "subsystem/torrc"
    const val TORRC_DEST = "usr/etc/tor/torrc"
    const val I2PD_CONF_ASSET = "subsystem/i2pd.conf"
    const val I2PD_CONF_DEST = "usr/etc/i2pd/i2pd.conf"

    /**
     * The tor client spec. Health = its enabled loopback listeners are open. A bound
     * SOCKS/DNS listener means the daemon is up and serving; full network bootstrap
     * (Bootstrapped 100%) is a separate progress signal surfaced via [TorControl] and
     * the notice log, not folded into "is the process healthy".
     */
    fun torSpec(settings: TorDaemonSettings = TorDaemonSettings.DEFAULT): ServiceSpec {
        val probes = ArrayList<ServiceHealthProbe>(2)
        if (settings.socksEnabled) probes += ServiceHealthProbe.LocalPort(settings.socksPort, "SOCKS proxy")
        if (settings.dnsEnabled) probes += ServiceHealthProbe.LocalPort(settings.dnsPort, "DNS resolver")
        return ServiceSpec(
            id = TOR_ID,
            label = "Tor",
            binary = TOR_BINARY,
            // The torrc carries DataDirectory, ports and everything else; -f points at it.
            args = listOf("-f", "${ServiceSpec.USR_TOKEN}/etc/tor/torrc"),
            workingDir = "home/tor",
            configs = listOf(ServiceConfigFile(asset = TORRC_ASSET, destination = TORRC_DEST)),
            health = probes,
            restart = ServiceRestartPolicy.ON_FAILURE,
            reach = "Runs the Tor client as uid 2000 in Godwall's prefix. It binds a SOCKS proxy " +
                "on 127.0.0.1:${settings.socksPort} and a DNS resolver on 127.0.0.1:${settings.dnsPort} " +
                "for the tun to dial into; it anonymises only the flows the routing policy steers to " +
                "it, and does not by itself route any app's traffic.",
        )
    }

    /**
     * The i2pd (Purple I2P) router spec. Datadir is passed on argv so the daemon and
     * the Supervisor agree on one location. Health = its enabled proxy listeners are open.
     */
    fun i2pdSpec(settings: I2pdSettings = I2pdSettings.DEFAULT): ServiceSpec {
        val probes = ArrayList<ServiceHealthProbe>(2)
        if (settings.httpProxy) probes += ServiceHealthProbe.LocalPort(settings.httpProxyPort, "HTTP proxy")
        if (settings.socksProxy) probes += ServiceHealthProbe.LocalPort(settings.socksProxyPort, "SOCKS proxy")
        return ServiceSpec(
            id = I2PD_ID,
            label = "Purple I2P (i2pd)",
            binary = I2PD_BINARY,
            args = listOf(
                "--conf", "${ServiceSpec.USR_TOKEN}/etc/i2pd/i2pd.conf",
                "--datadir", "${ServiceSpec.HOME_TOKEN}/i2pd",
            ),
            workingDir = "home/i2pd",
            configs = listOf(ServiceConfigFile(asset = I2PD_CONF_ASSET, destination = I2PD_CONF_DEST)),
            health = probes,
            restart = ServiceRestartPolicy.ON_FAILURE,
            reach = "Runs the i2pd router as uid 2000 in Godwall's prefix. It binds an HTTP proxy on " +
                "127.0.0.1:${settings.httpProxyPort} and a SOCKS proxy on 127.0.0.1:${settings.socksProxyPort} " +
                "for reaching .i2p services; it serves those proxies and does not route device traffic on its own.",
        )
    }
}
