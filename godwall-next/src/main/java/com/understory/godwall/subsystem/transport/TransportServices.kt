package com.understory.godwall.subsystem.transport

import com.understory.godwall.subsystem.ServiceConfigFile
import com.understory.godwall.subsystem.ServiceHealthProbe
import com.understory.godwall.subsystem.ServiceSpec

/**
 * The transport/proxy backends described as data: two daemons that run out of Godwall's own
 * prefix at uid 2000, each pre-configured, each exposing a loopback proxy inbound that the egress
 * chain dials into.
 *
 * ## The topology, once
 *
 * ```
 *   ChainDialer hop  ->  127.0.0.1:10808  ->  sing-box outbound  ->  server you configure
 *   (SOCKS5/HTTP)        mixed inbound        (SS/VMess/VLESS/       (or, by default, direct)
 *                                              Trojan/WireGuard/…)
 *
 *   ChainDialer hop  ->  127.0.0.1:10809  ->  v2ray outbound     ->  server you configure
 *   (SOCKS5)             socks inbound        (VMess/VLESS/SS/…)     (or, by default, direct)
 * ```
 *
 * A "sing-box hop" or "v2ray hop" is not a new chain mechanism — it is a real
 * [com.understory.godwall.chain.ProxyHop.Socks5] pointing at the daemon's loopback inbound, dialled
 * by the SAME [com.understory.godwall.chain.ChainDialer] that already carries SOCKS5 and HTTP
 * CONNECT hops. [TransportStack.chainHop] materialises it. That is the whole point of running these
 * as loopback listeners: a proxy inbound on 127.0.0.1 is reachable by Godwall's own process (and by
 * the tun handler) without any elevation, because loopback is shared across uids — the load-bearing
 * insight of the subsystem, stated in [ServiceSpec].
 *
 * ## Why the shipped default egresses directly, and why that is not a dead control
 *
 * Charter rule C: every backend ships with a working default. Both configs
 * ([TransportConfigs]) bind their inbound and route to a `direct`/`freedom` outbound. So the daemon,
 * when its ELF is present, genuinely starts and its inbound genuinely proxies — the health probe is
 * a real TCP connect to a real listener, not a stand-in. What it does NOT do until you supply a
 * server is route through Shadowsocks/VMess/VLESS/Trojan/WireGuard: those outbound blocks carry
 * per-user secrets (server address, keys, passwords) that cannot honestly be shipped, exactly as
 * obfs4 bridge lines cannot. The reach sentence says this in the same breath, so the control never
 * claims a remote tunnel it does not have. Editing the outbound to a real server is the Advanced
 * surface's job (WP-9), and the config seams there because [ServiceConfigFile.overwrite] is false:
 * the shipped default seeds the file once, and the edited file is authoritative afterwards.
 *
 * ## Honest gating lives in the foundation, not here
 *
 * The daemon ELFs are payload, and a stock Termux bootstrap carries neither sing-box nor v2ray (the
 * same situation as WP-3's dnscrypt-proxy/dnsmasq and WP-4's tor/i2pd). Payloads are not committed,
 * so on a clean checkout [ServiceSpec.binary] is not in the prefix, the [Supervisor] reports the
 * service ABSENT with a sentence, and the control stays disabled — while the build still succeeds.
 * The config files ship (they are cheap text and always present), but a config without its binary is
 * still ABSENT. Nothing here fakes a backend it does not have.
 */
internal object TransportServices {

    /** Stable service ids, also used as pid/log filenames and as capability backing keys. */
    const val ID_SINGBOX = "sing-box"
    const val ID_V2RAY = "v2ray"

    /** sing-box's mixed (SOCKS5 + HTTP CONNECT) loopback inbound — the port a chain hop dials. */
    const val PORT_SINGBOX = 10808

    /** v2ray's SOCKS5 loopback inbound — the port a chain hop dials. */
    const val PORT_V2RAY = 10809

    /**
     * sing-box: the universal proxy platform.
     *
     * Foreground by construction — `run -c <config>` does not daemonise, so the [Supervisor]
     * supervises the pid it launched (the contract in [ServiceSpec]). Config paths are absolute
     * against the prefix via [ServiceSpec.USR_TOKEN]; sing-box needs no cwd-relative files, so the
     * default working directory is fine.
     */
    val singBox = ServiceSpec(
        id = ID_SINGBOX,
        label = "sing-box transport",
        binary = "usr/bin/sing-box",
        args = listOf(
            "run",
            "-c",
            "${ServiceSpec.USR_TOKEN}/etc/sing-box/config.json",
        ),
        configs = listOf(
            ServiceConfigFile(
                asset = "subsystem/sing-box.json",
                destination = "usr/etc/sing-box/config.json",
            ),
        ),
        health = listOf(
            ServiceHealthProbe.LocalPort(PORT_SINGBOX, "SOCKS5/HTTP inbound"),
        ),
        reach = "runs a local SOCKS5/HTTP proxy on 127.0.0.1:$PORT_SINGBOX that the egress chain " +
            "dials into; the shipped default egresses directly, and its Shadowsocks / VMess / " +
            "VLESS / Trojan / WireGuard / Hysteria2 outbounds route through a server you supply in " +
            "the config. It carries only the flows dialled into that port and changes nothing about " +
            "how other apps reach the network.",
    )

    /**
     * v2ray: the v2ray-core proxy platform.
     *
     * Same foreground contract as sing-box. `run -c <config>` is the v5 CLI form; it reads the
     * classic inbound/outbound JSON below.
     */
    val v2ray = ServiceSpec(
        id = ID_V2RAY,
        label = "v2ray transport",
        binary = "usr/bin/v2ray",
        args = listOf(
            "run",
            "-c",
            "${ServiceSpec.USR_TOKEN}/etc/v2ray/config.json",
        ),
        configs = listOf(
            ServiceConfigFile(
                asset = "subsystem/v2ray.json",
                destination = "usr/etc/v2ray/config.json",
            ),
        ),
        health = listOf(
            ServiceHealthProbe.LocalPort(PORT_V2RAY, "SOCKS5 inbound"),
        ),
        reach = "runs a local SOCKS5 proxy on 127.0.0.1:$PORT_V2RAY that the egress chain dials " +
            "into; the shipped default egresses directly, and its VMess / VLESS / Shadowsocks / " +
            "Trojan outbounds route through a server you supply in the config. It carries only the " +
            "TCP flows dialled into that port.",
    )

    /** Both specs, in a stable order. Each is supervised independently; neither depends on the other. */
    val all: List<ServiceSpec> = listOf(singBox, v2ray)

    /** The loopback inbound port for a service this package owns, or null for an unknown id. */
    fun inboundPort(serviceId: String): Int? = when (serviceId) {
        ID_SINGBOX -> PORT_SINGBOX
        ID_V2RAY -> PORT_V2RAY
        else -> null
    }
}
