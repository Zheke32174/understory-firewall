package com.understory.godwall.ward

import com.understory.godwall.BuildConfig

/**
 * The capabilities the WARD screen shows but cannot run, each with the payload that is missing.
 *
 * `docs/DONOR-ASSETS.md` is the authority: several donors' behaviour lives in prebuilt ELF
 * binaries, not in their Kotlin. Tor's "new identity" is a NEWNYM on tor's control port and there
 * is no tor process without `assets/tor.mp3`; the same is true of dnscrypt-proxy and i2pd; the
 * hotspot rules are InviZible's, driven through a bundled busybox.
 *
 * The rule from that document, applied here: a capability whose payload is absent **reports
 * absent**. It draws a control that is visibly disabled with the sentence saying which payload is
 * missing — never an enabled control that no-ops, and never a state it cannot reach.
 *
 * [MESH] is the counter-example and the reference: its payload is a build input that IS present,
 * so it is not gated in this build.
 */
enum class GatedCapability(val available: Boolean) {

    /** tor ELF + torrc/geoip tree (InviZible). Gates "New Tor identity" and Tor routing. */
    TOR(available = false),

    /** i2pd ELF + i2pd.conf (InviZible). */
    I2P(available = false),

    /** dnscrypt-proxy ELF + dnscrypt-proxy.toml (InviZible). */
    DNSCRYPT(available = false),

    /** busybox + iptables rules for tethered clients (InviZible's hotspot). */
    HOTSPOT(available = false),

    /** firestack.aar — the packet-level tun2socks data plane (RethinkDNS). */
    PACKET_DATAPLANE(available = false),

    /** libtailscale.aar. LINKED in this build, and the pattern the rest copy. */
    MESH(available = BuildConfig.HAS_MESH_DATAPLANE),
}
