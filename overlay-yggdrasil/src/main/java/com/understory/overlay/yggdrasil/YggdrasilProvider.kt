package com.understory.overlay.yggdrasil

/**
 * Curated catalog of Yggdrasil public peers — the entry points a
 * yggdrasil node uses to join the mesh. Same intent as
 * [com.understory.overlay.i2p.I2pProvider] and
 * [com.understory.overlay.lokinet.LokinetProvider]: we ship the list,
 * the user picks. We do not host any of these.
 *
 * Yggdrasil peers are TLS connections to specific host:port pairs, not
 * URL bootstraps like the other two networks. The official catalog
 * lives at https://github.com/yggdrasil-network/public-peers — we
 * snapshot a small geographically diverse subset here. Users can add
 * their own via "Custom".
 *
 * Phase α (this commit): the yggdrasil binary is not bundled, so the
 * catalog is informational only. Phase β wires it into the supervisor.
 */
data class YggdrasilProvider(
    val id: String,
    val name: String,
    /** Peer URL in yggdrasil's tls://host:port form. Empty for Custom. */
    val peerUrl: String,
    /** Approximate region for diversity selection (UI hint only). */
    val region: String,
    /** One-line non-marketing operator note. */
    val privacyNote: String,
)

object YggdrasilProviders {

    val DigitalOceanFra = YggdrasilProvider(
        id = "do-fra",
        name = "DigitalOcean (Frankfurt)",
        peerUrl = "tls://yggno.de:18227",
        region = "EU",
        privacyNote = "Operated by yggno.de. Public peer; routes nothing it can decrypt.",
    )

    val UsEast = YggdrasilProvider(
        id = "us-east",
        name = "US-East public peer",
        peerUrl = "tls://ygg-us-east.averesoftware.com:18226",
        region = "US-East",
        privacyNote = "Operated by Averesoftware. Routes only encrypted yggdrasil traffic.",
    )

    val ApSingapore = YggdrasilProvider(
        id = "ap-sg",
        name = "Singapore public peer",
        peerUrl = "tls://sgp1.ygg.cloudbear.network:18227",
        region = "AP",
        privacyNote = "Operated by cloudbear.network. Routes only encrypted yggdrasil traffic.",
    )

    val Custom = YggdrasilProvider(
        id = "custom",
        name = "Custom peer",
        peerUrl = "",
        region = "?",
        privacyNote = "Provide your own tls://host:port peer.",
    )

    /** Catalog in a stable display order. UI iterates in list order. */
    val all: List<YggdrasilProvider> = listOf(DigitalOceanFra, UsEast, ApSingapore, Custom)
}
