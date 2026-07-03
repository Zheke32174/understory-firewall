package com.understory.overlay.lokinet

/**
 * Curated catalog of Lokinet bootstrap providers (the equivalent of
 * I2P's reseed servers — Lokinet calls them "bootstrap nodes"). Same
 * intent as [com.understory.overlay.i2p.I2pProvider]: we ship the
 * list, the user picks. We do not host any of these.
 *
 * Phase α (this commit): the lokinet binary is not bundled, so the
 * catalog is informational only — the active provider is wired into
 * UI but never consumed by a running daemon. Phase β fills in the
 * service-side wiring.
 *
 * Source for the seed nodes: the official lokinet repository's
 * `bootstrap.signed` file (https://seed.lokinet.org/bootstrap.signed).
 * The list rotates rarely; users can override via "Custom".
 */
data class LokinetProvider(
    val id: String,
    val name: String,
    /** Bootstrap RC URL. The lokinet daemon fetches this on first start. */
    val bootstrapUrl: String,
    /** One-line non-marketing privacy / operator note. */
    val privacyNote: String,
)

object LokinetProviders {

    val Official = LokinetProvider(
        id = "official-seed",
        name = "Lokinet Project (default)",
        bootstrapUrl = "https://seed.lokinet.org/bootstrap.signed",
        privacyNote = "Operated by the Lokinet project. The default; widely used.",
    )

    val Custom = LokinetProvider(
        id = "custom",
        name = "Custom bootstrap",
        bootstrapUrl = "",
        privacyNote = "Provide your own bootstrap.signed URL or path.",
    )

    /** Catalog in a stable display order. UI iterates in list order. */
    val all: List<LokinetProvider> = listOf(Official, Custom)
}
