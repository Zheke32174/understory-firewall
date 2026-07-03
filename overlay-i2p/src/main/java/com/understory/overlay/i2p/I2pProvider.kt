package com.understory.overlay.i2p

/**
 * Curated catalog of public I2P providers. Same shape and intent as
 * `firewall/DnsProvider` — we ship the list, the user picks. We do
 * not host any of these. Each entry's privacyNote is honest and
 * non-marketing.
 *
 * What's bundled:
 *
 * - **Reseed servers** — the bootstrap a fresh I2P router contacts to
 *   learn about peers. The official list is at
 *   https://geti2p.net/en/docs/spec/reseed and rotates rarely. We
 *   ship a snapshot; users can override via the Custom entry.
 * - **HTTP outproxy** — the bridge from I2P-internal traffic to
 *   the regular web. Choosing one means you trust that operator
 *   not to log your queries. Choosing "no outproxy" means your
 *   browser can only reach `.i2p` eepsites.
 *
 * The catalog is intentionally short. Niche / regional / self-hosted
 * is valid but harder to vet at the suite-curation layer; the user
 * picks "Custom" and configures their own.
 */
data class I2pProvider(
    val id: String,
    val name: String,
    /** Reseed bootstrap URL (HTTPS). Used by i2pd at first start. */
    val reseedUrl: String,
    /** HTTP outproxy hostname (eepsite). Empty = no outproxy → eepsites only. */
    val outproxyHost: String,
    /** HTTP outproxy port. Ignored if [outproxyHost] is empty. */
    val outproxyPort: Int,
    /** Honest privacy stance summary. Not marketing. */
    val privacyNote: String,
) {
    companion object {

        val EEPSITES_ONLY = I2pProvider(
            id = "eepsites_only",
            name = "Eepsites only (no outproxy)",
            reseedUrl = "https://reseed.i2p-projekt.de/",
            outproxyHost = "",
            outproxyPort = 0,
            privacyNote = "No HTTP outproxy. Browser can reach .i2p sites; " +
                "regular HTTPS sites simply don't resolve. The strongest " +
                "privacy posture — no exit operator trust required.",
        )

        val STORMYCLOUD = I2pProvider(
            id = "stormycloud",
            name = "stormycloud",
            reseedUrl = "https://reseed.stormycloud.org/",
            outproxyHost = "exit.stormycloud.org",
            outproxyPort = 80,
            privacyNote = "Free outproxy operator since ~2018. No-logging " +
                "policy. Trust assumption: stormycloud's operator. The " +
                "most widely used I2P outproxy at this point.",
        )

        val DIVA_EXCHANGE = I2pProvider(
            id = "diva",
            name = "DIVA.exchange",
            reseedUrl = "https://reseed.diva.exchange/",
            outproxyHost = "exit.diva.i2p",
            outproxyPort = 80,
            privacyNote = "Swiss DIVA project's reseed + community " +
                "outproxy. Smaller exit-bandwidth than stormycloud but " +
                "different operator (some redundancy if one disappears).",
        )

        val PROJEKT = I2pProvider(
            id = "i2p_projekt",
            name = "i2p-projekt (reseed only, no outproxy)",
            reseedUrl = "https://reseed.i2p-projekt.de/",
            outproxyHost = "",
            outproxyPort = 0,
            privacyNote = "Reseed from the upstream I2P project, no " +
                "outproxy configured. Same effect as the eepsites-only " +
                "entry but with the project's reseed instead of mine.",
        )

        val CUSTOM = I2pProvider(
            id = "custom",
            name = "Custom (advanced)",
            reseedUrl = "<your-reseed-url>",
            outproxyHost = "<your-outproxy-host-or-blank>",
            outproxyPort = 0,
            privacyNote = "Power-user entry. Edit the values via the " +
                "advanced config screen. The suite doesn't validate the " +
                "URL or outproxy — you're responsible for trusting them.",
        )

        /** All providers in display order. EEPSITES_ONLY is the safe default. */
        val ALL: List<I2pProvider> = listOf(
            EEPSITES_ONLY,
            STORMYCLOUD,
            DIVA_EXCHANGE,
            PROJEKT,
            CUSTOM,
        )

        fun byId(id: String): I2pProvider =
            ALL.firstOrNull { it.id == id } ?: EEPSITES_ONLY
    }
}
