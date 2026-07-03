package com.understory.firewall

/**
 * DNS provider catalog. Each entry carries the DoT hostname the user
 * surfaces to Android's system Private DNS (the [dotHostname]).
 *
 * V2 (design-v2/firewall.md §5.3, A8): DNSCrypt is DROPPED. The bundled
 * dnscrypt-proxy could never be queried without a tun, and the binary was
 * never in the repo. The enforced path is DoT via system Private DNS; the
 * empirical check is the DNS canary (CanaryScreen). Only DoT entries remain.
 *
 * Privacy notes come from each operator's stated policy. They're not
 * endorsements; the user makes the trust call. We surface the policy
 * stance because this is a sovereignty-flavored choice — *who* sees your
 * DNS queries matters as much as whether they're encrypted.
 */
data class DnsProvider(
    val id: String,
    val name: String,
    /** Hostname for DoT (Android system Private DNS field). Empty for
     *  SYSTEM_DEFAULT and for NextDNS until a config id is supplied. */
    val dotHostname: String,
    /**
     * True for NextDNS: [dotHostname] is empty and the applied specifier
     * is templated from a user-entered config id via [nextDnsHostname].
     * The Apply control stays disabled-with-reason until the id is valid.
     */
    val requiresConfigId: Boolean = false,
    /** Short privacy stance summary. Honest, not marketing. */
    val privacyNote: String,
) {
    companion object {

        val SYSTEM_DEFAULT = DnsProvider(
            id = "system",
            name = "System default",
            dotHostname = "",
            privacyNote = "No override — apps use whatever DNS the device's network " +
                "is configured for. Usually your carrier or Wi-Fi router. " +
                "Cleartext DNS over UDP unless something else encrypts it.",
        )

        val CLOUDFLARE = DnsProvider(
            id = "cloudflare",
            name = "Cloudflare 1.1.1.1",
            dotHostname = "1dot1dot1dot1.cloudflare-dns.com",
            privacyNote = "Logs queries for 24h then aggregates. No selling, " +
                "audited annually. Fast worldwide. Trust assumption: Cloudflare itself.",
        )

        val QUAD9 = DnsProvider(
            id = "quad9",
            name = "Quad9 9.9.9.9",
            dotHostname = "dns.quad9.net",
            privacyNote = "Swiss non-profit, no logging by policy. Filters " +
                "known-malicious domains by default. The strongest privacy " +
                "posture among the free options.",
        )

        val GOOGLE = DnsProvider(
            id = "google",
            name = "Google 8.8.8.8",
            dotHostname = "dns.google",
            privacyNote = "Logs full query data temporarily, aggregates " +
                "longer-term. Fast, ubiquitous. Trust assumption: Google. " +
                "If you avoid Google services, this defeats the purpose.",
        )

        val OPENDNS = DnsProvider(
            id = "opendns",
            name = "OpenDNS",
            dotHostname = "dns.opendns.com",
            privacyNote = "Owned by Cisco. Filters phishing/malware by default. " +
                "Logs queries; commercial product (Umbrella) for enterprise. " +
                "Trust assumption: Cisco.",
        )

        val NEXTDNS = DnsProvider(
            id = "nextdns",
            name = "NextDNS (custom config)",
            dotHostname = "",
            requiresConfigId = true,
            privacyNote = "Per-user filtering rules, no logs by default. Requires " +
                "a free account to get a config ID. Enter your config ID below; " +
                "the specifier becomes <id>.dns.nextdns.io. Most configurable; " +
                "trust assumption: NextDNS Inc.",
        )

        /**
         * Build the NextDNS DoT specifier from a user config id. The id is
         * hex (`[a-f0-9]{6,}`); the caller only enables Apply once
         * [isValidNextDnsConfigId] passes, so this never produces the old
         * `<your-config>` appliable-garbage specifier (D11).
         */
        fun nextDnsHostname(configId: String): String =
            "${configId.trim().lowercase()}.dns.nextdns.io"

        /** A NextDNS config id is 6+ hex chars. */
        fun isValidNextDnsConfigId(configId: String): Boolean =
            configId.trim().lowercase().matches(Regex("[a-f0-9]{6,}"))

        /** All providers in display order. SYSTEM_DEFAULT is always first. */
        val ALL: List<DnsProvider> = listOf(
            SYSTEM_DEFAULT,
            CLOUDFLARE,
            QUAD9,
            GOOGLE,
            OPENDNS,
            NEXTDNS,
        )

        fun byId(id: String): DnsProvider =
            ALL.firstOrNull { it.id == id } ?: SYSTEM_DEFAULT
    }
}
