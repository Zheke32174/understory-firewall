package com.understory.firewall

/**
 * DNS provider catalog. Each entry carries the data needed to either
 * surface to Android's system Private DNS settings (the [dotHostname])
 * or wire into our own tun-level DNS forwarding (the IPv4/IPv6
 * addresses, when phase-2 forwarding lands).
 *
 * Privacy notes for each provider come from each operator's stated
 * policy at the time of writing. They're not endorsements; the user
 * makes the trust call. We surface the policy stance because this is
 * specifically a sovereignty-flavored choice — *who* sees your DNS
 * queries matters as much as whether they're encrypted.
 *
 * The list is intentionally short and well-known. Niche / regional /
 * self-hosted resolvers are valid choices but harder to vet at the
 * suite-curation layer; users can pick "Custom" and enter their own.
 */
/** Transport that the firewall uses to talk to the resolver. */
enum class DnsProtocol {
    /** Plain UDP/TCP port 53. Cleartext on the wire. */
    PLAIN,
    /** DNS-over-TLS, RFC 7858. Android natively supports this via the
     *  system Private DNS toggle; provided dotHostname is what the user
     *  pastes there (or what we set via Settings.Global). */
    DOT,
    /** DNSCrypt v2. Requires the bundled dnscrypt-proxy binary to be
     *  available + a stamp identifying the upstream resolver. The stamp
     *  is the standard sdns:// URI from the public-resolvers list at
     *  https://download.dnscrypt.info/resolvers-list/. */
    DNSCRYPT,
}

data class DnsProvider(
    val id: String,
    val name: String,
    /** Transport this entry expects. PLAIN/DOT use ipv4/ipv6/dotHostname.
     *  DNSCRYPT uses [dnscryptStamp] and routes via the bundled proxy. */
    val protocol: DnsProtocol = DnsProtocol.DOT,
    /** Hostname for DoT (Android system Private DNS field). */
    val dotHostname: String,
    /** IPv4 addresses for direct UDP/TCP DNS — used by phase-2 tun forwarding. */
    val ipv4: List<String>,
    /** IPv6 addresses for the same. */
    val ipv6: List<String>,
    /** sdns:// stamp for DNSCrypt providers; empty for non-DNSCrypt. */
    val dnscryptStamp: String = "",
    /** Short privacy stance summary. Honest, not marketing. */
    val privacyNote: String,
) {
    companion object {

        val SYSTEM_DEFAULT = DnsProvider(
            id = "system",
            name = "System default",
            dotHostname = "",
            ipv4 = emptyList(),
            ipv6 = emptyList(),
            privacyNote = "No override — apps use whatever DNS the device's network " +
                "is configured for. Usually your carrier or Wi-Fi router. " +
                "Cleartext DNS over UDP unless something else encrypts it.",
        )

        val CLOUDFLARE = DnsProvider(
            id = "cloudflare",
            name = "Cloudflare 1.1.1.1",
            dotHostname = "1dot1dot1dot1.cloudflare-dns.com",
            ipv4 = listOf("1.1.1.1", "1.0.0.1"),
            ipv6 = listOf("2606:4700:4700::1111", "2606:4700:4700::1001"),
            privacyNote = "Logs queries for 24h then aggregates. No selling, " +
                "audited annually. Fast worldwide. Trust assumption: " +
                "Cloudflare itself.",
        )

        val QUAD9 = DnsProvider(
            id = "quad9",
            name = "Quad9 9.9.9.9",
            dotHostname = "dns.quad9.net",
            ipv4 = listOf("9.9.9.9", "149.112.112.112"),
            ipv6 = listOf("2620:fe::fe", "2620:fe::9"),
            privacyNote = "Swiss non-profit, no logging by policy. Filters " +
                "known-malicious domains by default (threat intel from " +
                "multiple feeds). The strongest privacy posture among the " +
                "free options.",
        )

        val GOOGLE = DnsProvider(
            id = "google",
            name = "Google 8.8.8.8",
            dotHostname = "dns.google",
            ipv4 = listOf("8.8.8.8", "8.8.4.4"),
            ipv6 = listOf("2001:4860:4860::8888", "2001:4860:4860::8844"),
            privacyNote = "Logs full query data temporarily, aggregates " +
                "longer-term. Fast, ubiquitous. Trust assumption: Google. " +
                "If you avoid Google services, this defeats the purpose.",
        )

        val OPENDNS = DnsProvider(
            id = "opendns",
            name = "OpenDNS",
            dotHostname = "dns.opendns.com",
            ipv4 = listOf("208.67.222.222", "208.67.220.220"),
            ipv6 = listOf("2620:119:35::35", "2620:119:53::53"),
            privacyNote = "Owned by Cisco. Filters phishing/malware by default. " +
                "Logs queries; commercial product (Umbrella) for enterprise. " +
                "Trust assumption: Cisco.",
        )

        val NEXTDNS = DnsProvider(
            id = "nextdns",
            name = "NextDNS (custom config)",
            dotHostname = "<your-config>.dns.nextdns.io",
            ipv4 = listOf("45.90.28.0", "45.90.30.0"),
            ipv6 = listOf("2a07:a8c0::", "2a07:a8c1::"),
            privacyNote = "Per-user filtering rules, no logs by default. " +
                "Requires a free account to get a config ID. Replace the " +
                "placeholder in the hostname with your config. Most " +
                "configurable; trust assumption: NextDNS Inc.",
        )

        // ---------- DNSCrypt providers ----------
        // Stamps come from the upstream public-resolvers list:
        //   https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md
        // We snapshot a few well-known ones; users can add Custom via
        // the proxy's own config (a follow-up commit will surface that).

        val DNSCRYPT_QUAD9 = DnsProvider(
            id = "dnscrypt-quad9",
            name = "Quad9 (DNSCrypt)",
            protocol = DnsProtocol.DNSCRYPT,
            dotHostname = "",
            ipv4 = emptyList(),
            ipv6 = emptyList(),
            dnscryptStamp = "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO" +
                "-eWNSWaEPI2jEIWcVyt53wFVlIiIyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
            privacyNote = "Same Quad9 backbone as the DoT entry above, but " +
                "via the DNSCrypt v2 protocol through the bundled proxy. " +
                "Same threat-feed blocking, no-log policy. Routed locally " +
                "via 127.0.0.1 once the proxy is active.",
        )

        val DNSCRYPT_ADGUARD = DnsProvider(
            id = "dnscrypt-adguard",
            name = "AdGuard (DNSCrypt)",
            protocol = DnsProtocol.DNSCRYPT,
            dotHostname = "",
            ipv4 = emptyList(),
            ipv6 = emptyList(),
            dnscryptStamp = "sdns://AQMAAAAAAAAAFFs5NDolbjU3OjIzZThdOjUxNDMgyfXt" +
                "1nuNjmPpkF50KPLAd4PhQrrfYZD7yeMQbCKQEZkbMi5kbnNjcnlwdC51bmZpbHRlcmVkLm5z" +
                "MS5hZGd1YXJkLmNvbQ",
            privacyNote = "AdGuard's unfiltered DNS over DNSCrypt v2. No " +
                "ad-blocking, no malware-blocking — that's by design for " +
                "the unfiltered variant. Logs minimal anonymized data per " +
                "their stated policy.",
        )

        val DNSCRYPT_CISCO = DnsProvider(
            id = "dnscrypt-cisco",
            name = "Cisco OpenDNS (DNSCrypt)",
            protocol = DnsProtocol.DNSCRYPT,
            dotHostname = "",
            ipv4 = emptyList(),
            ipv6 = emptyList(),
            dnscryptStamp = "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJd" +
                "PivYItf9cL4qfP493hyEhw7BrJAa8MISGjIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
            privacyNote = "Cisco-operated; DNSCrypt v2 transport. Filters " +
                "phishing/malware by default. Logs queries per Cisco's " +
                "Umbrella policy. Trust assumption: Cisco.",
        )

        /** All providers in display order. SYSTEM_DEFAULT is always first. */
        val ALL: List<DnsProvider> = listOf(
            SYSTEM_DEFAULT,
            CLOUDFLARE,
            QUAD9,
            GOOGLE,
            OPENDNS,
            NEXTDNS,
            DNSCRYPT_QUAD9,
            DNSCRYPT_ADGUARD,
            DNSCRYPT_CISCO,
        )

        fun byId(id: String): DnsProvider =
            ALL.firstOrNull { it.id == id } ?: SYSTEM_DEFAULT
    }
}
