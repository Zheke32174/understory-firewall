package com.understory.firewall

import android.content.Context

/**
 * Single source of truth for "what every setting defaults to" and a one-call
 * reset to those base-app values.
 *
 * Design rule (per the product ask): EVERY setting has a working default — the
 * base-app value — and every one is user-changeable. The individual settings
 * objects (FirewallSettings, BlocklistRepository, DnscryptResolvers, AnonRouting,
 * PcapController, TailscaleSettings, …) each encode their own default in their
 * getter (so a fresh install, or a cleared store, is immediately valid). This
 * object is the auditable CATALOG of those defaults plus [restoreDefaults], which
 * clears every firewall-owned preference store so every getter falls back to the
 * documented default.
 *
 * [restoreDefaults] is a FULL reset: it also clears user-curated data (flagged
 * apps, custom block/allow domains, saved egress chain). The UI states that.
 */
object FirewallDefaults {

    /** One documented default. [store] is the SharedPreferences file it lives in. */
    data class Default(val store: String, val setting: String, val value: String, val note: String)

    /** Every firewall preference store (each getter defaults when the store is empty). */
    val STORES = listOf(
        "firewall_settings",
        "firewall_dns_filter",
        "firewall_dnscrypt",
        "firewall_anon",
        "firewall_pcap",
        "firewall_tailscale",
        "firewall_chain",
        "firewall_policy",
        "arp_guard",
        "arp_guard_watch",
        "posture_watch",
    )

    /**
     * The base-app default for every user-facing setting, grouped by store. This
     * is documentation the "Defaults" surface renders and the audit reads; the
     * live defaults are enforced by each settings object's getter, not here.
     */
    val CATALOG: List<Default> = listOf(
        // Core mode / engine
        Default("firewall_settings", "Mode", "Companion", "Observe/advise only; never takes the VPN slot."),
        Default("firewall_settings", "Engine armed", "off", "Standalone blocking is opt-in."),
        Default("firewall_settings", "Tunnel flavor", "DNS filter", "The adblock-DNS tunnel is the headline tunnel."),
        Default("firewall_settings", "Upstream resolver IP", "1.1.1.1", "Cloudflare, used when no hostname is set."),
        Default("firewall_settings", "Upstream transport", "DoT (when a hostname is set)", "Blank hostname = plaintext UDP."),
        Default("firewall_settings", "DoH path", "/dns-query", "Only used in DoH mode."),
        Default("firewall_settings", "DNS provider (system Private DNS)", "System default", "No override applied."),
        Default("firewall_settings", "New-app install notify", "on", "Alert when a new app is installed."),
        Default("firewall_settings", "New-app auto-block", "off", "Silent connectivity change is opt-in."),
        // Blocklist
        Default("firewall_dns_filter", "DNS filter", "on", "Sinkhole ads/trackers when the tunnel runs."),
        Default("firewall_dns_filter", "Blocklist update URL", "(none)", "Bundled curated seed until a URL is added."),
        Default("firewall_dns_filter", "Sinkhole answer", "NXDOMAIN", "Cleanest block; 0.0.0.0 is the alternative."),
        // DNSCrypt
        Default("firewall_dnscrypt", "Use DNSCrypt", "off", "Base app keeps its plaintext/DoT upstream."),
        Default("firewall_dnscrypt", "Selected resolver", "(auto default)", "A no-log DNSSEC DNSCrypt resolver if none chosen."),
        Default("firewall_dnscrypt", "Require no-logs", "on", "Privacy-first filter."),
        Default("firewall_dnscrypt", "Require DNSSEC", "on", "Validated answers only."),
        Default("firewall_dnscrypt", "Require unfiltered", "off", "Many good resolvers block malware."),
        Default("firewall_dnscrypt", "Anonymizing relay", "none", "Optional Anonymized-DNSCrypt relay; direct by default."),
        // Anonymized routing
        Default("firewall_anon", "Route DNS through proxy", "off", "Tor/I2P DNS routing is opt-in."),
        Default("firewall_anon", "Proxy mode", "Tor", "Orbot SOCKS 127.0.0.1:9050."),
        Default("firewall_anon", "Custom SOCKS host", "127.0.0.1", "Only for custom mode."),
        Default("firewall_anon", "Custom SOCKS port", "1080", "Only for custom mode."),
        Default("firewall_anon", "Target resolver via proxy", "1.1.1.1", "DNS-over-TCP endpoint inside the proxy."),
        // PCAP
        Default("firewall_pcap", "Capture", "off", "Records tun packets only when on."),
        // Tailscale
        Default("firewall_tailscale", "Bring up tailnet", "off", "Node backend is a seam until libtailscale lands."),
        Default("firewall_tailscale", "Control server",
            com.understory.firewall.tailscale.TailscaleSettings.DEFAULT_LOGIN_SERVER, "Overridable for Headscale."),
        Default("firewall_tailscale", "Accept subnet routes", "on", ""),
        Default("firewall_tailscale", "Accept MagicDNS", "on", ""),
        Default("firewall_tailscale", "Advertise exit node", "off", ""),
        // Egress chain
        Default("firewall_chain", "Apply chain to egress", "off", "Direct egress by default."),
        Default("firewall_chain", "Hops", "(none)", "Empty chain = direct."),
    )

    /** Reset every firewall-owned setting to its base-app default (full reset). */
    fun restoreDefaults(ctx: Context) {
        for (store in STORES) {
            runCatching { ctx.getSharedPreferences(store, Context.MODE_PRIVATE).edit().clear().apply() }
        }
        // Re-stamp the V2 migration guard so the (now-cleared) settings store isn't
        // treated as a legacy v1 install on next launch.
        runCatching { FirewallSettings.migrateV2IfNeeded(ctx) }
    }
}
