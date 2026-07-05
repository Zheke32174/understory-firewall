package com.understory.firewall

/**
 * Which flavor of the slot-consuming Standalone tunnel is active when the
 * engine is armed (design-v2/firewall.md §6, S6). BOTH take the one VPN slot
 * and are gated by [VpnSlotProbe] + XOR-Tailscale — the difference is only what
 * the tun DOES:
 *
 *   APP_DROP    — the legacy Stage app-drop engine: captures the restricted
 *                 apps and silently drops their packets. No DNS filtering, no
 *                 routing, no per-domain rules. (Kept: it is the simplest honest
 *                 "block these apps entirely" tunnel.)
 *
 *   DNS_FILTER  — the S6 adblock-DNS tunnel: captures DNS on the tun, sinkholes
 *                 ad/tracker/malware domains against the on-device blocklist,
 *                 forwards allowed queries to the upstream resolver, attributes
 *                 each query to its app, and logs it for the visibility screen.
 *                 This is the achievable "firewall VPN tunnel" core.
 *
 * DNS_FILTER is the default flavor for the tunnel tier (the honest headline
 * feature). Persisted in [FirewallSettings].
 */
enum class TunnelMode { APP_DROP, DNS_FILTER }
