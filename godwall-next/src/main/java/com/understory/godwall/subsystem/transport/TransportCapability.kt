package com.understory.godwall.subsystem.transport

import com.understory.godwall.R

/**
 * What the transport/proxy stack exposes, modelled so a capability can never lie.
 *
 * The prime directive of this campaign (docs/DONOR-ASSETS.md): a capability whose payload or
 * privilege is absent must REPORT absent — a disabled control next to a sentence naming exactly what
 * is missing — and must never draw an enabled control it cannot back. This file encodes that as a
 * type, not a convention: every capability declares what BACKS it, and the backing is the only thing
 * that decides whether its control is enabled.
 *
 * Two kinds of backing, and nothing else:
 *
 * - [TransportBacking.Service] — a real supervised daemon. The capability's status is exactly that
 *   daemon's status. When the daemon's ELF is not in the prefix (the clean-checkout case, since a
 *   stock Termux bootstrap carries neither sing-box nor v2ray), the [com.understory.godwall.subsystem.Supervisor]
 *   reports ABSENT and the control is disabled. Shadowsocks shares sing-box's fate because it is one
 *   of sing-box's outbound protocols, not a separate daemon — the same "several facets, one process"
 *   shape WP-3 uses for DoH/ODoH/DNSCrypt over dnscrypt-proxy. Its reach sentence states plainly
 *   that "running" means the backend that speaks the protocol is up, and that the route through a
 *   Shadowsocks server is one you configure — so LIVE never implies a remote tunnel this
 *   socket-space package cannot verify.
 *
 * - [TransportBacking.Gated] — structurally not in this package, regardless of payload. WireGuard as
 *   a chain hop and proxychains-style chaining are gated with a fixed sentence and are never enabled
 *   here. WireGuard's canonical hop backend in this repo is firestack's `backend.WgKey`
 *   (docs/FIRESTACK-LINKING.md), a packet-level tun2socks data plane that is not wired into this
 *   build; the standalone wireguard-go path needs that same data plane to steer flows into the
 *   tunnel. proxychains is superseded by Godwall's own [com.understory.godwall.chain.ChainDialer],
 *   which composes SOCKS5/HTTP hops in userspace, and would in any case need a user shell Godwall
 *   deliberately does not expose. Both exist in the model so the surface can show them honestly as
 *   "not in this build" rather than omit them and leave the user wondering.
 */
internal data class TransportCapability(
    /** Stable identity for the capability, distinct from any service id. */
    val id: String,
    /** String resource for the control's title. */
    val titleRes: Int,
    /** String resource for the one sentence stating this control's REACH. Always shown. */
    val reachRes: Int,
    /** What decides whether this control is enabled — the only such decider. */
    val backing: TransportBacking,
)

/** How a [TransportCapability] is backed, which is the only thing that gates it. */
internal sealed interface TransportBacking {

    /** Backed by a supervised daemon; status mirrors that service exactly. */
    data class Service(val serviceId: String) : TransportBacking

    /**
     * Not in this package at all. [sentenceRes] is the exact, fixed sentence shown next to the
     * permanently disabled control — it must name precisely what is missing and where the real thing
     * would come from.
     */
    data class Gated(val sentenceRes: Int) : TransportBacking
}

/**
 * The coarse status the UI needs to decide enabled-vs-disabled and which colour to show. The exact,
 * dynamic reason always travels alongside as a sentence in [TransportCapabilityState.detail]; this
 * enum is only the bucket. Kept identical in shape to WP-3's DnsCapabilityStatus so a single surface
 * can render both without special-casing.
 */
internal enum class TransportCapabilityStatus {
    /** Backed and confirmed running now. */
    LIVE,

    /** Backed and present, but not currently confirmed running — the control is enabled. */
    READY,

    /** Running, but a health probe failed: up and not doing its job. Control enabled to fix it. */
    DEGRADED,

    /** The payload that backs this is not in this build. Control DISABLED, with a sentence. */
    ABSENT,

    /** Structurally not in this package. Control DISABLED, with a fixed sentence. */
    GATED,

    /** No privileged shell, so the prefix is unreadable and the state is genuinely unknown. */
    UNKNOWN,
    ;

    /** Whether the UI should render this capability's control as enabled. */
    val controlEnabled: Boolean get() = this == LIVE || this == READY || this == DEGRADED
}

/**
 * A capability resolved against the live world: its coarse [status], the one honest [detail]
 * sentence for that status, and whether its control is enabled. Built by [TransportStack]; this is
 * what a surface renders.
 */
internal data class TransportCapabilityState(
    val capability: TransportCapability,
    val status: TransportCapabilityStatus,
    val detail: String,
) {
    val controlEnabled: Boolean get() = status.controlEnabled
}

/**
 * The catalog. Order is the order a surface should list them: the daemon-backed backends first,
 * then the shared-daemon protocol facet, then the two honestly-gated rows last.
 */
internal object TransportCapabilities {

    // ---- Backed by a supervised daemon -------------------------------------------------

    val singBox = TransportCapability(
        id = "sing-box",
        titleRes = R.string.transport_cap_singbox_title,
        reachRes = R.string.transport_cap_singbox_reach,
        backing = TransportBacking.Service(TransportServices.ID_SINGBOX),
    )

    val v2ray = TransportCapability(
        id = "v2ray",
        titleRes = R.string.transport_cap_v2ray_title,
        reachRes = R.string.transport_cap_v2ray_reach,
        backing = TransportBacking.Service(TransportServices.ID_V2RAY),
    )

    /**
     * Shadowsocks is an outbound protocol of the sing-box backend, so it shares that daemon's fate
     * rather than pretending to be an independently toggleable process — exactly WP-3's DoH-over-
     * dnscrypt-proxy shape. Its reach sentence makes "LIVE" mean "the backend that speaks
     * Shadowsocks is running", never "your Shadowsocks server is connected".
     */
    val shadowsocks = TransportCapability(
        id = "shadowsocks",
        titleRes = R.string.transport_cap_shadowsocks_title,
        reachRes = R.string.transport_cap_shadowsocks_reach,
        backing = TransportBacking.Service(TransportServices.ID_SINGBOX),
    )

    // ---- Honestly gated: not in this build ---------------------------------------------

    val wireguard = TransportCapability(
        id = "wireguard",
        titleRes = R.string.transport_cap_wireguard_title,
        reachRes = R.string.transport_cap_wireguard_reach,
        backing = TransportBacking.Gated(R.string.transport_gate_wireguard),
    )

    val proxychains = TransportCapability(
        id = "proxychains",
        titleRes = R.string.transport_cap_proxychains_title,
        reachRes = R.string.transport_cap_proxychains_reach,
        backing = TransportBacking.Gated(R.string.transport_gate_proxychains),
    )

    val all: List<TransportCapability> = listOf(
        singBox, v2ray, shadowsocks,
        wireguard, proxychains,
    )
}
