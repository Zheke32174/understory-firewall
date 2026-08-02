package com.understory.godwall.subsystem.dns

import com.understory.godwall.R

/**
 * What the DNS stack exposes, modelled so a capability can never lie.
 *
 * The prime directive of this campaign (docs/DONOR-ASSETS.md): a capability whose payload or
 * privilege is absent must REPORT absent — a disabled control next to a sentence naming exactly
 * what is missing — and must never draw an enabled control it cannot back. This file encodes
 * that as a type, not a convention: every capability declares what BACKS it, and the backing is
 * the only thing that decides whether its control is enabled.
 *
 * Two kinds of backing, and nothing else:
 *
 * - [DnsBacking.Service] — a real supervised daemon. The capability's status is exactly that
 *   daemon's status. When the daemon's ELF is not in the prefix (the clean-checkout case, since
 *   a stock Termux bootstrap carries neither dnscrypt-proxy nor dnsmasq), the Supervisor reports
 *   ABSENT and the control is disabled. Several capabilities share one daemon — DoH, ODoH,
 *   DNSCrypt, the anonymized relays and the DNSSEC/no-log/no-filter floor are all facets of the
 *   single dnscrypt-proxy process configured by its toml, so they share its fate rather than
 *   pretending to be independently toggleable. That is the point: none of them is a separate
 *   switch with nothing behind it.
 *
 * - [DnsBacking.Gated] — structurally not in this package, regardless of payload. DoT (which
 *   dnscrypt-proxy does not speak) and system-wide leak-prevention enforcement (a tun/netfilter
 *   redirect, not a socket-space concern) are gated with a fixed sentence and are never enabled
 *   here. They exist in the model so the surface can show them honestly as "not in this build",
 *   rather than omit them and leave the user wondering.
 */
internal data class DnsCapability(
    /** Stable identity for the capability, distinct from any service id. */
    val id: String,
    /** String resource for the control's title. */
    val titleRes: Int,
    /** String resource for the one sentence stating this control's REACH. Always shown. */
    val reachRes: Int,
    /** What decides whether this control is enabled — the only such decider. */
    val backing: DnsBacking,
)

/** How a [DnsCapability] is backed, which is the only thing that gates it. */
internal sealed interface DnsBacking {

    /** Backed by a supervised daemon; status mirrors that service exactly. */
    data class Service(val serviceId: String) : DnsBacking

    /**
     * Not in this package at all. [sentenceRes] is the exact, fixed sentence shown next to the
     * permanently disabled control — it must name precisely what is missing and where the real
     * thing would come from.
     */
    data class Gated(val sentenceRes: Int) : DnsBacking
}

/**
 * The coarse status the UI needs to decide enabled-vs-disabled and which colour to show. The
 * exact, dynamic reason always travels alongside as a sentence in [DnsCapabilityState.detail];
 * this enum is only the bucket.
 */
internal enum class DnsCapabilityStatus {
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
 * sentence for that status, and whether its control is enabled. Built by [DnsStack]; this is
 * what a surface renders.
 */
internal data class DnsCapabilityState(
    val capability: DnsCapability,
    val status: DnsCapabilityStatus,
    val detail: String,
) {
    val controlEnabled: Boolean get() = status.controlEnabled
}

/**
 * The catalog. Order is the order a surface should list them: the encrypted transports first
 * (all backed by dnscrypt-proxy), then the front-end's cache/guard facets (backed by dnsmasq),
 * then the two honestly-gated rows last.
 */
internal object DnsCapabilities {

    // ---- Backed by dnscrypt-proxy ------------------------------------------------------

    val dnscrypt = DnsCapability(
        id = "dnscrypt",
        titleRes = R.string.dns_cap_dnscrypt_title,
        reachRes = R.string.dns_cap_dnscrypt_reach,
        backing = DnsBacking.Service(DnsServices.ID_DNSCRYPT),
    )

    val relays = DnsCapability(
        id = "anon-relays",
        titleRes = R.string.dns_cap_relays_title,
        reachRes = R.string.dns_cap_relays_reach,
        backing = DnsBacking.Service(DnsServices.ID_DNSCRYPT),
    )

    val doh = DnsCapability(
        id = "doh",
        titleRes = R.string.dns_cap_doh_title,
        reachRes = R.string.dns_cap_doh_reach,
        backing = DnsBacking.Service(DnsServices.ID_DNSCRYPT),
    )

    val odoh = DnsCapability(
        id = "odoh",
        titleRes = R.string.dns_cap_odoh_title,
        reachRes = R.string.dns_cap_odoh_reach,
        backing = DnsBacking.Service(DnsServices.ID_DNSCRYPT),
    )

    val dnssec = DnsCapability(
        id = "dnssec-floor",
        titleRes = R.string.dns_cap_dnssec_title,
        reachRes = R.string.dns_cap_dnssec_reach,
        backing = DnsBacking.Service(DnsServices.ID_DNSCRYPT),
    )

    // ---- Backed by dnsmasq -------------------------------------------------------------

    val cache = DnsCapability(
        id = "cache",
        titleRes = R.string.dns_cap_cache_title,
        reachRes = R.string.dns_cap_cache_reach,
        backing = DnsBacking.Service(DnsServices.ID_DNSMASQ),
    )

    val rebind = DnsCapability(
        id = "rebind",
        titleRes = R.string.dns_cap_rebind_title,
        reachRes = R.string.dns_cap_rebind_reach,
        backing = DnsBacking.Service(DnsServices.ID_DNSMASQ),
    )

    val noLeakPath = DnsCapability(
        id = "no-leak-path",
        titleRes = R.string.dns_cap_noleak_title,
        reachRes = R.string.dns_cap_noleak_reach,
        backing = DnsBacking.Service(DnsServices.ID_DNSMASQ),
    )

    // ---- Honestly gated: not in this package -------------------------------------------

    val dot = DnsCapability(
        id = "dot",
        titleRes = R.string.dns_cap_dot_title,
        reachRes = R.string.dns_cap_dot_reach,
        backing = DnsBacking.Gated(R.string.dns_gate_dot),
    )

    val leakEnforcement = DnsCapability(
        id = "leak-enforcement",
        titleRes = R.string.dns_cap_leak_enforce_title,
        reachRes = R.string.dns_cap_leak_enforce_reach,
        backing = DnsBacking.Gated(R.string.dns_gate_leak_enforce),
    )

    val all: List<DnsCapability> = listOf(
        dnscrypt, relays, doh, odoh, dnssec,
        cache, rebind, noLeakPath,
        dot, leakEnforcement,
    )
}
