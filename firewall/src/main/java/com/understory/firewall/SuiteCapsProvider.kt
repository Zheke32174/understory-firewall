package com.understory.firewall

import com.understory.security.BaseCapabilityProvider

/**
 * firewall's capability beacon (design-v2/firewall.md §10.5). Consumers
 * translate `(com.understory.firewall, version=1)` into
 * [com.understory.security.SuiteCapability.NET_POSTURE_AUDIT] via their
 * KNOWN_PEERS table — the honest, rootless "audits network posture and
 * advises; never intercepts packets" role.
 *
 * The app may only claim a filter-class capability while
 * `mode == STANDALONE && engine armed` — a state that is permanently
 * unreachable on a Tailscale device (the VpnSlotProbe guardrail keeps the
 * slot ceded). Because that state never occurs on the reference device, the
 * beacon truthfully advertises NET_POSTURE_AUDIT and nothing more. Bumping
 * [providedVersion] to a version that maps to a filter-class capability is
 * deferred until a genuinely armed peer-invocable surface ships (BEACON-1).
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
