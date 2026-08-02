package com.understory.godwall.ward

import com.understory.godwall.core.EngineState

/**
 * The health & alerts banner's engine.
 *
 * ## The donors
 *
 * RethinkDNS's home screen carries a rotating warning strip — "another VPN is active",
 * "the firewall is not applying rules", "you have blocked an app you may need". InviZible surfaces
 * module faults the same way. Tailscale reports a conflicting VPN. The banner is the one place a
 * security app is allowed to interrupt, so what goes in it is deliberately narrow: things that
 * make the app's claim about itself untrue, and things the user did that they may not have meant.
 *
 * ## Why this is a pure function
 *
 * Every input is data the caller has already gathered, so the whole rule set is testable off
 * device — which matters because the banner is the surface most likely to be wrong in a way
 * nobody notices. [evaluate] never reads a preference, a package manager or a clock.
 *
 * Order is severity-first and, within a severity, the order of declaration in [HealthAlert] —
 * so the top line of the banner is stable rather than jittering between refreshes.
 */
object HealthCheck {

    enum class Severity { CRITICAL, WARNING, INFO }

    /** Alert identity. The copy lives in `strings_ward.xml`; this carries only the facts. */
    enum class HealthAlert {
        ENGINE_FAILED,
        CONFLICTING_VPN,
        DNS_LEAK,
        SELF_BLOCK,
        FIREWALL_TIER_INERT,
        TAILNET_TIER_INERT,
        REFUSED_DENIALS,
        MITM_USER_CA,
        FILTER_EMPTY,
        PAUSED,
        LOCKDOWN_ON,
        CHILD_LOCK_ON,
    }

    /** One banner line. [args] are formatted into the alert's string by the UI. */
    data class Alert(
        val kind: HealthAlert,
        val severity: Severity,
        val args: List<Any> = emptyList(),
    )

    data class Input(
        val enginePhase: EngineState.Phase,
        val engineDetail: String,
        val mode: WardMode,
        val firewallTierAvailable: Boolean,
        val tailnetTierAvailable: Boolean,
        /** Some other app holds the VPN slot while Godwall does not. */
        val otherVpnActive: Boolean,
        val paused: Boolean,
        val pauseRemainingMs: Long,
        val lockdown: Boolean,
        val userCaCount: Int,
        /** Stored rules that name Godwall's own package. */
        val selfBlockRules: Int,
        /** Stored denials the exemption gate will not apply. */
        val refusedDenials: Int,
        val filterEnabled: Boolean,
        val blocklistDomains: Int,
        val leak: DnsLeak.Verdict,
        val childLockEngaged: Boolean,
    )

    fun evaluate(i: Input): List<Alert> {
        val out = ArrayList<Alert>(4)

        if (i.enginePhase == EngineState.Phase.FAILED) {
            out += Alert(HealthAlert.ENGINE_FAILED, Severity.CRITICAL, listOf(i.engineDetail))
        }
        // Only meaningful while we are NOT holding the slot: if Godwall is up, Godwall has it.
        if (i.otherVpnActive && i.enginePhase != EngineState.Phase.UP) {
            out += Alert(HealthAlert.CONFLICTING_VPN, Severity.CRITICAL)
        }
        if (i.leak == DnsLeak.Verdict.LEAK) {
            out += Alert(HealthAlert.DNS_LEAK, Severity.CRITICAL)
        }
        if (i.selfBlockRules > 0) {
            out += Alert(HealthAlert.SELF_BLOCK, Severity.CRITICAL, listOf(i.selfBlockRules))
        }

        // A mode that asks for a tier this device cannot run is the "it looks on but does
        // nothing" failure the whole banner exists to prevent.
        val unmet = i.mode.unmet(i.firewallTierAvailable, i.tailnetTierAvailable)
        if (WardTier.FIREWALL in unmet) {
            out += Alert(HealthAlert.FIREWALL_TIER_INERT, Severity.WARNING)
        }
        if (WardTier.TAILNET in unmet) {
            out += Alert(HealthAlert.TAILNET_TIER_INERT, Severity.WARNING)
        }
        if (i.refusedDenials > 0) {
            out += Alert(HealthAlert.REFUSED_DENIALS, Severity.WARNING, listOf(i.refusedDenials))
        }
        if (i.userCaCount > 0) {
            out += Alert(HealthAlert.MITM_USER_CA, Severity.WARNING, listOf(i.userCaCount))
        }
        if (i.filterEnabled && i.blocklistDomains == 0) {
            out += Alert(HealthAlert.FILTER_EMPTY, Severity.WARNING)
        }

        if (i.paused) {
            out += Alert(HealthAlert.PAUSED, Severity.INFO, listOf(i.pauseRemainingMs))
        }
        if (i.lockdown) {
            out += Alert(HealthAlert.LOCKDOWN_ON, Severity.INFO)
        }
        if (i.childLockEngaged) {
            out += Alert(HealthAlert.CHILD_LOCK_ON, Severity.INFO)
        }

        return out.sortedWith(
            compareBy({ it.severity.ordinal }, { it.kind.ordinal }),
        )
    }

    /** The worst severity present, or null when the banner should read "operating normally". */
    fun worst(alerts: List<Alert>): Severity? = alerts.minByOrNull { it.severity.ordinal }?.severity
}
