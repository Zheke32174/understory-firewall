package com.understory.firewall

import android.content.Context
import com.understory.security.Diagnostics

/** Tri-state for a fact we can read, can't read, or read as absent. */
enum class Tri { YES, NO, UNKNOWN }

/**
 * Pure read-model of the device's tunnel posture (design-v2/firewall.md
 * §5.1). Every field traces to a rootless read; anything unreadable
 * degrades to [Tri.UNKNOWN]/null and never throws. This is the honest
 * replacement for the old inverted "preempted" banner.
 */
data class TunnelPosture(
    val tailscaleInstalled: Boolean,   // getPackageInfo != null
    val tailscaleVersion: String?,     // best-effort
    val aVpnIsUp: Tri,                 // TRANSPORT_VPN on any network
    val alwaysOnApp: String?,          // Settings.Secure, may be null
    val alwaysOnIsTailscale: Tri,      // alwaysOnApp == com.tailscale.ipn
    val lockdown: Tri,                 // always_on_vpn_lockdown == 1
) {
    /** The overall verdict chip ladder (§5.1). Never green on an inference
     *  gap (CD-4d): any UNKNOWN that would block a green keeps it non-green. */
    enum class Verdict { NO_TAILSCALE, STRONG, HARDENING, INSTALLED_NO_VPN, UNKNOWN }

    val verdict: Verdict
        get() = when {
            !tailscaleInstalled -> Verdict.NO_TAILSCALE
            aVpnIsUp == Tri.YES && alwaysOnIsTailscale == Tri.YES && lockdown == Tri.YES ->
                Verdict.STRONG
            aVpnIsUp == Tri.YES -> Verdict.HARDENING
            aVpnIsUp == Tri.NO -> Verdict.INSTALLED_NO_VPN
            else -> Verdict.UNKNOWN
        }

    companion object {
        /**
         * Compute the live posture. All reads wrapped; logs to Diagnostics
         * on failure and degrades — never throws. Refresh on ON_START and
         * on an explicit "Re-check"; no background polling.
         */
        fun read(ctx: Context): TunnelPosture {
            val installed = VpnSlotProbe.isInstalled(ctx, VpnSlotProbe.TAILSCALE_PKG)
            val version = if (installed)
                VpnSlotProbe.versionName(ctx, VpnSlotProbe.TAILSCALE_PKG) else null

            val vpnUp: Tri = runCatching {
                if (VpnSlotProbe.isAnotherVpnActive(ctx)) Tri.YES else Tri.NO
            }.getOrElse {
                Diagnostics.error("firewall.TunnelPosture", "vpnUp read failed: ${it.message}")
                Tri.UNKNOWN
            }

            val alwaysOn = VpnSlotProbe.alwaysOnVpnApp(ctx)
            val alwaysOnIsTs: Tri = when {
                alwaysOn == null -> Tri.UNKNOWN
                alwaysOn == VpnSlotProbe.TAILSCALE_PKG -> Tri.YES
                else -> Tri.NO
            }
            val lockdown: Tri = when (VpnSlotProbe.alwaysOnLockdown(ctx)) {
                true -> Tri.YES
                false -> Tri.NO
                null -> Tri.UNKNOWN
            }

            return TunnelPosture(
                tailscaleInstalled = installed,
                tailscaleVersion = version,
                aVpnIsUp = vpnUp,
                alwaysOnApp = alwaysOn,
                alwaysOnIsTailscale = alwaysOnIsTs,
                lockdown = lockdown,
            )
        }
    }
}
