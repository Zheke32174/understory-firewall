package com.understory.firewall

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.provider.Settings
import com.understory.security.Diagnostics

/**
 * The hard guardrail (design-v2/firewall.md §4): detect an active VPN and
 * refuse to start the Standalone engine so the app NEVER evicts the
 * incumbent tunnel (Tailscale on the operator's phone).
 *
 * Two independent checks combine into a [VpnSlotState]. **Check 1 is the
 * veto** — if a VPN network exists, we FAIL regardless of Check 2.
 * Fail-closed: any exception in Check 1 ⇒ FAIL (assume an incumbent). A
 * false refusal costs a no-VPN user one retry; a false PASS could evict
 * Tailscale — the one thing the doctrine forbids.
 *
 * This file is Companion-safe: it reads only ACCESS_NETWORK_STATE (already
 * held) plus permissionless Settings.Secure keys. It never establishes a tun.
 */
object VpnSlotProbe {

    const val TAILSCALE_PKG = "com.tailscale.ipn"

    /** The combined guardrail verdict. */
    enum class Verdict {
        /** A VPN is active — an incumbent holds the slot. Refuse to arm. */
        FAIL_INCUMBENT,
        /** No VPN active and we already hold consent — safe to (re)start silently. */
        PASS_OWN_CONSENT,
        /** No VPN active, consent needed — safe to walk the consent dialog. */
        PASS_NEEDS_CONSENT,
    }

    /**
     * Full verdict plus advisory attribution. [incumbentName] is the
     * best-effort human name of whatever holds the slot (may be null —
     * degrade copy to "another app"). Attribution NEVER gates the refusal.
     */
    data class VpnSlotState(
        val verdict: Verdict,
        val incumbentName: String?,
    ) {
        val isPass: Boolean
            get() = verdict == Verdict.PASS_OWN_CONSENT || verdict == Verdict.PASS_NEEDS_CONSENT
    }

    // ---------------------------------------------------------------
    // Check 1 — ConnectivityManager capability scan (primary, the veto)
    // ---------------------------------------------------------------

    /**
     * True iff SOME network on the device is a VPN. Scans ALL networks,
     * not just the active default: a split-tunnel VPN may not be the
     * active default during handover. `TRANSPORT_VPN` present AND
     * `NET_CAPABILITY_NOT_VPN` absent ⇒ a VPN network exists.
     *
     * Fail-closed: any exception is treated as "a VPN is active" by the
     * caller ([evaluate]); this function itself surfaces the exception by
     * returning true so the veto holds.
     */
    fun isAnotherVpnActive(ctx: Context): Boolean {
        return try {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
                ?: return true // no CM → cannot prove absence → fail closed
            cm.allNetworks.any { n ->
                val caps = cm.getNetworkCapabilities(n) ?: return@any false
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            }
        } catch (t: Throwable) {
            Diagnostics.error(
                "firewall.VpnSlotProbe",
                "isAnotherVpnActive threw ${t.javaClass.simpleName}: ${t.message} — failing closed",
            )
            true
        }
    }

    // ---------------------------------------------------------------
    // Combined verdict
    // ---------------------------------------------------------------

    /**
     * Evaluate the guardrail. Check 1 (CM veto) decides PASS/FAIL; Check 2
     * (`VpnService.prepare`) only disambiguates, on a PASS, whether the
     * consent dialog is needed.
     */
    fun evaluate(ctx: Context): VpnSlotState {
        val vpnActive = isAnotherVpnActive(ctx)
        if (vpnActive) {
            val name = incumbentName(ctx)
            Diagnostics.log(
                "firewall.VpnSlotProbe",
                "evaluate: FAIL — a VPN network is active (incumbent=${name ?: "unknown"})",
            )
            return VpnSlotState(Verdict.FAIL_INCUMBENT, name)
        }
        // No VPN network. prepare() == null ⇒ we already hold consent;
        // non-null ⇒ consent needed (does NOT imply an incumbent).
        val prepare = runCatching { VpnService.prepare(ctx) }.getOrElse {
            // A prepare() throw is odd but non-fatal for the veto: no VPN
            // network was found, so treat as needs-consent and let the
            // consent launcher surface any real problem.
            Diagnostics.error(
                "firewall.VpnSlotProbe",
                "prepare() threw ${it.javaClass.simpleName}: ${it.message}",
            )
            return VpnSlotState(Verdict.PASS_NEEDS_CONSENT, null)
        }
        val verdict = if (prepare == null) Verdict.PASS_OWN_CONSENT
        else Verdict.PASS_NEEDS_CONSENT
        Diagnostics.log("firewall.VpnSlotProbe", "evaluate: ${verdict.name}")
        return VpnSlotState(verdict, null)
    }

    // ---------------------------------------------------------------
    // Package attribution (advisory only — never gates the refusal)
    // ---------------------------------------------------------------

    /**
     * Best-effort name of the app holding the slot, for copy only. Reads
     * `always_on_vpn_app` (permissionless; blank for a manually-started
     * VPN). If it resolves to a known package we return its label; else
     * null → the caller says "another app." NEVER claims a name we didn't
     * verify (CD-4).
     */
    fun incumbentName(ctx: Context): String? {
        val alwaysOn = alwaysOnVpnApp(ctx)
        if (!alwaysOn.isNullOrBlank()) {
            return labelForPackage(ctx, alwaysOn) ?: alwaysOn
        }
        // Manually-started VPN: we can't read the owner directly. If
        // Tailscale is at least installed, name it as a *possibility* only
        // when copy asks; here we return null so the caller degrades
        // honestly to "another app."
        return null
    }

    /** `always_on_vpn_app` Secure key, or null. Undocumented but stable. */
    fun alwaysOnVpnApp(ctx: Context): String? =
        runCatching {
            Settings.Secure.getString(ctx.contentResolver, "always_on_vpn_app")
        }.getOrNull()?.takeIf { it.isNotBlank() }

    /** `always_on_vpn_lockdown` == 1, tri-encoded as true/false/null. */
    fun alwaysOnLockdown(ctx: Context): Boolean? =
        runCatching {
            when (Settings.Secure.getInt(ctx.contentResolver, "always_on_vpn_lockdown", -1)) {
                1 -> true
                0 -> false
                else -> null
            }
        }.getOrNull()

    /** True if [pkg] is installed (getPackageInfo succeeds). Requires the
     *  package to be visible under package-visibility (§11 <queries>). */
    fun isInstalled(ctx: Context, pkg: String): Boolean =
        runCatching { ctx.packageManager.getPackageInfo(pkg, 0) }.isSuccess

    /** Best-effort version name of [pkg], or null. */
    fun versionName(ctx: Context, pkg: String): String? =
        runCatching { ctx.packageManager.getPackageInfo(pkg, 0).versionName }.getOrNull()

    private fun labelForPackage(ctx: Context, pkg: String): String? =
        runCatching {
            val pm = ctx.packageManager
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        }.getOrNull()

    // ---------------------------------------------------------------
    // Live slot-watcher
    // ---------------------------------------------------------------

    /**
     * Build the NetworkRequest the slot-watcher registers while the engine
     * is armed: any network with TRANSPORT_VPN. When such a network that is
     * not ours appears, the caller proactively stops the engine BEFORE the
     * system's onRevoke fires (§4 point 3).
     */
    fun vpnNetworkRequest(): NetworkRequest =
        NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .build()
}
