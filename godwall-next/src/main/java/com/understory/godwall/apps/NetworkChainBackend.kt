package com.understory.godwall.apps

import android.content.Context
import android.os.Build
import com.understory.godwall.privilege.Privilege
import com.understory.security.Diagnostics

/**
 * Per-app network denial through the platform firewall chain.
 *
 * The mechanism is two `cmd connectivity` calls, which is the genuine Android
 * 13+ path to FIREWALL_CHAIN_OEM_DENY_3 in netd:
 *
 *     cmd connectivity set-chain3-enabled true
 *     cmd connectivity set-package-networking-enabled <true|false> <pkg>
 *
 * `enabled=false` denies. The denial covers every transport — Wi-Fi, mobile and
 * any VPN — and consumes no VPN slot of its own, which is why it composes with
 * Godwall holding the slot for the DNS filter or the mesh node instead of
 * competing with it.
 *
 * The commands run through [Privilege], which is Yojimbo and nothing else. When
 * no privileged shell is attached, [isAvailable] is false and every call returns
 * an honest failure rather than a silent no-op.
 *
 * Two properties worth keeping in mind because the UI states them:
 *   - the denial is all-or-nothing per app; there is no per-transport split;
 *   - netd's chain state does not survive a reboot, so [applyAll] must be run
 *     again after one. Godwall re-applies when the engine is armed.
 */
class NetworkChainBackend(private val appContext: Context) {

    /** Cache of what we have actually applied: package → denied. */
    private val applied = HashMap<String, Boolean>()

    fun isAvailable(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && Privilege.isAvailable()

    /** Why the control is unavailable, in one sentence, or null when it is available. */
    fun unavailableReason(context: Context): String? = when {
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ->
            "Needs Android 13 or newer — this device is API ${Build.VERSION.SDK_INT}."
        !Privilege.isAvailable() -> Privilege.explain(context)
        else -> null
    }

    /** Enable the chain once. Idempotent. Blocking — call off the main thread. */
    fun arm(): Boolean {
        val r = Privilege.exec(listOf("cmd", "connectivity", "set-chain3-enabled", "true"))
        if (r.ok) {
            Diagnostics.log(TAG, "firewall chain armed")
        } else {
            Diagnostics.error(TAG, "arm failed: exit=${r.exit} ${r.summary()}")
        }
        return r.ok
    }

    fun disarm(): Boolean {
        val r = Privilege.exec(listOf("cmd", "connectivity", "set-chain3-enabled", "false"))
        applied.clear()
        return r.ok
    }

    /** Deny or allow one package. Blocking. */
    fun setDenied(pkg: String, denied: Boolean): Boolean {
        if (denied && UidExemptions.isExempt(appContext, pkg)) {
            Diagnostics.warn(TAG, "refused to deny $pkg — protected package")
            return false
        }
        val enabled = (!denied).toString()
        val r = Privilege.exec(
            listOf("cmd", "connectivity", "set-package-networking-enabled", enabled, pkg),
        )
        if (r.ok) {
            applied[pkg] = denied
            Diagnostics.log(TAG, "$pkg → ${if (denied) "DENY" else "ALLOW"} (all networks)")
        } else {
            Diagnostics.error(TAG, "$pkg failed: exit=${r.exit} ${r.summary()}")
        }
        return r.ok
    }

    data class ApplyResult(val changed: Int, val failed: Int, val note: String) {
        val ok: Boolean get() = failed == 0
    }

    /**
     * Reconcile the device to exactly [deniedPkgs]. Issues one command per real
     * CHANGE, not one per app per pass — the cache is what makes re-arming after
     * a reboot cheap instead of a storm of shell calls.
     */
    fun applyAll(deniedPkgs: Set<String>): ApplyResult {
        if (!isAvailable()) {
            return ApplyResult(0, 0, unavailableReason(appContext) ?: "Unavailable.")
        }
        if (!arm()) return ApplyResult(0, 1, "Could not enable the firewall chain.")

        val desired = HashMap<String, Boolean>(applied.size + deniedPkgs.size)
        for ((pkg, wasDenied) in applied) if (wasDenied) desired[pkg] = false
        for (pkg in deniedPkgs) if (!UidExemptions.isExempt(appContext, pkg)) desired[pkg] = true

        var changed = 0
        var failed = 0
        for ((pkg, shouldDeny) in desired) {
            if (applied[pkg] == shouldDeny) continue
            changed++
            if (!setDenied(pkg, shouldDeny)) failed++
        }
        val note = "Applied ${deniedPkgs.size} denial(s): $changed command(s), $failed failure(s)."
        Diagnostics.log(TAG, note)
        return ApplyResult(changed, failed, note)
    }

    private companion object {
        const val TAG = "godwall.apps.NetworkChain"
    }
}
