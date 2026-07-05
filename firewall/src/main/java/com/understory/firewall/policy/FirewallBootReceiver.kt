package com.understory.firewall.policy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.understory.elevation.Elevation
import com.understory.security.Diagnostics
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Boot / app-update re-arm for the slot-free policy engine (Stage-3 §3).
 *
 * HONESTY — rootless firewalls have NO true boot persistence. The kernel
 * FIREWALL_CHAIN_OEM_DENY_3 chain armed via the Shizuku shell is cleared by a
 * reboot and CANNOT be re-armed until the Shizuku shell binder is re-granted to
 * this app post-boot. That grant is not instant: the Shizuku service itself must
 * come up and (depending on the user's Shizuku config) may require the manager
 * app or an ADB-started service before it can hand us a binder. So between boot
 * and that moment, the firewall rules are GENUINELY INACTIVE — every app can
 * reach the network. We do not and cannot claim seamless boot enforcement.
 *
 * What this receiver does, honestly: it polls [Elevation.canRunShell] on a
 * bounded, backing-off schedule after boot. The instant the shell becomes
 * available it re-arms the chain and re-applies the persisted effective policy
 * via [BackendManager.restore]. If the shell never becomes available within the
 * window (Shizuku not started / not granted), it gives up quietly — the UI's
 * "rules may be briefly inactive after a reboot until Shizuku reconnects" line
 * is the truthful surface for that state; we do not fire a misleading
 * "protected" notification.
 *
 * Registered exported="false" for BOOT_COMPLETED / LOCKED_BOOT_COMPLETED /
 * MY_PACKAGE_REPLACED — only the system's protected broadcasts reach it. It
 * no-ops entirely if there is no persisted policy to restore.
 */
class FirewallBootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        when (action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            -> reArm(context.applicationContext, action)
            else -> Diagnostics.log(TAG, "ignoring unexpected action: $action")
        }
    }

    private fun reArm(appCtx: Context, trigger: String?) {
        val manager = BackendManager.get(appCtx)
        val hasPolicy = manager.blockedPackages().isNotEmpty() || manager.isLockdown()
        if (!hasPolicy) {
            Diagnostics.log(TAG, "no persisted policy — nothing to restore after $trigger")
            return
        }

        // goAsync keeps the receiver's process alive while we poll + apply. We
        // finish() it in the finally so we never hold the process longer than
        // the bounded poll window.
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Diagnostics.log(TAG, "re-arm after $trigger — waiting for Shizuku shell (honest: rules inactive until then)")
                val available = awaitShell(appCtx)
                if (!available) {
                    // Truthful outcome: we could not re-arm. No misleading
                    // "firewall active" claim. The next app launch / manual
                    // apply, or a Shizuku grant, will restore.
                    Diagnostics.warn(
                        TAG,
                        "Shizuku shell did not become available within the boot window — " +
                            "policy NOT re-armed. Rules are inactive until Shizuku reconnects.",
                    )
                    return@launch
                }
                val result = manager.restore()
                Diagnostics.log(
                    TAG,
                    "boot restore applied: changed=${result.changed} failed=${result.failed}",
                )
            } catch (t: Throwable) {
                Diagnostics.error(TAG, "boot re-arm threw: ${t.javaClass.simpleName}: ${t.message}")
            } finally {
                runCatching { pending.finish() }
            }
        }
    }

    /**
     * Poll [Elevation.canRunShell] until it is true or the bounded window
     * elapses. Bounded so the receiver process is not held indefinitely — the
     * honest contract is "we try for a while after boot", not "forever".
     * Returns true if the shell became available.
     */
    private suspend fun awaitShell(appCtx: Context): Boolean {
        var waited = 0L
        while (waited < MAX_WAIT_MS) {
            if (Elevation.canRunShell(appCtx)) return true
            delay(POLL_INTERVAL_MS)
            waited += POLL_INTERVAL_MS
        }
        return Elevation.canRunShell(appCtx)
    }

    companion object {
        private const val TAG = "firewall.policy.BootReceiver"

        // Poll cadence and ceiling. ~60s total: long enough for Shizuku to come
        // up on most devices, short enough not to pin the process. Deliberately
        // NOT a fast tight loop (cadence-keep-slow).
        private const val POLL_INTERVAL_MS = 3_000L
        private const val MAX_WAIT_MS = 60_000L
    }
}
