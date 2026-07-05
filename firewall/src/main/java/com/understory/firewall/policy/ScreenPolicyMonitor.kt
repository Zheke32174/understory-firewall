package com.understory.firewall.policy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.PowerManager
import com.understory.security.Diagnostics
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Runtime-registered screen on/off monitor that drives the per-app "block when
 * screen off / in background" flags (Stage-3 §2). On each SCREEN_ON / SCREEN_OFF
 * it kicks a DEBOUNCED re-apply of the effective set via
 * [BackendManager.applyEffective], so the conditional flags add/remove their
 * packages from the enforced set as the screen changes.
 *
 * WHY RUNTIME REGISTRATION (honest lifecycle): since Android 8 (Oreo) the
 * implicit ACTION_SCREEN_ON / ACTION_SCREEN_OFF broadcasts are NOT deliverable
 * to manifest-declared receivers — they must be registered at runtime against a
 * live [Context]. This monitor is therefore a process-scoped singleton that the
 * app starts (from a started component / the policy screen) and that lives only
 * while the process is alive. Consequence, stated plainly: if the OS kills the
 * app process while it is backgrounded, the monitor stops and screen-off rules
 * pause until the process is next started. This is the honest ceiling of a
 * rootless, service-free design — we do NOT run a persistent foreground service
 * just to keep this receiver alive (that would be a heavier promise than the
 * feature warrants, and the slot-free doctrine avoids it).
 *
 * The apply itself runs in [kotlinx.coroutines.NonCancellable] inside
 * [BackendManager.applyEffective]; the debounce here only coalesces a burst of
 * screen toggles into one apply — it never cancels a shell mid-flight.
 */
object ScreenPolicyMonitor {

    private const val TAG = "firewall.policy.ScreenMonitor"

    /** Coalesce a flurry of screen toggles (e.g. pocket flicker) into one apply. */
    private const val DEBOUNCE_MS = 800L

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private var receiver: BroadcastReceiver? = null

    // The most recent debounced apply job; a new screen event cancels+replaces it
    // (the DEBOUNCE window, not the shell command, is what gets cancelled).
    private var pendingJob: Job? = null

    @Volatile
    private var started = false

    /**
     * Start monitoring against [context] (uses the application context). Idempotent.
     * Safe to call when no shell tier is granted — the eventual apply just NOOPs
     * until Shizuku is available. Only actually registers when at least one
     * conditional flag exists, to avoid holding a receiver for nothing; callers
     * should re-invoke after changing a flag.
     */
    @Synchronized
    fun start(context: Context) {
        val appCtx = context.applicationContext
        if (started) return
        val hasFlags = PolicyStore.getScreenOffPackages(appCtx).isNotEmpty() ||
            PolicyStore.getBackgroundPackages(appCtx).isNotEmpty()
        if (!hasFlags) {
            Diagnostics.log(TAG, "start: no screen-off/background flags — not registering")
            return
        }

        val r = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_ON -> onScreenChanged(appCtx, screenOn = true)
                    Intent.ACTION_SCREEN_OFF -> onScreenChanged(appCtx, screenOn = false)
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        runCatching { appCtx.registerReceiver(r, filter) }
            .onSuccess {
                receiver = r
                started = true
                Diagnostics.log(TAG, "screen-state monitor registered")
            }
            .onFailure { Diagnostics.error(TAG, "registerReceiver failed: ${it.javaClass.simpleName}") }
    }

    /** Stop and unregister. Idempotent. */
    @Synchronized
    fun stop(context: Context) {
        val r = receiver ?: return
        runCatching { context.applicationContext.unregisterReceiver(r) }
        receiver = null
        started = false
        pendingJob?.cancel()
        pendingJob = null
        Diagnostics.log(TAG, "screen-state monitor unregistered")
    }

    /**
     * Re-evaluate registration after the user changes a flag: register if any
     * flag now exists, unregister if none do. Cheap; call from the UI after a
     * flag toggle.
     */
    fun refresh(context: Context) {
        val appCtx = context.applicationContext
        val hasFlags = PolicyStore.getScreenOffPackages(appCtx).isNotEmpty() ||
            PolicyStore.getBackgroundPackages(appCtx).isNotEmpty()
        if (hasFlags) start(appCtx) else stop(appCtx)
    }

    /** True if [context]'s screen is currently interactive. */
    fun isScreenOn(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        return pm?.isInteractive ?: true
    }

    private fun onScreenChanged(appCtx: Context, screenOn: Boolean) {
        Diagnostics.log(TAG, "SCREEN_${if (screenOn) "ON" else "OFF"} — scheduling debounced apply")
        pendingJob?.cancel()
        pendingJob = scope.launch {
            delay(DEBOUNCE_MS)
            // The installed-app universe is only needed for BLOCK_ALL; enumerate
            // once here so a screen-off in lockdown still computes "everything".
            val manager = BackendManager.get(appCtx)
            val installed = if (manager.isLockdown()) manager.installedNonSelfPackages() else emptySet()
            val result = manager.applyEffective(installedPackages = installed, screenOn = screenOn)
            Diagnostics.log(
                TAG,
                "screen-driven apply done: changed=${result.changed} failed=${result.failed} screenOn=$screenOn",
            )
        }
    }
}
