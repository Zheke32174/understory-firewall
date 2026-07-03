package com.understory.elevation

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Process
import android.os.RemoteException
import com.rosan.dhizuku.api.Dhizuku
import com.rosan.dhizuku.api.DhizukuRequestPermissionListener
import com.rosan.dhizuku.shared.DhizukuVariables
import com.understory.elevation.dhizuku.DhizukuDpm
import com.understory.elevation.shizuku.ShizukuShell
import kotlinx.coroutines.suspendCancellableCoroutine
import rikka.shizuku.Shizuku
import kotlin.coroutines.resume

/**
 * The suite's OPTIONAL-elevation broker.
 *
 * Core principle: the suite is rootless by default. Nothing in here runs unless
 * the user installed Shizuku or Dhizuku and explicitly granted THIS app access.
 * Feature code should prefer the capability predicates ([canControlAppNetwork]
 * etc.) over tier checks — "can I block an app's network?" not "is Shizuku
 * present?" — so a feature transparently works on whichever tier is granted.
 *
 * Every high-level helper returns an [Outcome] and never throws to the UI; only
 * the low-level [runShell] throws ([NotElevated]) when no shell tier is granted.
 */
object Elevation {

    private const val SHIZUKU_PERMISSION_REQUEST_CODE = 0xE1E7 // "ELE7"

    /** Default per-command timeout for the high-level shell helpers. */
    private const val DEFAULT_CMD_TIMEOUT_MS = 15_000L

    // ---- Discovery ----------------------------------------------------------

    /**
     * Tiers that are *installed and reachable* right now (whether or not this
     * app has been granted them). SHIZUKU when the Shizuku service is running
     * (pingBinder); DHIZUKU when the Dhizuku app is installed AND currently the
     * active Device/Profile Owner (so a delegate could be requested).
     */
    fun availableTiers(ctx: Context): Set<ElevTier> {
        val tiers = LinkedHashSet<ElevTier>()
        if (isShizukuAlive()) tiers.add(ElevTier.SHIZUKU)
        if (isDhizukuAvailable(ctx)) tiers.add(ElevTier.DHIZUKU)
        return tiers
    }

    /**
     * The highest tier currently GRANTED to this app, or [ElevTier.NONE].
     * "Granted" means: Shizuku permission granted, or Dhizuku bound with
     * permission granted. DHIZUKU outranks SHIZUKU only as a stable tie-break.
     */
    fun grantedTier(ctx: Context): ElevTier = when {
        isDhizukuGranted(ctx) -> ElevTier.DHIZUKU
        isShizukuGranted() -> ElevTier.SHIZUKU
        else -> ElevTier.NONE
    }

    // ---- Grant flows --------------------------------------------------------

    /**
     * Trigger (or complete) the Shizuku permission grant. Returns whether the
     * permission is granted when the flow settles. Safe to call when already
     * granted (returns true immediately) or when Shizuku is not running
     * (returns false immediately).
     */
    suspend fun requestShizuku(activity: Activity): Boolean {
        if (!isShizukuAlive()) return false
        if (isShizukuGranted()) return true
        // Pre-11 Shizuku exposes a runtime-permission style flow; the API's
        // shouldShowRequestPermissionRationale is respected by callers, but here
        // we simply request and await the result callback.
        return suspendCancellableCoroutine { cont ->
            val listener = object : Shizuku.OnRequestPermissionResultListener {
                override fun onRequestPermissionResult(requestCode: Int, grantResult: Int) {
                    if (requestCode != SHIZUKU_PERMISSION_REQUEST_CODE) return
                    Shizuku.removeRequestPermissionResultListener(this)
                    if (cont.isActive) cont.resume(grantResult == PackageManager.PERMISSION_GRANTED)
                }
            }
            Shizuku.addRequestPermissionResultListener(listener)
            cont.invokeOnCancellation { Shizuku.removeRequestPermissionResultListener(listener) }
            try {
                Shizuku.requestPermission(SHIZUKU_PERMISSION_REQUEST_CODE)
            } catch (t: Throwable) {
                Shizuku.removeRequestPermissionResultListener(listener)
                if (cont.isActive) cont.resume(false)
            }
        }
    }

    /**
     * Trigger the Dhizuku bind + owner-permission grant. Returns whether the
     * permission is granted when the flow settles. Returns false immediately if
     * Dhizuku is not installed or not the active owner.
     */
    suspend fun requestDhizuku(activity: Activity): Boolean {
        if (!isDhizukuAvailable(activity)) return false
        if (!runCatching { Dhizuku.init(activity) }.getOrDefault(false)) return false
        if (runCatching { Dhizuku.isPermissionGranted() }.getOrDefault(false)) return true
        return suspendCancellableCoroutine { cont ->
            val listener = object : DhizukuRequestPermissionListener() {
                @Throws(RemoteException::class)
                override fun onRequestPermission(grantResult: Int) {
                    if (cont.isActive) cont.resume(grantResult == PackageManager.PERMISSION_GRANTED)
                }
            }
            try {
                Dhizuku.requestPermission(listener)
            } catch (t: Throwable) {
                if (cont.isActive) cont.resume(false)
            }
        }
    }

    // ---- Capability predicates (prefer these over tier checks) --------------

    /** A privileged shell is available (Shizuku granted). */
    fun canRunShell(ctx: Context): Boolean = isShizukuGranted()

    /** `settings put global/secure` reachable — via Shizuku shell or Dhizuku setGlobalSetting. */
    fun canWriteSecureSettings(ctx: Context): Boolean =
        isShizukuGranted() || isDhizukuGranted(ctx)

    /** An app's background network can be blocked — Shizuku netpolicy or Dhizuku restriction. */
    fun canControlAppNetwork(ctx: Context): Boolean =
        isShizukuGranted() || isDhizukuGranted(ctx)

    /** Apps can be suspended/hidden/force-stopped/uninstalled — Shizuku pm/am or Dhizuku DPM. */
    fun canManageApps(ctx: Context): Boolean =
        isShizukuGranted() || isDhizukuGranted(ctx)

    // ---- The shell workhorse ------------------------------------------------

    /**
     * Run [cmd] (argv, already split — pass `listOf("pm","list","packages")`,
     * NOT a single shell string) at the granted shell privilege via Shizuku.
     *
     * @throws NotElevated when no Shizuku shell is granted. This is the ONE
     *   primitive that throws; callers should gate on [canRunShell]. High-level
     *   helpers below never surface this — they return [Outcome].
     */
    suspend fun runShell(
        ctx: Context,
        cmd: List<String>,
        timeoutMs: Long = DEFAULT_CMD_TIMEOUT_MS,
    ): ShellResult {
        if (!isShizukuGranted()) throw NotElevated()
        return ShizukuShell.exec(ctx, cmd, timeoutMs)
            ?: throw NotElevated("Shizuku shell service could not be bound")
    }

    // ---- High-level helpers (Shizuku shell OR Dhizuku DPM) ------------------

    /**
     * Set Private DNS. Shizuku: `settings put global private_dns_mode …` (+
     * `private_dns_specifier` for a hostname). Dhizuku: DPM.setGlobalSetting on
     * the same keys.
     */
    suspend fun setPrivateDns(
        ctx: Context,
        mode: PrivateDnsMode,
        hostname: String? = null,
    ): Outcome {
        if (mode == PrivateDnsMode.HOSTNAME && hostname.isNullOrBlank()) {
            return Outcome.Failed("Strict Private DNS requires a hostname")
        }
        return when (grantedTier(ctx)) {
            ElevTier.SHIZUKU -> shellOutcome(ctx, "set Private DNS") {
                if (mode == PrivateDnsMode.HOSTNAME) {
                    val a = runShell(ctx, listOf("settings", "put", "global", "private_dns_specifier", hostname!!))
                    if (!a.ok) return@shellOutcome a
                }
                runShell(ctx, listOf("settings", "put", "global", "private_dns_mode", mode.settingValue))
            }
            ElevTier.DHIZUKU -> dpmOutcome("set Private DNS") {
                val specOk = if (mode == PrivateDnsMode.HOSTNAME) {
                    DhizukuDpm.setGlobalSetting(ctx, "private_dns_specifier", hostname!!)
                } else true
                specOk && DhizukuDpm.setGlobalSetting(ctx, "private_dns_mode", mode.settingValue)
            }
            ElevTier.NONE -> unsupported("Private DNS control")
        }
    }

    /**
     * Block/unblock an app's *background* (metered/data-restricted) network.
     * Shizuku: `cmd netpolicy add/remove restrict-background-blacklist <uid>`.
     * Dhizuku: a user restriction is the closest owner-level equivalent — we
     * scope it via app suspension of network is not available per-app, so we use
     * setApplicationHidden as the honest owner fallback only when asked to block
     * fully; per-app metered policy is Shizuku-only, so on Dhizuku we report the
     * precise capability we CAN offer.
     */
    suspend fun setAppBackgroundNetworkBlocked(
        ctx: Context,
        pkg: String,
        blocked: Boolean,
    ): Outcome {
        val uid = appUid(ctx, pkg)
            ?: return Outcome.Failed("Unknown package: $pkg")
        return when (grantedTier(ctx)) {
            ElevTier.SHIZUKU -> shellOutcome(ctx, "app background network") {
                val verb = if (blocked) "add" else "remove"
                runShell(
                    ctx,
                    listOf("cmd", "netpolicy", verb, "restrict-background-blacklist", uid.toString()),
                )
            }
            ElevTier.DHIZUKU ->
                // Per-app metered denylist is not a Device-Owner API; be honest
                // rather than silently doing something different.
                Outcome.Unsupported(
                    "Per-app background-network block needs Shizuku; Dhizuku (Device Owner) has no per-app metered API.",
                )
            ElevTier.NONE -> unsupported("app network control")
        }
    }

    /**
     * Revoke a runtime permission from an app. Shizuku: `pm revoke <pkg> <perm>`.
     * Dhizuku: DPM.setPermissionGrantState(…, PERMISSION_GRANT_STATE_DENIED).
     */
    suspend fun revokePermission(ctx: Context, pkg: String, perm: String): Outcome =
        when (grantedTier(ctx)) {
            ElevTier.SHIZUKU -> shellOutcome(ctx, "revoke permission") {
                runShell(ctx, listOf("pm", "revoke", pkg, perm))
            }
            ElevTier.DHIZUKU -> dpmOutcome("revoke permission") {
                DhizukuDpm.setPermissionGrantState(
                    ctx, pkg, perm, DevicePolicyManager.PERMISSION_GRANT_STATE_DENIED,
                )
            }
            ElevTier.NONE -> unsupported("permission control")
        }

    /**
     * Force-stop an app. Shizuku: `am force-stop <pkg>`. Dhizuku: no exact
     * owner equivalent — hiding then unhiding kills the process as the closest
     * effect, but that is surprising, so we instead suspend+unsuspend which the
     * platform uses to stop an app's processes without hiding it from the
     * launcher. We report honestly which mechanism ran.
     */
    suspend fun forceStop(ctx: Context, pkg: String): Outcome =
        when (grantedTier(ctx)) {
            ElevTier.SHIZUKU -> shellOutcome(ctx, "force-stop") {
                runShell(ctx, listOf("am", "force-stop", pkg))
            }
            ElevTier.DHIZUKU -> dpmOutcome("force-stop (via suspend cycle)") {
                // Suspending a package stops its running processes; immediately
                // un-suspending leaves visible state unchanged but achieves the
                // "kill now" intent as closely as a Device Owner can.
                val s = DhizukuDpm.setPackagesSuspended(ctx, pkg, true)
                val u = DhizukuDpm.setPackagesSuspended(ctx, pkg, false)
                s && u
            }
            ElevTier.NONE -> unsupported("force-stop")
        }

    /**
     * Uninstall an app. Shizuku: `pm uninstall <pkg>`. Dhizuku (Device Owner):
     * there is no silent removePackage in the public DPM; the honest owner
     * action is to HIDE the package (setApplicationHidden true), which removes
     * it from the launcher and stops it. We report which action ran.
     */
    suspend fun uninstall(ctx: Context, pkg: String): Outcome =
        when (grantedTier(ctx)) {
            ElevTier.SHIZUKU -> shellOutcome(ctx, "uninstall") {
                runShell(ctx, listOf("pm", "uninstall", pkg))
            }
            ElevTier.DHIZUKU -> dpmOutcome("hide app (Device-Owner uninstall equivalent)") {
                DhizukuDpm.setApplicationHidden(ctx, pkg, true)
            }
            ElevTier.NONE -> unsupported("uninstall")
        }

    /**
     * Suspend/unsuspend an app (greyed out, cannot launch). Shizuku:
     * `pm suspend/unsuspend <pkg>`. Dhizuku: DPM.setPackagesSuspended.
     */
    suspend fun setAppSuspended(ctx: Context, pkg: String, suspended: Boolean): Outcome =
        when (grantedTier(ctx)) {
            ElevTier.SHIZUKU -> shellOutcome(ctx, "suspend app") {
                runShell(ctx, listOf("pm", if (suspended) "suspend" else "unsuspend", pkg))
            }
            ElevTier.DHIZUKU -> dpmOutcome("suspend app") {
                DhizukuDpm.setPackagesSuspended(ctx, pkg, suspended)
            }
            ElevTier.NONE -> unsupported("app suspend")
        }

    // ---- internals ----------------------------------------------------------

    private fun isShizukuAlive(): Boolean =
        runCatching { Shizuku.pingBinder() }.getOrDefault(false)

    private fun isShizukuGranted(): Boolean = runCatching {
        // checkSelfPermission() unifies the pre-v11 runtime-permission path and
        // the v11+ binder-permission path, so a single check is correct on all
        // Shizuku versions. Guard with pingBinder so we never call into a dead
        // service.
        Shizuku.pingBinder() &&
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    }.getOrDefault(false)

    private fun isDhizukuAvailable(ctx: Context): Boolean = runCatching {
        // Installed?
        val pm = ctx.packageManager
        val installed = runCatching {
            pm.getPackageInfo(DhizukuVariables.OFFICIAL_PACKAGE_NAME, 0); true
        }.getOrDefault(false)
        if (!installed) return false
        // Active as Device/Profile Owner (so a delegate can be requested)?
        Dhizuku.getOwnerComponent(ctx) != null
    }.getOrDefault(false)

    private fun isDhizukuGranted(ctx: Context): Boolean = runCatching {
        isDhizukuAvailable(ctx) &&
            Dhizuku.init(ctx) &&
            Dhizuku.isPermissionGranted()
    }.getOrDefault(false)

    private fun appUid(ctx: Context, pkg: String): Int? = runCatching {
        ctx.packageManager.getApplicationInfo(pkg, 0).uid
    }.getOrNull()

    private fun unsupported(what: String): Outcome =
        Outcome.Unsupported("$what needs Shizuku or Dhizuku; grant one to enable it.")

    /** Run a shell-backed block, translating exit codes / throwables to [Outcome]. */
    private suspend inline fun shellOutcome(
        ctx: Context,
        label: String,
        block: () -> ShellResult,
    ): Outcome = try {
        val r = block()
        if (r.ok) Outcome.Success(r.out.trim().ifBlank { null })
        else Outcome.Failed("$label failed (exit ${r.exit}): ${r.err.trim().take(200)}")
    } catch (e: NotElevated) {
        Outcome.Unsupported(e.message ?: "not elevated")
    } catch (t: Throwable) {
        Outcome.Failed("$label failed: ${t.message ?: t.javaClass.simpleName}", t)
    }

    /** Run a DPM-backed block, translating a boolean / throwable to [Outcome]. */
    private inline fun dpmOutcome(label: String, block: () -> Boolean): Outcome = try {
        if (block()) Outcome.Success(label) else Outcome.Failed("$label failed (Device Owner call returned false)")
    } catch (t: Throwable) {
        Outcome.Failed("$label failed: ${t.message ?: t.javaClass.simpleName}", t)
    }

    /** Exposed for diagnostics: the app's own uid (shell commands often need it). */
    fun selfUid(): Int = Process.myUid()
}
