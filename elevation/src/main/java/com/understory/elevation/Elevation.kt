package com.understory.elevation

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Process
import com.understory.elevation.shizuku.ShizukuShell
import kotlinx.coroutines.suspendCancellableCoroutine
import rikka.shizuku.Shizuku
import kotlin.coroutines.resume

/**
 * The suite's OPTIONAL-elevation broker.
 *
 * Core principle: the suite is rootless by default. Nothing in here runs unless
 * the user installed Shizuku and explicitly granted THIS app access.
 * Feature code should prefer the capability predicates ([canControlAppNetwork]
 * etc.) over tier checks — "can I block an app's network?" not "is Shizuku
 * present?" — so a feature transparently works on whichever tier is granted.
 *
 * Every high-level helper returns an [Outcome] and never throws to the UI; only
 * the low-level [runShell] throws ([NotElevated]) when no shell tier is granted.
 *
 * NOTE: [ElevTier.DHIZUKU] is defined but NOT compiled into this build — the
 * Dhizuku-API artifact is JitPack-only and does not resolve on CI, so the
 * DHIZUKU code path is stubbed (see [requestDhizuku]). The enum value is kept so
 * the tier can be restored later (re-add the dependency + un-stub) without a
 * source-compatibility break for consumers that switch on [ElevTier].
 */
object Elevation {

    private const val SHIZUKU_PERMISSION_REQUEST_CODE = 0xE1E7 // "ELE7"

    /** Default per-command timeout for the high-level shell helpers. */
    private const val DEFAULT_CMD_TIMEOUT_MS = 15_000L

    // ---- Discovery ----------------------------------------------------------

    /**
     * Tiers that are *installed and reachable* right now (whether or not this
     * app has been granted them). SHIZUKU when the Shizuku service is running
     * (pingBinder). DHIZUKU is never reported: it is not compiled into this
     * build (Dhizuku-API is JitPack-only / does not resolve on CI).
     */
    fun availableTiers(ctx: Context): Set<ElevTier> {
        val tiers = LinkedHashSet<ElevTier>()
        if (isShizukuAlive()) tiers.add(ElevTier.SHIZUKU)
        return tiers
    }

    /**
     * The highest tier currently GRANTED to this app, or [ElevTier.NONE].
     * "Granted" means: Shizuku permission granted. DHIZUKU is never returned in
     * this build (the tier is stubbed out; see [requestDhizuku]).
     */
    fun grantedTier(ctx: Context): ElevTier = when {
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
     * Trigger the Dhizuku bind + owner-permission grant.
     *
     * STUBBED in this build: Dhizuku support is not compiled in (the JitPack-only
     * Dhizuku-API artifact does not resolve on CI), so this always returns false.
     * The signature is preserved so callers and the grant UI stay source-stable;
     * restore the real flow by re-adding the dependency and the Dhizuku code path.
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun requestDhizuku(activity: Activity): Boolean = false

    // ---- Capability predicates (prefer these over tier checks) --------------

    /** A privileged shell is available (Shizuku granted). */
    fun canRunShell(ctx: Context): Boolean = isShizukuGranted()

    /** `settings put global/secure` reachable — via the Shizuku shell. */
    fun canWriteSecureSettings(ctx: Context): Boolean = isShizukuGranted()

    /** An app's background network can be blocked — via Shizuku netpolicy. */
    fun canControlAppNetwork(ctx: Context): Boolean = isShizukuGranted()

    /** Apps can be suspended/hidden/force-stopped/uninstalled — via the Shizuku pm/am shell. */
    fun canManageApps(ctx: Context): Boolean = isShizukuGranted()

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

    // ---- High-level helpers (Shizuku shell) ---------------------------------
    // Each `when` also has an `else -> dhizukuNotCompiled()` guard: unreachable in
    // this build (grantedTier never returns DHIZUKU) but keeps the enum `when`
    // exhaustive so restoring the tier is a localized change.

    /**
     * Set Private DNS via the Shizuku shell:
     * `settings put global private_dns_mode …` (+ `private_dns_specifier` for a
     * hostname).
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
            ElevTier.NONE -> unsupported("Private DNS control")
            else -> dhizukuNotCompiled()
        }
    }

    /**
     * Block/unblock an app's *background* (metered/data-restricted) network via
     * the Shizuku shell:
     * `cmd netpolicy add/remove restrict-background-blacklist <uid>`.
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
            ElevTier.NONE -> unsupported("app network control")
            else -> dhizukuNotCompiled()
        }
    }

    /**
     * Revoke a runtime permission from an app via the Shizuku shell:
     * `pm revoke <pkg> <perm>`.
     */
    suspend fun revokePermission(ctx: Context, pkg: String, perm: String): Outcome =
        when (grantedTier(ctx)) {
            ElevTier.SHIZUKU -> shellOutcome(ctx, "revoke permission") {
                runShell(ctx, listOf("pm", "revoke", pkg, perm))
            }
            ElevTier.NONE -> unsupported("permission control")
            else -> dhizukuNotCompiled()
        }

    /**
     * Force-stop an app via the Shizuku shell: `am force-stop <pkg>`.
     */
    suspend fun forceStop(ctx: Context, pkg: String): Outcome =
        when (grantedTier(ctx)) {
            ElevTier.SHIZUKU -> shellOutcome(ctx, "force-stop") {
                runShell(ctx, listOf("am", "force-stop", pkg))
            }
            ElevTier.NONE -> unsupported("force-stop")
            else -> dhizukuNotCompiled()
        }

    /**
     * Uninstall an app via the Shizuku shell: `pm uninstall <pkg>`.
     */
    suspend fun uninstall(ctx: Context, pkg: String): Outcome =
        when (grantedTier(ctx)) {
            ElevTier.SHIZUKU -> shellOutcome(ctx, "uninstall") {
                runShell(ctx, listOf("pm", "uninstall", pkg))
            }
            ElevTier.NONE -> unsupported("uninstall")
            else -> dhizukuNotCompiled()
        }

    /**
     * Suspend/unsuspend an app (greyed out, cannot launch) via the Shizuku shell:
     * `pm suspend/unsuspend <pkg>`.
     */
    suspend fun setAppSuspended(ctx: Context, pkg: String, suspended: Boolean): Outcome =
        when (grantedTier(ctx)) {
            ElevTier.SHIZUKU -> shellOutcome(ctx, "suspend app") {
                runShell(ctx, listOf("pm", if (suspended) "suspend" else "unsuspend", pkg))
            }
            ElevTier.NONE -> unsupported("app suspend")
            else -> dhizukuNotCompiled()
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

    private fun appUid(ctx: Context, pkg: String): Int? = runCatching {
        ctx.packageManager.getApplicationInfo(pkg, 0).uid
    }.getOrNull()

    private fun unsupported(what: String): Outcome =
        Outcome.Unsupported("$what needs Shizuku; grant it to enable this.")

    /**
     * Reached only if [grantedTier] somehow returned [ElevTier.DHIZUKU], which
     * cannot happen in this build (the tier is stubbed out). Kept so the enum
     * `when`s stay exhaustive without a compiled-in Dhizuku code path.
     */
    private fun dhizukuNotCompiled(): Outcome =
        Outcome.Unsupported("Dhizuku support is not available in this build")

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

    /** Exposed for diagnostics: the app's own uid (shell commands often need it). */
    fun selfUid(): Int = Process.myUid()
}
