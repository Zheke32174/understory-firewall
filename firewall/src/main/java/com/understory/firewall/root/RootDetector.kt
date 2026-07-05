package com.understory.firewall.root

import android.content.Context
import com.understory.elevation.Elevation
import com.understory.security.Diagnostics
import java.io.File

/**
 * Honest root / uid-0 detector for the S8 root iptables tier. This device is
 * UNROOTED (the operator runs Shizuku, not Magisk), so the whole tier is a
 * dormant stub — this detector exists so the UI can state, truthfully, WHY it
 * is unavailable, and would light up the tier on a genuinely rooted device.
 *
 * Detection is layered, cheapest-first, and NEVER executes `su` (running su
 * would pop a grant prompt — a side effect we refuse for a mere capability
 * probe). We only look for the PRESENCE of a root path:
 *   1. a `su` binary on any standard PATH location, or
 *   2. the Shizuku shell reporting it runs as uid 0 (root-mode Shizuku, as
 *      opposed to the normal adb-shell uid 2000 this device uses).
 *
 * The Shizuku uid probe is READ-ONLY (`id -u`) and only runs when the Shizuku
 * shell is already granted — it never triggers a new prompt. On this device it
 * returns 2000, so [detect] reports NOT_ROOTED with the honest reason.
 */
object RootDetector {

    private const val TAG = "firewall.root.RootDetector"

    /** Standard locations a `su` binary lives at on rooted devices. */
    private val SU_PATHS = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/system/su",
        "/vendor/bin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/magisk/.core/bin/su",
    )

    /** The verdict + the shell uid we observed (or null if not probed). */
    data class RootState(
        val rooted: Boolean,
        /** True if a Shizuku shell is granted and runs as uid 0. */
        val shizukuIsRoot: Boolean,
        /** The uid the granted Shizuku shell runs as (2000 = adb, 0 = root), or null. */
        val shizukuShellUid: Int?,
        /** True if a su binary path exists on disk. */
        val suBinaryPresent: Boolean,
    ) {
        /** One honest line for the UI. */
        val reason: String
            get() = when {
                rooted && shizukuIsRoot -> "Root available via root-mode Shizuku (uid 0)."
                rooted && suBinaryPresent -> "Root available (su binary present)."
                shizukuShellUid != null ->
                    "Not rooted — the Shizuku shell runs as uid $shizukuShellUid (adb shell), " +
                        "which cannot set iptables. Root (uid 0) is required."
                else ->
                    "Not rooted — no su binary and no root-mode shell on this device. " +
                        "The root firewall tier requires root (uid 0)."
            }
    }

    /**
     * Static (no-shell) probe: just the su-binary path check. Cheap + synchronous,
     * safe on the main thread. Does NOT report root-mode Shizuku (that needs a
     * shell read — use [detect]).
     */
    fun suBinaryPresent(): Boolean =
        runCatching { SU_PATHS.any { File(it).exists() } }.getOrDefault(false)

    /**
     * Full probe, including a READ-ONLY `id -u` through a granted Shizuku shell
     * (only if already granted; never prompts). Suspends because the shell call
     * is async. On this unrooted device: suBinaryPresent=false, shizukuShellUid=
     * 2000 ⇒ rooted=false with the honest reason.
     */
    suspend fun detect(ctx: Context): RootState {
        val suPresent = suBinaryPresent()

        var shellUid: Int? = null
        if (Elevation.canRunShell(ctx)) {
            val out = runCatching { Elevation.readShell(ctx, listOf("id", "-u")) }.getOrNull()
            shellUid = out?.trim()?.toIntOrNull()
        }
        val shizukuIsRoot = shellUid == 0

        val rooted = suPresent || shizukuIsRoot
        val state = RootState(
            rooted = rooted,
            shizukuIsRoot = shizukuIsRoot,
            shizukuShellUid = shellUid,
            suBinaryPresent = suPresent,
        )
        Diagnostics.log(TAG, "detect: rooted=$rooted shellUid=$shellUid suBinary=$suPresent")
        return state
    }
}
