package com.understory.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

/**
 * Tamper / hooking detection. Best-effort; raises the bar against Lucky Patcher,
 * Xposed/LSPosed, Frida, Magisk, and re-signed/repackaged APKs.
 *
 * A determined attacker with full root can patch any of these out. The point is
 * to defeat casual modifications and make the easy-mode attacks fail loudly.
 *
 * Hard-fail conditions (refuse to function):
 *   - APK signature digest doesn't match the expected value
 *   - Xposed / LSPosed bridge detected loaded into our process
 *   - Frida agent detected mapped into our process
 *   - A known patcher package is installed on the device
 *   - We were installed by a known patcher package (installer source check)
 *
 * Soft conditions (warn user, don't refuse):
 *   - Root binaries / Magisk paths present
 *   - Build.TAGS contains "test-keys" (custom or development ROM)
 */
object Tamper {

    /**
     * SHA-256 of our APK signing certificate. Hardcoded against this build's
     * key. If the APK is repackaged with a different signature, this check
     * fails and the app refuses to run.
     */
    private const val EXPECTED_CERT_SHA256 =
        "aba68a81a0d63b5549794e586875a4f04e6dba3a6fe25d363e04eb75f46df69e"

    data class Report(
        val signatureMatches: Boolean,
        val xposed: Boolean,
        val frida: Boolean,
        val luckyPatcherInstalled: Boolean,
        val installedByPatcher: Boolean,
        val rootMarkers: List<String>,
        val testKeys: Boolean,
    ) {
        /** Conditions that should refuse function entirely. */
        val hardFail: Boolean
            get() = !signatureMatches ||
                xposed ||
                frida ||
                luckyPatcherInstalled ||
                installedByPatcher

        /** Conditions to surface to the user but not refuse on. */
        val warnings: List<String>
            get() = buildList {
                if (rootMarkers.isNotEmpty()) {
                    add("Root markers detected (${rootMarkers.size})")
                }
                if (testKeys) {
                    add("Build signed with test-keys (custom ROM)")
                }
            }
    }

    // Memoize the (expensive) check for 5s. Tamper.check() is called from hot
    // paths (every onFillRequest, every IME onStartInput, every secure click);
    // re-running 7 hook-class probes + reading /proc/self/maps + 9
    // PackageManager.getPackageInfo calls every time would lag the UI.
    // Lifecycle observers can call invalidate() on resume / config change /
    // package-add to force a fresh check.
    private const val CACHE_TTL_MS = 5_000L
    @Volatile private var cachedAt: Long = 0
    @Volatile private var cached: Report? = null

    fun invalidate() {
        cached = null
        cachedAt = 0
    }

    fun check(ctx: Context): Report {
        val now = android.os.SystemClock.elapsedRealtime()
        cached?.let { c ->
            if (now - cachedAt < CACHE_TTL_MS) return c
        }
        val r = Report(
            signatureMatches = signatureMatches(ctx),
            xposed = hookFrameworkLoaded(),
            frida = fridaInjected(),
            luckyPatcherInstalled = luckyPatcherInstalled(ctx),
            installedByPatcher = installedByPatcher(ctx),
            rootMarkers = rootMarkers(),
            testKeys = testKeysBuild(),
        )
        cached = r
        cachedAt = now
        return r
    }

    private fun signatureMatches(ctx: Context): Boolean {
        return try {
            val pi = ctx.packageManager.getPackageInfo(
                ctx.packageName,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
            val info = pi.signingInfo ?: return false
            // Use apkContentsSigners exclusively. signingCertificateHistory
            // would accept *rotated-out* certs as valid — wrong behaviour if
            // a cert was rotated because of compromise. apkContentsSigners
            // is the current-valid-signers set only.
            val sigs = info.apkContentsSigners ?: return false
            sigs.any { sig ->
                val digest = MessageDigest.getInstance("SHA-256")
                    .digest(sig.toByteArray())
                    .joinToString("") { "%02x".format(it) }
                digest.equals(EXPECTED_CERT_SHA256, ignoreCase = true)
            }
        } catch (_: Throwable) {
            false
        }
    }

    private fun hookFrameworkLoaded(): Boolean {
        // Hook frameworks expose canonical bridge / loader classes that don't
        // exist on a clean device. Probe for them by full class name. We do
        // NOT do stack-trace string matching — our own function and exception
        // names would trip the substring check and false-positive every device.
        val markerClasses = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XC_MethodHook",
            "de.robv.android.xposed.IXposedHookLoadPackage",
            "org.lsposed.lspd.core.Main",
            "org.lsposed.lspd.nativebridge.Yahfa",
            "io.github.lsposed.lspd.LSPApplication",
            "io.github.lsposed.lspd.core.Main",
        )
        for (m in markerClasses) {
            try {
                Class.forName(m)
                return true
            } catch (_: Throwable) {
                // not present, continue
            }
        }
        return false
    }

    private fun fridaInjected(): Boolean {
        // /proc/self/maps will contain frida-agent or gum-js-loop when a
        // Frida agent is mapped into our process. Reading this file does not
        // require any permission. We only match very specific tokens to avoid
        // false positives on legitimate libraries.
        val needles = listOf("frida-agent", "frida-gadget", "gum-js-loop", "linjector")
        return try {
            File("/proc/self/maps").bufferedReader().use { reader ->
                reader.lineSequence().any { line ->
                    needles.any { line.contains(it) }
                }
            }
        } catch (_: Throwable) {
            false
        }
    }

    private fun luckyPatcherInstalled(ctx: Context): Boolean {
        val pkgs = listOf(
            "com.chelpus.lackypatch",
            "com.dimonvideo.luckypatcher",
            "com.forpda.lp",
            "com.android.vending.billing.InAppBillingService.LUCK",
            "com.android.vending.billing.InAppBillingService.LACK",
            "ru.aaaaaaac.luckypatcher",
            "uret.jasi2169.patcher",
            "zone.jasi2169.uretpatcher",
            "ru.luckypatchers.luckypatcherinstaller",
        )
        val pm = ctx.packageManager
        return pkgs.any { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            } catch (_: Throwable) {
                false
            }
        }
    }

    private fun installedByPatcher(ctx: Context): Boolean {
        val installer = try {
            ctx.packageManager.getInstallSourceInfo(ctx.packageName).installingPackageName
        } catch (_: Throwable) {
            null
        } ?: return false
        val knownPatcherInstallers = setOf(
            "com.chelpus.lackypatch",
            "com.dimonvideo.luckypatcher",
            "com.forpda.lp",
            "uret.jasi2169.patcher",
            "zone.jasi2169.uretpatcher",
            "ru.aaaaaaac.luckypatcher",
        )
        return installer in knownPatcherInstallers
    }

    private fun rootMarkers(): List<String> {
        val paths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/etc/.installed_su_daemon",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/sbin/magisk",
            "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/cache/.disable_magisk",
        )
        return paths.filter {
            try {
                File(it).exists()
            } catch (_: Throwable) {
                false
            }
        }
    }

    private fun testKeysBuild(): Boolean = Build.TAGS?.contains("test-keys") == true
}
