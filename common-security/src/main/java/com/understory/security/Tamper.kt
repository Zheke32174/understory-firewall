package com.understory.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

/**
 * Best-effort tamper and hooking detection.
 *
 * Release variants enforce the offline Understory release certificate. Debug
 * variants intentionally do not claim signing identity because their former
 * shared private key became public. Debug builds remain development builds.
 */
object Tamper {
    private val EXPECTED_RELEASE_CERT_SHA256 = SuitePins.EXPECTED_RELEASE_CERT_SHA256

    data class Report(
        val signatureMatches: Boolean,
        val xposed: Boolean,
        val frida: Boolean,
        val luckyPatcherInstalled: Boolean,
        val installedByPatcher: Boolean,
        val rootMarkers: List<String>,
        val testKeys: Boolean,
    ) {
        val hardFail: Boolean
            get() = !signatureMatches || xposed || frida || luckyPatcherInstalled || installedByPatcher

        val warnings: List<String>
            get() = buildList {
                if (BuildConfig.DEBUG) add("Debug signing identity is not trusted")
                if (rootMarkers.isNotEmpty()) add("Root markers detected (${rootMarkers.size})")
                if (testKeys) add("Build signed with test-keys (custom ROM)")
            }
    }

    private const val CACHE_TTL_MS = 5_000L
    @Volatile private var cachedAt: Long = 0
    @Volatile private var cached: Report? = null

    fun invalidate() {
        cached = null
        cachedAt = 0
    }

    fun check(ctx: Context): Report {
        val now = android.os.SystemClock.elapsedRealtime()
        cached?.let { if (now - cachedAt < CACHE_TTL_MS) return it }
        val result = Report(
            signatureMatches = signatureMatches(ctx),
            xposed = hookFrameworkLoaded(),
            frida = fridaInjected(),
            luckyPatcherInstalled = luckyPatcherInstalled(ctx),
            installedByPatcher = installedByPatcher(ctx),
            rootMarkers = rootMarkers(),
            testKeys = Build.TAGS?.contains("test-keys") == true,
        )
        cached = result
        cachedAt = now
        return result
    }

    private fun signatureMatches(ctx: Context): Boolean {
        if (BuildConfig.DEBUG) return true
        return try {
            val packageInfo = ctx.packageManager.getPackageInfo(
                ctx.packageName,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
            val signers = packageInfo.signingInfo?.apkContentsSigners ?: return false
            signers.any { signer ->
                val digest = MessageDigest.getInstance("SHA-256")
                    .digest(signer.toByteArray())
                    .joinToString("") { "%02x".format(it) }
                digest.equals(EXPECTED_RELEASE_CERT_SHA256, ignoreCase = true)
            }
        } catch (_: Throwable) {
            false
        }
    }

    private fun hookFrameworkLoaded(): Boolean {
        val markers = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XC_MethodHook",
            "de.robv.android.xposed.IXposedHookLoadPackage",
            "org.lsposed.lspd.core.Main",
            "org.lsposed.lspd.nativebridge.Yahfa",
            "io.github.lsposed.lspd.LSPApplication",
            "io.github.lsposed.lspd.core.Main",
        )
        return markers.any { marker ->
            try {
                Class.forName(marker)
                true
            } catch (_: Throwable) {
                false
            }
        }
    }

    private fun fridaInjected(): Boolean {
        val needles = listOf("frida-agent", "frida-gadget", "gum-js-loop", "linjector")
        return try {
            File("/proc/self/maps").bufferedReader().use { reader ->
                reader.lineSequence().any { line -> needles.any(line::contains) }
            }
        } catch (_: Throwable) {
            false
        }
    }

    private fun luckyPatcherInstalled(ctx: Context): Boolean {
        val packages = listOf(
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
        return packages.any { packageName ->
            try {
                ctx.packageManager.getPackageInfo(packageName, 0)
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
        return installer in setOf(
            "com.chelpus.lackypatch",
            "com.dimonvideo.luckypatcher",
            "com.forpda.lp",
            "uret.jasi2169.patcher",
            "zone.jasi2169.uretpatcher",
            "ru.aaaaaaac.luckypatcher",
        )
    }

    private fun rootMarkers(): List<String> = listOf(
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
    ).filter { path ->
        try {
            File(path).exists()
        } catch (_: Throwable) {
            false
        }
    }
}
