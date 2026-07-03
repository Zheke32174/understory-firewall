package com.understory.firewall

import android.content.Context
import android.provider.Settings
import com.understory.security.Diagnostics

/**
 * Programmatic Android Private DNS configuration. The "set Private DNS
 * automatically rather than make the user paste a hostname into Settings"
 * path the user asked for.
 *
 * Reality check: setting `Settings.Global.PRIVATE_DNS_MODE` and
 * `Settings.Global.PRIVATE_DNS_SPECIFIER` requires the
 * `android.permission.WRITE_SECURE_SETTINGS` permission, which is
 * **signature-level**. A user-installed third-party APK CAN'T be
 * granted this from runtime UI; the user has to grant it via ADB:
 *
 *   adb shell pm grant com.understory.firewall \
 *     android.permission.WRITE_SECURE_SETTINGS
 *
 * Once granted (it persists across reboots until the app is uninstalled
 * or the user manually revokes via `adb shell pm revoke ...`), this
 * helper succeeds. Without the grant it returns [Result.NeedsAdbGrant]
 * and the caller falls back to the deep-link path that was already in
 * place.
 *
 * We intentionally do NOT request WRITE_SECURE_SETTINGS in the manifest
 * via `tools:node="replace"` or similar — that wouldn't help (it's a
 * signature permission; the manifest declaration just lets the runtime
 * know to look for the grant). We DO declare it as a uses-permission
 * so the grant call has a target to attach to.
 */
object PrivateDnsApplier {

    sealed class Result {
        /** The set succeeded. Android Private DNS is now using [hostname]. */
        data class Applied(val hostname: String) : Result()

        /** WRITE_SECURE_SETTINGS isn't granted. Fall back to the deep-link
         *  path or run the ADB grant command shown in [adbCommand]. */
        data class NeedsAdbGrant(val adbCommand: String) : Result()

        /** The set was attempted but Settings.Global rejected the value
         *  (provider returned false). Rare; usually a permissions issue
         *  surfacing as an unrelated SecurityException. */
        data class Failed(val reason: String) : Result()
    }

    private const val PERM = "android.permission.WRITE_SECURE_SETTINGS"
    private const val MODE_KEY = "private_dns_mode"
    private const val SPECIFIER_KEY = "private_dns_specifier"

    /** True if the activity has the WRITE_SECURE_SETTINGS grant from
     *  ADB. Stable across recompositions; the grant doesn't change at
     *  runtime without an explicit ADB revoke. */
    fun hasGrant(ctx: Context): Boolean {
        return ctx.checkCallingOrSelfPermission(PERM) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
    }

    /** Apply [hostname] as the device's Private DNS specifier in
     *  hostname mode. If the grant is missing, returns [Result.NeedsAdbGrant]
     *  with the exact command the user can run from a connected machine. */
    fun apply(ctx: Context, hostname: String): Result {
        if (!hasGrant(ctx)) {
            return Result.NeedsAdbGrant(
                "adb shell pm grant ${ctx.packageName} $PERM",
            )
        }
        val ok = runCatching {
            // "hostname" mode tells Android to use the specifier as a
            // strict-DoT server name. The other valid modes are "off"
            // and "opportunistic" (auto-detect, fallback to plain DNS).
            // We always set hostname mode here — opportunistic isn't
            // what users mean when they say "use Cloudflare DoT".
            val resolver = ctx.contentResolver
            Settings.Global.putString(resolver, MODE_KEY, "hostname") &&
                Settings.Global.putString(resolver, SPECIFIER_KEY, hostname)
        }
        return when {
            ok.isSuccess && ok.getOrDefault(false) -> {
                Diagnostics.log("firewall.PrivateDnsApplier",
                    "set Private DNS specifier: $hostname")
                Result.Applied(hostname)
            }
            ok.isSuccess -> Result.Failed("Settings.Global.putString returned false")
            else -> {
                val msg = ok.exceptionOrNull()?.message ?: "unknown"
                Diagnostics.error("firewall.PrivateDnsApplier",
                    "set Private DNS failed: $msg")
                Result.Failed(msg)
            }
        }
    }

    /** Disable Private DNS (set mode to "off"). Same grant requirement. */
    fun clear(ctx: Context): Result {
        if (!hasGrant(ctx)) {
            return Result.NeedsAdbGrant(
                "adb shell pm grant ${ctx.packageName} $PERM",
            )
        }
        return runCatching {
            Settings.Global.putString(ctx.contentResolver, MODE_KEY, "off")
        }.fold(
            onSuccess = {
                if (it) Result.Applied("(off)")
                else Result.Failed("putString returned false")
            },
            onFailure = { Result.Failed(it.message ?: "unknown") },
        )
    }
}
