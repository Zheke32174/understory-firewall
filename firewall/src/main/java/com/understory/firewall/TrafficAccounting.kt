package com.understory.firewall

import android.app.AppOpsManager
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.net.NetworkCapabilities
import com.understory.security.Diagnostics

/**
 * Per-app traffic accounting via [NetworkStatsManager] (design-v2/firewall.md
 * §5.2). Honest, rootless answer to "who talked and how much" — observation,
 * NOT interception. Requires the special-access PACKAGE_USAGE_STATS grant
 * (Usage access); the screen degrades to a NeedsGrant affordance without it,
 * never a dead chart.
 *
 * All queries are meant to run on Dispatchers.IO (SUITE #8): the callers
 * wrap [query] in a coroutine on IO.
 */
object TrafficAccounting {

    /** One app's totals over the query window. [packages] is the shared-UID
     *  group (rendered honestly when >1). */
    data class AppTraffic(
        val uid: Int,
        val label: String,
        val packages: List<String>,
        val wifiBytes: Long,
        val cellBytes: Long,
    ) {
        val totalBytes: Long get() = wifiBytes + cellBytes
    }

    /** Query windows offered by the segmented control. */
    enum class Window(val label: String) {
        TODAY("Today"),
        WEEK("7 days"),
    }

    sealed interface Result {
        /** Usage access is not granted; the caller shows the opt-in. */
        data object NeedsGrant : Result
        data class Data(val apps: List<AppTraffic>) : Result
        data object Empty : Result
        data class Error(val message: String) : Result
    }

    /** True iff PACKAGE_USAGE_STATS is granted for this app. */
    fun hasUsageAccess(ctx: Context): Boolean {
        val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
            ?: return false
        return runCatching {
            @Suppress("DEPRECATION")
            val mode = ops.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(),
                ctx.packageName,
            )
            mode == AppOpsManager.MODE_ALLOWED
        }.getOrDefault(false)
    }

    /**
     * Run the accounting query. Must be called off the main thread. Returns
     * [Result.NeedsGrant] if usage access is missing (no throw). Sums
     * rx+tx per uid for WIFI and MOBILE over [window].
     */
    fun query(ctx: Context, window: Window): Result {
        if (!hasUsageAccess(ctx)) return Result.NeedsGrant

        val nsm = ctx.getSystemService(Context.NETWORK_STATS_SERVICE) as? NetworkStatsManager
            ?: return Result.Error("NetworkStatsManager unavailable on this device.")
        val pm = ctx.packageManager

        val now = System.currentTimeMillis()
        val start = when (window) {
            Window.TODAY -> startOfTodayMillis(now)
            Window.WEEK -> now - 7L * 24 * 60 * 60 * 1000
        }

        // uid -> [wifi, cell]
        val perUid = HashMap<Int, LongArray>()
        for (transport in intArrayOf(
            NetworkCapabilities.TRANSPORT_WIFI,
            NetworkCapabilities.TRANSPORT_CELLULAR,
        )) {
            val networkType = if (transport == NetworkCapabilities.TRANSPORT_WIFI)
                android.net.ConnectivityManager.TYPE_WIFI
            else android.net.ConnectivityManager.TYPE_MOBILE
            val bucketIsWifi = transport == NetworkCapabilities.TRANSPORT_WIFI
            runCatching {
                @Suppress("DEPRECATION")
                val stats = nsm.querySummary(networkType, null, start, now)
                val bucket = android.app.usage.NetworkStats.Bucket()
                while (stats.hasNextBucket()) {
                    stats.getNextBucket(bucket)
                    val uid = bucket.uid
                    val bytes = bucket.rxBytes + bucket.txBytes
                    val arr = perUid.getOrPut(uid) { LongArray(2) }
                    if (bucketIsWifi) arr[0] += bytes else arr[1] += bytes
                }
                stats.close()
            }.onFailure {
                Diagnostics.error(
                    "firewall.TrafficAccounting",
                    "querySummary($networkType) failed: ${it.javaClass.simpleName}: ${it.message}",
                )
                return Result.Error(
                    "Couldn't read traffic stats: ${it.javaClass.simpleName}. " +
                        "See Diagnostics.",
                )
            }
        }

        if (perUid.isEmpty()) return Result.Empty

        val apps = perUid.entries.mapNotNull { (uid, arr) ->
            if (arr[0] + arr[1] <= 0L) return@mapNotNull null
            val pkgs = runCatching { pm.getPackagesForUid(uid)?.toList() }
                .getOrNull().orEmpty()
            val label = pkgs.firstNotNullOfOrNull { pkg ->
                runCatching {
                    pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
                }.getOrNull()
            } ?: pkgs.firstOrNull() ?: "uid $uid"
            AppTraffic(
                uid = uid,
                label = label,
                packages = pkgs,
                wifiBytes = arr[0],
                cellBytes = arr[1],
            )
        }.sortedByDescending { it.totalBytes }

        return if (apps.isEmpty()) Result.Empty else Result.Data(apps)
    }

    private fun startOfTodayMillis(now: Long): Long {
        val cal = java.util.Calendar.getInstance()
        cal.timeInMillis = now
        cal.set(java.util.Calendar.HOUR_OF_DAY, 0)
        cal.set(java.util.Calendar.MINUTE, 0)
        cal.set(java.util.Calendar.SECOND, 0)
        cal.set(java.util.Calendar.MILLISECOND, 0)
        return cal.timeInMillis
    }

    /** Human byte size, e.g. "1.2 GB". */
    fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var v = bytes.toDouble() / 1024.0
        var i = 0
        while (v >= 1024.0 && i < units.size - 1) {
            v /= 1024.0
            i++
        }
        return String.format(java.util.Locale.US, "%.1f %s", v, units[i])
    }
}
