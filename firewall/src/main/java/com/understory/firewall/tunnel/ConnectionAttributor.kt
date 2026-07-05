package com.understory.firewall.tunnel

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import java.net.InetSocketAddress
import com.understory.security.Diagnostics

/**
 * Per-flow app attribution for the opt-in adblock-DNS tunnel (S6). Given the
 * 4-tuple of a captured packet, resolve which app owns the socket via
 * [ConnectivityManager.getConnectionOwnerUid] — the unprivileged, tun-scoped
 * API RethinkDNS uses (clean-room; credited in NOTICE).
 *
 * HONEST BOUNDARY: this only works while OUR tun is up (the S6 tunnel tier).
 * The slot-free policy tier has no tun and therefore no per-flow attribution —
 * that is stated in the visibility UI. getConnectionOwnerUid can also return
 * [INVALID_UID] for a flow that has already closed by the time we ask, or throw
 * SecurityException on some OEM builds; both degrade to "unknown app", never a
 * wrong attribution.
 *
 * A tiny bounded LRU caches (proto,srcPort)->uid so a burst of DNS from one app
 * costs one lookup, not one per query. DNS source ports are ephemeral and
 * unique per query in practice, so the cache mostly helps retries; it is capped
 * hard to stay O(1) memory.
 */
class ConnectionAttributor(private val appContext: Context) {

    private val cm: ConnectivityManager? =
        appContext.getSystemService(ConnectivityManager::class.java)

    private val pm: PackageManager = appContext.packageManager

    /** Bounded LRU: key = "proto:srcIp:srcPort" -> uid. accessOrder LRU. */
    private val uidCache = object : LinkedHashMap<String, Int>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Int>): Boolean =
            size > MAX_CACHE
    }

    /** Bounded uid -> label cache (labels don't change at runtime). */
    private val labelCache = HashMap<Int, String>()

    /**
     * Resolve the owning app uid for a UDP/TCP flow, or [INVALID_UID] when it
     * can't be determined. [protocol] is 6 (TCP) or 17 (UDP).
     */
    @Synchronized
    fun uidFor(
        protocol: Int,
        srcIp: String,
        srcPort: Int,
        dstIp: String,
        dstPort: Int,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return INVALID_UID
        if (protocol != PROTO_TCP && protocol != PROTO_UDP) return INVALID_UID
        val c = cm ?: return INVALID_UID

        val key = "$protocol:$srcIp:$srcPort"
        uidCache[key]?.let { return it }

        return try {
            val local = InetSocketAddress(srcIp, srcPort)
            val remote = InetSocketAddress(dstIp, dstPort)
            val uid = c.getConnectionOwnerUid(protocol, local, remote)
            if (uid >= Process.FIRST_APPLICATION_UID) uidCache[key] = uid
            uid
        } catch (t: Throwable) {
            Diagnostics.error(TAG, "getConnectionOwnerUid threw ${t.javaClass.simpleName}")
            INVALID_UID
        }
    }

    /** Best-effort human label for [uid]; degrades to "uid N" then "unknown app". */
    @Synchronized
    fun labelFor(uid: Int): String {
        if (uid == INVALID_UID) return "unknown app"
        labelCache[uid]?.let { return it }
        val label = runCatching {
            val pkgs = pm.getPackagesForUid(uid)
            val first = pkgs?.firstOrNull()
            if (first != null) {
                runCatching {
                    pm.getApplicationLabel(pm.getApplicationInfo(first, 0)).toString()
                }.getOrNull() ?: first
            } else {
                "uid $uid"
            }
        }.getOrDefault("uid $uid")
        labelCache[uid] = label
        return label
    }

    /** Best-effort package name for [uid], or null. */
    @Synchronized
    fun packageFor(uid: Int): String? {
        if (uid == INVALID_UID) return null
        return runCatching { pm.getPackagesForUid(uid)?.firstOrNull() }.getOrNull()
    }

    companion object {
        private const val TAG = "firewall.tunnel.ConnectionAttributor"
        const val INVALID_UID = -1
        const val PROTO_TCP = 6
        const val PROTO_UDP = 17
        private const val MAX_CACHE = 512
    }
}
