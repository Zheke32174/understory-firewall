package com.understory.firewall.tunnel

import java.util.concurrent.atomic.AtomicLong

/**
 * In-process ring buffer of DNS-filtering events for the connection-visibility
 * surface (S7). Same-process as the VpnService (no android:process on the
 * service), so the UI observes it without IPC — the DropStats pattern, extended
 * to carry per-event detail.
 *
 * Lean, clean-room (PCAPdroid's ConnectionsRegister is a far richer per-flow
 * ring; we log only what the DNS-filtering tunnel actually sees — a domain, the
 * owning app, and allow/block — credited in NOTICE). Bounded to [CAPACITY]
 * newest events; older events roll off. Aggregate per-app counts are kept
 * separately so a cleared ring still shows lifetime-of-session totals until the
 * user clears those too.
 *
 * HONESTY: events are recorded ONLY by the S6 tunnel while it is running (real
 * per-flow DNS data). When the tunnel is off, this log is empty and the
 * visibility screen shows the slot-free policy block COUNTERS instead (which are
 * not per-domain — the policy tier has no tun and cannot see domains). We never
 * fabricate domain-level events without the tun.
 */
object DnsEventLog {

    /**
     * One DNS-filtering decision. [blocked] = sinkholed as an ad/tracker. [seq]
     * is a process-monotonic id that makes every event uniquely keyable in a
     * LazyColumn — two queries (A + AAAA) for the same domain from the same app
     * can share a millisecond timestamp, so the timestamp alone is NOT a safe key.
     */
    data class Event(
        val seq: Long,
        val timestampMillis: Long,
        val domain: String,
        val appLabel: String,
        val appUid: Int,
        val blocked: Boolean,
    )

    private const val CAPACITY = 500

    private val ring = ArrayDeque<Event>(CAPACITY)
    private val lock = Any()

    private val seqCounter = AtomicLong(0L)
    private val totalQueries = AtomicLong(0L)
    private val totalBlocked = AtomicLong(0L)

    /** Per-app aggregate counts: uid -> [queries, blocked]. */
    private val perApp = HashMap<Int, LongArray>()
    private val perAppLabel = HashMap<Int, String>()

    fun record(domain: String, appLabel: String, appUid: Int, blocked: Boolean) {
        val e = Event(
            seq = seqCounter.incrementAndGet(),
            timestampMillis = System.currentTimeMillis(),
            domain = domain,
            appLabel = appLabel,
            appUid = appUid,
            blocked = blocked,
        )
        synchronized(lock) {
            if (ring.size >= CAPACITY) ring.removeFirst()
            ring.addLast(e)
            val counts = perApp.getOrPut(appUid) { LongArray(2) }
            counts[0]++
            if (blocked) counts[1]++
            perAppLabel[appUid] = appLabel
        }
        totalQueries.incrementAndGet()
        if (blocked) totalBlocked.incrementAndGet()
    }

    /** Newest-first snapshot of up to [limit] recent events. */
    fun recent(limit: Int = CAPACITY): List<Event> = synchronized(lock) {
        ring.toList().asReversed().take(limit)
    }

    /** Per-app aggregate rows, sorted by total queries desc. */
    data class AppCount(val uid: Int, val label: String, val queries: Long, val blocked: Long)

    fun perAppCounts(): List<AppCount> = synchronized(lock) {
        perApp.entries.map { (uid, c) ->
            AppCount(uid, perAppLabel[uid] ?: "uid $uid", c[0], c[1])
        }.sortedByDescending { it.queries }
    }

    fun totalQueries(): Long = totalQueries.get()
    fun totalBlocked(): Long = totalBlocked.get()

    /** True once at least one event has been recorded this session. */
    fun hasData(): Boolean = totalQueries.get() > 0L

    /** Clear the ring + aggregates. Called by the user's Clear action and on a
     *  full tunnel stop, so counts track the current session. */
    fun clear() {
        synchronized(lock) {
            ring.clear()
            perApp.clear()
            perAppLabel.clear()
        }
        totalQueries.set(0L)
        totalBlocked.set(0L)
        seqCounter.set(0L)
    }

    /**
     * Render the current log as a plain-text export (newest first). Domain-only,
     * app label, verdict, timestamp — no packet contents (there are none to
     * leak; the tunnel reads DNS question names, not payloads).
     */
    fun exportText(): String {
        val sb = StringBuilder()
        sb.append("Understory Net Audit — DNS event log\n")
        sb.append("queries=${totalQueries.get()} blocked=${totalBlocked.get()}\n\n")
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
        for (e in recent(CAPACITY)) {
            val verdict = if (e.blocked) "BLOCK" else "allow"
            sb.append("${fmt.format(java.util.Date(e.timestampMillis))}  $verdict  ${e.domain}  (${e.appLabel})\n")
        }
        return sb.toString()
    }
}
