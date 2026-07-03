package com.understory.firewall

import java.util.concurrent.atomic.AtomicLong

/**
 * In-process counter for packets dropped by the VpnService reader. The
 * VpnService and MainActivity both run in the suite app's main process
 * (the manifest doesn't set android:process on the service), so this
 * singleton is observable from the UI without IPC.
 *
 * Phase B keeps this aggregate-only — no per-package attribution. The
 * tun is shared across all blocked apps and packet headers don't carry
 * the app identity directly; attributing per-packet would require either
 * parsing IPv4/IPv6 + TCP/UDP headers and calling
 * [android.net.ConnectivityManager.getConnectionOwnerUid] per flow, or
 * keeping a flow table. Both are real Phase-C work; this counter
 * deliberately stops short and just answers "is the firewall actually
 * doing anything right now?" — a question the silent drop loop didn't.
 */
object DropStats {
    private val packets = AtomicLong(0L)
    private val lastDropMillis = AtomicLong(0L)

    fun record() {
        packets.incrementAndGet()
        lastDropMillis.set(System.currentTimeMillis())
    }

    /** Total packets dropped since process start. */
    fun totalPackets(): Long = packets.get()

    /** Wall-clock millis of the last drop, or 0 if nothing dropped yet. */
    fun lastDropAt(): Long = lastDropMillis.get()

    /**
     * Reset the counters. Called when the VpnService is fully stopped
     * (not just rebuilt with a new ruleset) so the displayed total
     * tracks the current session, not lifetime-of-process.
     */
    fun reset() {
        packets.set(0L)
        lastDropMillis.set(0L)
    }
}
