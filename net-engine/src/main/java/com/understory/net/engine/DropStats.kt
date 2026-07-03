package com.understory.net.engine

import java.util.concurrent.atomic.AtomicLong

/**
 * In-process counter for packets dropped by the Standalone engine's tun
 * reader. The VpnService and the app UI run in the same process (the
 * manifest doesn't set android:process on the service), so this singleton
 * is observable from the UI without IPC.
 *
 * Aggregate-only — no per-package attribution (the tun is shared across
 * blocked apps and headers don't carry the app identity). It answers "is
 * the engine actually intercepting right now?" and nothing more.
 *
 * HONESTY (design-v2/firewall.md §9): this counter is rendered ONLY in the
 * Standalone-armed, tun-established state. In Companion the engine never
 * runs, so a "0 dropped" readout would be a false adjacency implying
 * enforcement — the counter is simply absent there.
 */
object DropStats {
    private val packets = AtomicLong(0L)
    private val lastDropMillis = AtomicLong(0L)

    fun record() {
        packets.incrementAndGet()
        lastDropMillis.set(System.currentTimeMillis())
    }

    /** Total packets dropped since the current engine session started. */
    fun totalPackets(): Long = packets.get()

    /** Wall-clock millis of the last drop, or 0 if nothing dropped yet. */
    fun lastDropAt(): Long = lastDropMillis.get()

    /** Reset the counters. Called when the engine is fully stopped (not
     *  on the rule-change re-establish), so the total tracks the current
     *  session, not lifetime-of-process. */
    fun reset() {
        packets.set(0L)
        lastDropMillis.set(0L)
    }
}
