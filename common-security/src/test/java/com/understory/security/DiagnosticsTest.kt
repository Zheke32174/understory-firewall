package com.understory.security

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Sanity check: Diagnostics writes events, snapshots them in order, and
 * exports them. Runs entirely in JVM via Robolectric — no emulator,
 * no /dev/kvm needed.
 *
 * The point of this first test is to confirm the whole Robolectric
 * toolchain works in this environment. Once green, we add tests for
 * the trickier stuff (Stage.valueOf round-trip, transient-flight
 * counter under concurrent begin/end, BackHandler integration).
 */
@RunWith(RobolectricTestRunner::class)
class DiagnosticsTest {

    @After
    fun tearDown() {
        Diagnostics.clear()
    }

    @Test
    fun log_appendsEventInOrder() {
        Diagnostics.clear()
        Diagnostics.log("test", "first")
        Diagnostics.log("test", "second")
        Diagnostics.warn("test", "third (warn)")
        Diagnostics.error("test", "fourth (error)")

        val events = Diagnostics.snapshot()
        // clear() itself appends a "ring cleared" event; expect 5 total.
        assertEquals(5, events.size)
        assertEquals("ring cleared", events[0].message)
        assertEquals("first", events[1].message)
        assertEquals("second", events[2].message)
        assertEquals(Diagnostics.Level.WARN, events[3].level)
        assertEquals(Diagnostics.Level.ERROR, events[4].level)
    }

    @Test
    fun formatForExport_includesAllEvents() {
        Diagnostics.clear()
        Diagnostics.log("alpha", "hello")
        Diagnostics.log("beta", "world")

        val dump = Diagnostics.formatForExport()
        assertTrue("dump contains alpha tag", dump.contains("alpha"))
        assertTrue("dump contains beta tag", dump.contains("beta"))
        assertTrue("dump contains hello", dump.contains("hello"))
        assertTrue("dump contains world", dump.contains("world"))
    }

    @Test
    fun ringIsBoundedAtMaxEvents() {
        Diagnostics.clear()
        // Push more than the cap (250) and confirm the oldest are evicted.
        repeat(300) { i -> Diagnostics.log("flood", "event-$i") }
        val events = Diagnostics.snapshot()
        assertTrue("snapshot bounded ≤ 250", events.size <= 250)
        // Newest event must still be there.
        assertEquals("event-299", events.last().message)
    }
}
