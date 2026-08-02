package com.understory.godwall.ward

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PauseTest {

    @After
    fun tearDown() = Pause.resume()

    @Test
    fun `remaining never goes negative`() {
        assertEquals(0L, Pause.remainingAt(until = 1_000L, at = 5_000L))
        assertEquals(4_000L, Pause.remainingAt(until = 9_000L, at = 5_000L))
    }

    @Test
    fun `a duration is clamped into the allowed window`() {
        assertEquals(Pause.MAX_MS, Pause.clampDuration(Pause.MAX_MS * 10))
        assertEquals(0L, Pause.clampDuration(-1))
        assertEquals(Pause.DEFAULT_MS, Pause.clampDuration(Pause.DEFAULT_MS))
    }

    @Test
    fun `the countdown rounds up so it never shows zero while still paused`() {
        assertEquals("1:00", Pause.format(60_000))
        assertEquals("0:01", Pause.format(1))
        assertEquals("0:00", Pause.format(0))
        assertEquals("15:00", Pause.format(Pause.DEFAULT_MS))
    }

    @Test
    fun `pause then resume clears the stamp`() {
        Pause.pause(60_000)
        assertTrue(Pause.isPaused())
        Pause.resume()
        assertFalse(Pause.isPaused())
        assertEquals(0L, Pause.remainingMs())
    }

    @Test
    fun `adjusting down past zero resumes rather than leaving a stale pause`() {
        Pause.pause(Pause.STEP_MS)
        Pause.adjust(-Pause.STEP_MS * 2)
        assertFalse(Pause.isPaused())
    }

    @Test
    fun `adjusting an expired pause does not resurrect it`() {
        Pause.resume()
        Pause.adjust(Pause.STEP_MS)
        assertFalse(Pause.isPaused())
    }

    @Test
    fun `adding a step extends the remaining time`() {
        Pause.pause(2 * Pause.STEP_MS)
        val before = Pause.remainingMs()
        Pause.adjust(Pause.STEP_MS)
        // Wall clock moves between the two reads, so assert the step landed rather than an exact
        // value — the property under test is "it grew by about a minute", not millisecond parity.
        assertTrue(Pause.remainingMs() > before + Pause.STEP_MS - 2_000)
    }
}
