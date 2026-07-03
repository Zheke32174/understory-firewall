package com.understory.overlay.i2p

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Tests for the [I2pStatus] state singleton. Compose's `mutableStateOf`
 * runs on plain JVM as long as we don't enter a Composable scope, so
 * these tests don't need Robolectric.
 *
 * The singleton state means we must reset between tests — a previous
 * test's transition would leak into the next one.
 */
class I2pStatusTest {

    @Before
    fun resetToIdle() {
        I2pStatus.update(I2pStatus.State.Idle)
    }

    @After
    fun cleanup() {
        I2pStatus.update(I2pStatus.State.Idle)
    }

    @Test
    fun initialState_isIdle() {
        // The class doc claims "default state at process boot is Idle" —
        // pin it. (Our @Before resets here too; this test is essentially
        // checking that Idle is a valid sentinel.)
        assertSame(I2pStatus.State.Idle, I2pStatus.state)
    }

    @Test
    fun update_transitionsThroughLifecycle() {
        I2pStatus.update(I2pStatus.State.BinaryMissing)
        assertSame(I2pStatus.State.BinaryMissing, I2pStatus.state)

        I2pStatus.update(I2pStatus.State.Starting)
        assertSame(I2pStatus.State.Starting, I2pStatus.state)

        I2pStatus.update(I2pStatus.State.Ready(httpPort = 4444, socksPort = 4447))
        val ready = I2pStatus.state
        assertTrue(ready is I2pStatus.State.Ready)
        assertEquals(4444, (ready as I2pStatus.State.Ready).httpPort)
        assertEquals(4447, ready.socksPort)

        I2pStatus.update(I2pStatus.State.Error("reseed unreachable"))
        val err = I2pStatus.state
        assertTrue(err is I2pStatus.State.Error)
        assertEquals("reseed unreachable", (err as I2pStatus.State.Error).reason)
    }

    @Test
    fun ready_dataClassEqualityHonorsBothPorts() {
        // The Ready state is data-class so consumers can use it as a
        // key in caches / pinned receivers. Equality must consider
        // both port fields.
        val a = I2pStatus.State.Ready(httpPort = 4444, socksPort = 4447)
        val b = I2pStatus.State.Ready(httpPort = 4444, socksPort = 4447)
        val cDifferentSocks = I2pStatus.State.Ready(httpPort = 4444, socksPort = 9999)
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertTrue(a != cDifferentSocks)
    }

    @Test
    fun error_dataClassEqualityHonorsReason() {
        val a = I2pStatus.State.Error("foo")
        val b = I2pStatus.State.Error("foo")
        val c = I2pStatus.State.Error("bar")
        assertEquals(a, b)
        assertTrue(a != c)
    }

    @Test
    fun states_areExhaustivelyTyped() {
        // Compile-time check: a `when` over the sealed class must
        // remain exhaustive when every state is enumerated. If a future
        // refactor adds a new State without updating call sites, this
        // pattern catches it at the test compile (the IDE would too,
        // but tests run in CI, IDE warnings don't always).
        for (state in listOf(
            I2pStatus.State.Idle,
            I2pStatus.State.BinaryMissing,
            I2pStatus.State.Starting,
            I2pStatus.State.Ready(0, 0),
            I2pStatus.State.Error("x"),
        )) {
            val label: String = when (state) {
                is I2pStatus.State.Idle -> "idle"
                is I2pStatus.State.BinaryMissing -> "missing"
                is I2pStatus.State.Starting -> "starting"
                is I2pStatus.State.Ready -> "ready"
                is I2pStatus.State.Error -> "error"
            }
            assertTrue(label.isNotBlank())
        }
    }
}
