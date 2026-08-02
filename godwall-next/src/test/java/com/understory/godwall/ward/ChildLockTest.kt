package com.understory.godwall.ward

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Only the parts that do not touch Android: `android.util.Base64` and SharedPreferences are
 * stubs in a JVM unit test, so the storage round trip is out of reach here. The derivation and
 * the comparison are the security-relevant halves and they are both pure JCA.
 */
class ChildLockTest {

    private val salt = ByteArray(16) { it.toByte() }

    @Test
    fun `the same PIN and salt derive the same key`() {
        assertArrayEquals(ChildLock.derive("1234", salt), ChildLock.derive("1234", salt))
    }

    @Test
    fun `a different PIN derives a different key`() {
        assertFalse(
            ChildLock.constantTimeEquals(
                ChildLock.derive("1234", salt),
                ChildLock.derive("1235", salt),
            ),
        )
    }

    @Test
    fun `a different salt derives a different key — so two devices never share a digest`() {
        val other = ByteArray(16) { (it + 1).toByte() }
        assertFalse(
            ChildLock.constantTimeEquals(
                ChildLock.derive("1234", salt),
                ChildLock.derive("1234", other),
            ),
        )
    }

    @Test
    fun `the comparison is length-safe and value-correct`() {
        assertTrue(ChildLock.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3)))
        assertFalse(ChildLock.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2)))
        assertFalse(ChildLock.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 4)))
        assertTrue(ChildLock.constantTimeEquals(ByteArray(0), ByteArray(0)))
    }

    @Test
    fun `the derived key is a full 256 bits`() {
        assertTrue(ChildLock.derive("1234", salt).size == 32)
    }
}
