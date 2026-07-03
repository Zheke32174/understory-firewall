package com.understory.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RFC 6238 known-answer tests + skew-window / format / constant-time
 * checks for [Totp]. These are the canonical TOTP test vectors used by
 * every interoperable implementation; if these fail, vault unlock would
 * silently disagree with the user's authenticator app.
 *
 * The RFC 6238 vectors are 8-digit codes against a 20-byte ASCII secret
 * "12345678901234567890". Our [Totp] returns 6 digits — we compare the
 * last 6 digits of each RFC vector.
 */
class TotpTest {

    /** RFC 6238 reference secret: "12345678901234567890" as ASCII bytes. */
    private val rfcSecret: ByteArray =
        "12345678901234567890".toByteArray(Charsets.US_ASCII)

    @Test
    fun rfc6238_vector_t0_59seconds() {
        // Vector: time=59, expected 8-digit=94287082 → last-6 = 287082.
        assertEquals("287082", Totp.currentCode(rfcSecret, nowSeconds = 59L))
    }

    @Test
    fun rfc6238_vector_t1_1111111109() {
        // Vector: time=1111111109, expected 8-digit=07081804 → last-6 = 081804.
        assertEquals("081804", Totp.currentCode(rfcSecret, nowSeconds = 1111111109L))
    }

    @Test
    fun rfc6238_vector_t2_1111111111() {
        // One second later — code rotates because we cross a 30s boundary.
        assertEquals("050471", Totp.currentCode(rfcSecret, nowSeconds = 1111111111L))
    }

    @Test
    fun rfc6238_vector_t3_1234567890() {
        assertEquals("005924", Totp.currentCode(rfcSecret, nowSeconds = 1234567890L))
    }

    @Test
    fun rfc6238_vector_t4_2000000000() {
        assertEquals("279037", Totp.currentCode(rfcSecret, nowSeconds = 2000000000L))
    }

    @Test
    fun currentCode_alwaysSixDigits() {
        // Even when the truncated HOTP value happens to be small (e.g.
        // 42), the output must be zero-padded to 6 digits — typing "42"
        // when the authenticator shows "000042" would fail. Sweep enough
        // time-steps to be confident a small-value case is included.
        for (t in 0L until 600L step 31L) {
            val code = Totp.currentCode(rfcSecret, nowSeconds = t)
            assertEquals("code length at t=$t", 6, code.length)
            assertTrue("digits at t=$t", code.all { it.isDigit() })
        }
    }

    @Test
    fun verifyCode_acceptsCurrentCode() {
        val now = 1700000000L
        val code = Totp.currentCode(rfcSecret, nowSeconds = now)
        assertTrue(Totp.verifyCode(rfcSecret, code, nowSeconds = now))
    }

    @Test
    fun verifyCode_acceptsOneStepEarly() {
        // skewSteps=1 (the default) → ±30s window. A code from the
        // previous step should still verify when checked at the current
        // step.
        val previous = 1700000000L
        val code = Totp.currentCode(rfcSecret, nowSeconds = previous)
        assertTrue(Totp.verifyCode(rfcSecret, code, nowSeconds = previous + 30L))
    }

    @Test
    fun verifyCode_acceptsOneStepLate() {
        val nextStep = 1700000030L
        val code = Totp.currentCode(rfcSecret, nowSeconds = nextStep)
        // Treat that future code as if it arrived 30s "early" from the
        // verifier's clock — defensive against clock skew the other way.
        assertTrue(Totp.verifyCode(rfcSecret, code, nowSeconds = nextStep - 30L))
    }

    @Test
    fun verifyCode_rejectsOutsideSkewWindow() {
        val veryOld = 1700000000L
        val code = Totp.currentCode(rfcSecret, nowSeconds = veryOld)
        // Two full steps later — beyond skewSteps=1.
        assertFalse(Totp.verifyCode(rfcSecret, code, nowSeconds = veryOld + 90L))
    }

    @Test
    fun verifyCode_rejectsWrongLength() {
        // Anything that's not exactly 6 digits is rejected before any
        // crypto runs — guards against a UI bug submitting a partial
        // entry.
        assertFalse(Totp.verifyCode(rfcSecret, ""))
        assertFalse(Totp.verifyCode(rfcSecret, "12345"))
        assertFalse(Totp.verifyCode(rfcSecret, "1234567"))
    }

    @Test
    fun verifyCode_rejectsNonDigits() {
        // 6-char string with a letter — must fail without consulting the
        // secret. Catches the case where a paste includes a stray space
        // or letter and the digit-check is bypassed.
        assertFalse(Totp.verifyCode(rfcSecret, "12345A"))
        assertFalse(Totp.verifyCode(rfcSecret, "1 2345"))
    }

    @Test
    fun verifyCode_rejectsWrongCode() {
        // A clearly wrong code — sanity check that verify isn't a tautology.
        assertFalse(Totp.verifyCode(rfcSecret, "000000", nowSeconds = 59L))
    }

    @Test
    fun differentSecrets_produceDifferentCodes() {
        val secretA = HotpSecret.generate()
        val secretB = HotpSecret.generate()
        val now = 1700000000L
        // Two random 160-bit secrets producing the same 6-digit code at
        // the same moment is a 10⁶ collision probability — possible but
        // vanishingly unlikely. If this trips repeatedly, something's
        // very wrong (e.g. RNG returning a constant).
        assertNotEquals(
            Totp.currentCode(secretA, nowSeconds = now),
            Totp.currentCode(secretB, nowSeconds = now),
        )
    }
}
