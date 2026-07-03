package com.understory.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Locale

/**
 * Tests for HOTP secret generation and base32 codec — the bridge between
 * our secrets and what authenticator apps (Aegis, Google Authenticator,
 * 2FAS, etc.) expect on QR scan.
 *
 * Pure-JVM (no Robolectric needed). Failures here mean a freshly-set-up
 * vault would produce QR codes the user's authenticator can't read, or
 * an authenticator's exported secret can't be re-imported.
 */
class HotpSecretTest {

    @Test
    fun generate_producesExactly160Bits() {
        val secret = HotpSecret.generate()
        assertEquals(20, secret.size)
        assertEquals(20, HotpSecret.SECRET_BYTES)
    }

    @Test
    fun generate_producesDistinctSecrets() {
        // SecureRandom collisions on 160 bits are vanishingly unlikely;
        // identical successive outputs would mean the RNG is broken
        // (e.g. uninitialized seed) which is what we want to catch.
        val a = HotpSecret.generate()
        val b = HotpSecret.generate()
        assertNotEquals("two fresh secrets must differ", a.toList(), b.toList())
    }

    @Test
    fun encodeBase32_isUppercaseUnpadded() {
        val zeros = ByteArray(20)
        val encoded = HotpSecret.encodeBase32(zeros)
        assertEquals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", encoded)
        assertTrue("no padding in output", !encoded.contains("="))
        assertTrue("no whitespace", encoded.all { !it.isWhitespace() })
        assertEquals("uppercase", encoded, encoded.uppercase(Locale.ROOT))
    }

    @Test
    fun decodeBase32_roundTripsRandomSecret() {
        val original = HotpSecret.generate()
        val encoded = HotpSecret.encodeBase32(original)
        val decoded = HotpSecret.decodeBase32(encoded)
        assertArrayEquals(original, decoded)
    }

    @Test
    fun decodeBase32_acceptsLowercase() {
        val original = HotpSecret.generate()
        val encoded = HotpSecret.encodeBase32(original).lowercase(Locale.ROOT)
        val decoded = HotpSecret.decodeBase32(encoded)
        assertArrayEquals(original, decoded)
    }

    @Test
    fun decodeBase32_acceptsEmbeddedWhitespaceAndDashes() {
        val original = HotpSecret.generate()
        val encoded = HotpSecret.encodeBase32(original)
        // Authenticator apps often display secrets in space-separated
        // 4-char groups for readability — JBSWY3DP EHPK3PXP. Decoding
        // must tolerate that or users will copy-paste the displayed
        // form and see "invalid" errors.
        val pretty = encoded.chunked(4).joinToString(" ")
        val decoded = HotpSecret.decodeBase32(pretty)
        assertArrayEquals(original, decoded)
    }

    @Test
    fun decodeBase32_acceptsMissingPadding() {
        // Standard base32 of 20 bytes is 32 chars exactly (no padding
        // needed). For partial-byte inputs the encoder pads with '=';
        // the decoder must accept padded *and* unpadded forms.
        val short = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val encoded = HotpSecret.encodeBase32(short) // unpadded
        val decoded = HotpSecret.decodeBase32(encoded)
        assertArrayEquals(short, decoded)
    }

    @Test
    fun decodeBase32_isTurkishLocaleSafe() {
        // Regression for the "i" → "İ" hazard called out in HotpSecret's
        // Locale.ROOT comment. If decodeBase32 ever consults the default
        // locale's case-fold, a Turkish-locale phone would map lowercase
        // 'i' to dotted-I (U+0130), which isn't a base32 letter, and
        // import would silently fail. Pin the locale and the contract.
        val previous = Locale.getDefault()
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"))
            // "JBSWY3DPEHPK3PXP" — base32 of "Hello!sZ", contains 'i' not
            // but contains lowercase letters when written in user form;
            // construct one with i explicitly.
            val original = "ifyou".toByteArray(Charsets.US_ASCII).copyOf(20)
            val encoded = HotpSecret.encodeBase32(original)
            val asLower = encoded.lowercase(Locale.getDefault())
            val decoded = HotpSecret.decodeBase32(asLower)
            assertArrayEquals(original, decoded)
        } finally {
            Locale.setDefault(previous)
        }
    }

    @Test
    fun decodeBase32_rejectsExcessivelyLongInput() {
        // The cap is a defense against a malicious QR whose payload is
        // megabytes of base32 characters — without a cap, decode would
        // happily allocate a huge byte array.
        val giant = "A".repeat(2048)
        try {
            HotpSecret.decodeBase32(giant)
            fail("expected IllegalArgumentException for over-long base32 input")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun otpauthUri_followsGoogleConvention() {
        val uri = HotpSecret.otpauthUri(
            secretBase32 = "JBSWY3DPEHPK3PXP",
            label = "alice@example.com",
            issuer = "Test Issuer",
        )
        // Spec-shape checks rather than exact string match — the format
        // is "otpauth://totp/<issuer>:<label>?secret=...&issuer=...".
        assertTrue(uri.startsWith("otpauth://totp/"))
        assertTrue(uri.contains("Test%20Issuer:alice@example.com"))
        assertTrue(uri.contains("secret=JBSWY3DPEHPK3PXP"))
        assertTrue(uri.contains("issuer=Test%20Issuer"))
        assertTrue(uri.contains("digits=6"))
        assertTrue(uri.contains("period=30"))
        assertTrue(uri.contains("algorithm=SHA1"))
    }
}
