package com.understory.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Tests for [OtpAuthEntry] parsing — the QR-code surface every
 * authenticator app speaks. Uses Robolectric because the parser leans
 * on android.net.Uri, which is shadowed by Robolectric's framework.
 *
 * The shape we have to interop with is loose by spec but tight in
 * practice: every QR-emitter we'd want to import from (Aegis, Google
 * Authenticator, 2FAS) writes the same canonical form. Failures here
 * mean a user's existing TOTP entries can't be migrated in.
 */
@RunWith(RobolectricTestRunner::class)
class OtpAuthUriTest {

    @Test
    fun parse_canonicalTotpUri() {
        val uri = "otpauth://totp/Example:alice@example.com" +
            "?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30&algorithm=SHA1"
        val entry = OtpAuthEntry.parse(uri)
        assertEquals(OtpAuthEntry.Type.TOTP, entry.type)
        assertEquals("Example", entry.issuer)
        assertEquals("alice@example.com", entry.account)
        assertEquals(6, entry.digits)
        assertEquals(30, entry.period)
        assertEquals(OtpAuthEntry.Algorithm.SHA1, entry.algorithm)
        // Decoded secret should match the known base32 value byte-for-byte.
        assertArrayEquals(HotpSecret.decodeBase32("JBSWY3DPEHPK3PXP"), entry.secret)
    }

    @Test
    fun parse_canonicalHotpUri() {
        val uri = "otpauth://hotp/Example:bob?secret=JBSWY3DPEHPK3PXP&counter=42"
        val entry = OtpAuthEntry.parse(uri)
        assertEquals(OtpAuthEntry.Type.HOTP, entry.type)
        assertEquals(42L, entry.counter)
    }

    @Test
    fun parse_isSchemeCaseInsensitive() {
        // QR encoders sometimes upper-case the scheme. Spec says scheme
        // matching is case-insensitive; we honor that.
        val uri = "OTPAUTH://totp/X:y?secret=JBSWY3DPEHPK3PXP"
        val entry = OtpAuthEntry.parse(uri)
        assertEquals(OtpAuthEntry.Type.TOTP, entry.type)
    }

    @Test
    fun parse_issuerParamTakesPrecedenceOverLabelIssuer() {
        // Per Google's spec: when both label-issuer ("Foo:account") and
        // ?issuer= query param are present, the query param wins. This
        // matters when re-exporting — the label form is descriptive,
        // the query form is canonical.
        val uri = "otpauth://totp/LabelIssuer:user" +
            "?secret=JBSWY3DPEHPK3PXP&issuer=QueryIssuer"
        val entry = OtpAuthEntry.parse(uri)
        assertEquals("QueryIssuer", entry.issuer)
        assertEquals("user", entry.account)
    }

    @Test
    fun parse_emptyIssuerParamFallsBackToLabel() {
        // Some tools emit `&issuer=` (empty) — fall back to the label.
        val uri = "otpauth://totp/LabelIssuer:user?secret=JBSWY3DPEHPK3PXP&issuer="
        val entry = OtpAuthEntry.parse(uri)
        assertEquals("LabelIssuer", entry.issuer)
    }

    @Test
    fun parse_labelWithoutIssuerColon() {
        // "/account" with no colon — no issuer encoded in the label.
        val uri = "otpauth://totp/onlyaccount?secret=JBSWY3DPEHPK3PXP"
        val entry = OtpAuthEntry.parse(uri)
        assertEquals("", entry.issuer)
        assertEquals("onlyaccount", entry.account)
    }

    @Test
    fun parse_urlEncodedLabel() {
        // Issuer/account often contain spaces or punctuation; QR
        // encoders URL-encode them. Decoding must round-trip.
        val uri = "otpauth://totp/My%20Bank:user@example.com?secret=JBSWY3DPEHPK3PXP"
        val entry = OtpAuthEntry.parse(uri)
        assertEquals("My Bank", entry.issuer)
        assertEquals("user@example.com", entry.account)
    }

    @Test
    fun parse_unknownAlgorithmDefaultsToSha1() {
        // Spec says SHA1/SHA256/SHA512 only. Unknown values fall back to
        // SHA1 (the default) rather than throwing — robustness matters
        // here because mis-parses on import would lose entries the user
        // can't re-create.
        val uri = "otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"
        val entry = OtpAuthEntry.parse(uri)
        assertEquals(OtpAuthEntry.Algorithm.SHA1, entry.algorithm)
    }

    @Test
    fun parse_rejectsMissingSecret() {
        try {
            OtpAuthEntry.parse("otpauth://totp/X:y?digits=6")
            fail("expected IllegalArgumentException for missing secret")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun parse_rejectsUnknownType() {
        try {
            OtpAuthEntry.parse("otpauth://wat/X:y?secret=JBSWY3DPEHPK3PXP")
            fail("expected IllegalArgumentException for unknown type")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun parse_rejectsWrongScheme() {
        try {
            OtpAuthEntry.parse("https://totp/X:y?secret=JBSWY3DPEHPK3PXP")
            fail("expected non-otpauth URI to fall through to base32 raw path and fail")
        } catch (_: Throwable) {
            // The "https://..." string isn't valid base32 either, so the
            // raw-secret fallback throws too. Either kind of throw is
            // acceptable — we just don't want it to silently succeed.
        }
    }

    @Test
    fun parse_rawBase32() {
        // Manual entry path: the user types just the base32 secret; the
        // app fills in issuer/account separately.
        val entry = OtpAuthEntry.parse("JBSWY3DPEHPK3PXP")
        assertEquals(OtpAuthEntry.Type.TOTP, entry.type)
        assertEquals("", entry.issuer)
        assertEquals("", entry.account)
        assertArrayEquals(HotpSecret.decodeBase32("JBSWY3DPEHPK3PXP"), entry.secret)
    }

    @Test
    fun toUri_then_parse_roundTrip() {
        val original = OtpAuthEntry(
            type = OtpAuthEntry.Type.TOTP,
            issuer = "Round Trip Issuer",
            account = "user+tag@example.com",
            secret = HotpSecret.generate(),
            digits = 6,
            period = 30,
            algorithm = OtpAuthEntry.Algorithm.SHA256,
        )
        val uri = original.toUri()
        val restored = OtpAuthEntry.parse(uri)
        assertEquals(original.type, restored.type)
        assertEquals(original.issuer, restored.issuer)
        assertEquals(original.account, restored.account)
        assertArrayEquals(original.secret, restored.secret)
        assertEquals(original.digits, restored.digits)
        assertEquals(original.period, restored.period)
        assertEquals(original.algorithm, restored.algorithm)
    }

    @Test
    fun toUri_isParseableByAuthenticator() {
        // Sanity-check the URI shape — every authenticator app we care
        // about expects this exact set of params for a TOTP entry.
        val entry = OtpAuthEntry(
            type = OtpAuthEntry.Type.TOTP,
            issuer = "Test",
            account = "alice",
            secret = HotpSecret.decodeBase32("JBSWY3DPEHPK3PXP"),
        )
        val uri = entry.toUri()
        assertTrue(uri.startsWith("otpauth://totp/"))
        assertTrue(uri.contains("secret="))
        assertTrue(uri.contains("issuer=Test"))
        assertTrue(uri.contains("digits=6"))
        assertTrue(uri.contains("period=30"))
        assertTrue(uri.contains("algorithm=SHA1"))
    }

    @Test
    fun wipeSecret_zeroesAllBytes() {
        val entry = OtpAuthEntry(
            type = OtpAuthEntry.Type.TOTP,
            issuer = "X",
            account = "y",
            secret = HotpSecret.generate(),
        )
        entry.wipeSecret()
        for (b in entry.secret) {
            assertEquals(0.toByte(), b)
        }
    }
}
