package com.understory.security

import org.bouncycastle.util.encoders.Base32
import java.util.Locale

/**
 * Generate / encode HOTP secrets in the format authenticator apps expect.
 *
 * Standard authenticator apps (Aegis, Google Authenticator, 2FAS, etc.)
 * scan an `otpauth://` URI containing the secret as base32. We generate
 * 160 bits (RFC 6238 recommendation), encode as uppercase base32 without
 * padding. The resulting URI is what the QR-encoder turns into the
 * single on-screen secret in the app's lifetime — shown once at vault
 * setup, scanned once into the authenticator, then sealed as entry[1]
 * of the vault.
 */
object HotpSecret {
    /** RFC 6238 recommends 160 bits (20 bytes) of secret. */
    const val SECRET_BYTES: Int = 20

    /**
     * Generate a fresh 160-bit secret as raw bytes. Caller wipes after
     * use; pair with [encodeBase32] to produce the value the
     * authenticator app needs.
     */
    fun generate(): ByteArray = java.security.SecureRandom().let { val out = ByteArray(SECRET_BYTES); it.nextBytes(out); out }

    /**
     * Encode raw secret bytes as authenticator-compatible base32:
     * uppercase, no padding, no whitespace.
     */
    fun encodeBase32(secret: ByteArray): String {
        val raw = String(Base32.encode(secret), Charsets.US_ASCII)
        return raw.trimEnd('=')
    }

    /**
     * Decode a base32 string back to raw bytes. Used during recovery
     * when the user types or scans a secret on a new device.
     * Tolerates lower/uppercase, embedded whitespace, missing padding.
     */
    fun decodeBase32(encoded: String): ByteArray {
        // Reasonable upper bound: TOTP/HOTP secrets are 16-32 bytes per
        // RFC 4226; nothing legitimate exceeds 64 bytes raw. 64 bytes
        // base32-encoded fits in ~104 chars; cap at 1024 chars input to
        // leave generous headroom for whitespace/dashes/padding while
        // still rejecting a malicious QR carrying megabytes of "secret".
        require(encoded.length <= MAX_BASE32_LEN) { "base32 secret too long" }
        // Locale.ROOT for the case fold: in Turkish locale (the default
        // form .uppercase() consults), lowercase 'i' -> 'İ' (U+0130) and
        // 'I' -> 'ı' (U+0131), neither of which is in the base32 alphabet.
        // A user with 'i' anywhere in their secret would see import fail
        // silently on a Turkish-locale phone. ROOT pins ASCII semantics.
        val cleaned = encoded
            .uppercase(Locale.ROOT)
            .filter { it.isLetterOrDigit() }
        val padded = cleaned + "=".repeat((8 - cleaned.length % 8) % 8)
        return Base32.decode(padded)
    }

    private const val MAX_BASE32_LEN = 1024

    /**
     * Build the `otpauth://totp/...` URI that the QR-encoder turns into
     * the single visible secret of the app's lifetime. Issuer and label
     * are user-visible strings in the authenticator app's entry list.
     *
     * Format follows Google's de-facto standard (Aegis, 2FAS, Google
     * Authenticator all parse this).
     */
    fun otpauthUri(
        secretBase32: String,
        label: String = "vault",
        issuer: String = "passgen",
    ): String {
        val labelEnc = label.replace(" ", "%20")
        val issuerEnc = issuer.replace(" ", "%20")
        return "otpauth://totp/$issuerEnc:$labelEnc" +
            "?secret=$secretBase32" +
            "&issuer=$issuerEnc" +
            "&digits=6&period=30&algorithm=SHA1"
    }
}
