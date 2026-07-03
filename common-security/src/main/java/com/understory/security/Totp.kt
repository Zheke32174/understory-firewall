package com.understory.security

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 6238 TOTP / RFC 4226 HOTP code generator.
 *
 * Stage 2C uses this as the second factor for vault unlock: at vault
 * setup, passgen self-generates a 160-bit HOTP secret (see [HotpSecret]),
 * shows it ONCE as a QR code for the user to scan into their authenticator
 * app (Aegis, Google Authenticator, 2FAS, etc.), and seals it as
 * entry[1] of the vault. To unlock daily, the user enters the current
 * 6-digit TOTP code from their authenticator alongside BiometricPrompt.
 * The TOTP check is fully offline — no network roundtrip, no shared
 * server state.
 *
 * Stage 2D extends this: instead of typing the code, plug in a USB drive
 * holding the same HOTP secret; the app reads, computes the current code
 * internally, no typing required.
 *
 * Algorithm: HMAC-SHA1, 6 digits, 30-second period — the de-facto
 * standard every major authenticator app emits by default.
 */
object Totp {
    private const val DEFAULT_PERIOD_SECONDS: Int = 30
    private const val DEFAULT_DIGITS: Int = 6
    private const val ALGORITHM = "HmacSHA1"

    /**
     * Compute the current TOTP code for [secret] at time [nowSeconds].
     * Returns a fixed-length zero-padded decimal string of [DEFAULT_DIGITS]
     * digits.
     */
    fun currentCode(
        secret: ByteArray,
        nowSeconds: Long = System.currentTimeMillis() / 1000L,
    ): String {
        val counter = nowSeconds / DEFAULT_PERIOD_SECONDS
        return hotpCode(secret, counter, DEFAULT_DIGITS)
    }

    /**
     * Verify a user-typed [code] against [secret] with [skewSteps] worth
     * of tolerance on either side of the current step. Default ±1 step
     * (±30 seconds) handles the clock drift typically present between an
     * authenticator app and our device. Higher [skewSteps] would weaken
     * security; don't go above ±2.
     *
     * Constant-time string compare to avoid timing-channel discovery of
     * partial code matches.
     */
    fun verifyCode(
        secret: ByteArray,
        code: String,
        nowSeconds: Long = System.currentTimeMillis() / 1000L,
        skewSteps: Int = 1,
    ): Boolean {
        if (code.length != DEFAULT_DIGITS) return false
        if (!code.all { it.isDigit() }) return false
        val center = nowSeconds / DEFAULT_PERIOD_SECONDS
        for (offset in -skewSteps..skewSteps) {
            val candidate = hotpCode(secret, center + offset, DEFAULT_DIGITS)
            if (constantTimeEquals(candidate, code)) return true
        }
        return false
    }

    /**
     * Raw RFC 4226 HOTP. Counter is whatever monotonic value the caller
     * chose; for TOTP it's `unixSeconds / period`.
     */
    private fun hotpCode(secret: ByteArray, counter: Long, digits: Int): String {
        val counterBytes = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) {
            counterBytes[i] = (c and 0xFF).toByte()
            c = c ushr 8
        }
        val mac = Mac.getInstance(ALGORITHM).apply {
            init(SecretKeySpec(secret, ALGORITHM))
        }
        val hash = mac.doFinal(counterBytes)
        val offset = hash[hash.size - 1].toInt() and 0x0F
        val truncated =
            ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        var mod = 1
        repeat(digits) { mod *= 10 }
        val codeInt = truncated % mod
        return codeInt.toString().padStart(digits, '0')
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].code xor b[i].code)
        }
        return result == 0
    }
}
