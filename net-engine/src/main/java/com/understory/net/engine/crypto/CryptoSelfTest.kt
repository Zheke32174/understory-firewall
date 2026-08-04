package com.understory.net.engine.crypto

import javax.crypto.Cipher
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Runtime self-test for the DNSCrypt crypto stack. This is the honesty gate: the
 * app never offers a DNSCrypt cipher suite whose primitives don't reproduce a
 * known-answer vector on THIS device. Because [SecretBox.open] already fails
 * closed on a MAC mismatch (a broken cipher yields NO answer, never a WRONG one),
 * this test is about not advertising a dead transport, not about safety.
 *
 * What each primitive is checked against:
 *   - Poly1305   → RFC 8439 §2.5.2 known-answer vector.
 *   - ChaCha20   → cross-checked live against the platform `Cipher("ChaCha20")`
 *                  keystream (no vector to mis-transcribe).
 *   - HChaCha20  → draft-irtf-cfrg-xchacha §2.2.1 vector.
 *   - X25519     → RFC 7748 §5.2 vector.
 *   - Ed25519    → RFC 8032 §7.1 test 1, via the platform provider.
 *   - secretbox  → seal→open round-trip for both es-version cipher suites.
 *
 * es-version 2 (X25519-XChaCha20Poly1305) is [es2Ready] when its chain passes;
 * es-version 1 (X25519-XSalsa20Poly1305) is [es1Ready] likewise. The result is
 * computed once and cached.
 */
object CryptoSelfTest {

    data class Result(
        val poly1305: Boolean,
        val chacha20: Boolean,
        val hchacha20: Boolean,
        val salsaRoundTrip: Boolean,
        val xchachaRoundTrip: Boolean,
        val x25519: Boolean,
        val ed25519: Boolean,
    ) {
        /** es-version 2 upstream (XChaCha20) is trustworthy on this device. */
        val es2Ready: Boolean
            get() = poly1305 && chacha20 && hchacha20 && xchachaRoundTrip && x25519 && ed25519

        /** es-version 1 upstream (XSalsa20) is trustworthy on this device. */
        val es1Ready: Boolean
            get() = poly1305 && salsaRoundTrip && x25519 && ed25519

        /** Any DNSCrypt suite usable at all. */
        val anyReady: Boolean get() = es2Ready || es1Ready

        /** One-line human summary for the diagnostics/UI surface. */
        fun summary(): String = when {
            es2Ready && es1Ready -> "DNSCrypt crypto verified (es-version 1 + 2)."
            es2Ready -> "DNSCrypt crypto verified (es-version 2 / XChaCha20)."
            es1Ready -> "DNSCrypt crypto verified (es-version 1 / XSalsa20)."
            !ed25519 -> "DNSCrypt disabled: Ed25519 signature verification unavailable on this device."
            !x25519 -> "DNSCrypt disabled: X25519 self-test failed."
            else -> "DNSCrypt disabled: cipher self-test failed."
        }
    }

    @Volatile private var cached: Result? = null

    fun result(): Result = cached ?: run().also { cached = it }

    private fun run(): Result {
        val poly = runCatching { checkPoly1305() }.getOrDefault(false)
        val chacha = runCatching { checkChaCha20VsPlatform() }.getOrDefault(false)
        val hchacha = runCatching { checkHChaCha20() }.getOrDefault(false)
        val salsaRt = runCatching { roundTrip(SecretBox.Variant.XSALSA20) }.getOrDefault(false)
        val xchachaRt = runCatching { roundTrip(SecretBox.Variant.XCHACHA20) }.getOrDefault(false)
        val x = runCatching { checkX25519() }.getOrDefault(false)
        val ed = runCatching { checkEd25519() }.getOrDefault(false)
        return Result(poly, chacha, hchacha, salsaRt, xchachaRt, x, ed)
    }

    // ---- individual checks ----

    private fun checkPoly1305(): Boolean {
        val key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        val msg = "Cryptographic Forum Research Group".toByteArray(Charsets.US_ASCII)
        val expect = hex("a8061dc1305136c6c22b8baf0c0127a9")
        return Poly1305.mac(key, msg).contentEquals(expect)
    }

    private fun checkChaCha20VsPlatform(): Boolean {
        val key = ByteArray(32) { it.toByte() }
        val nonce = hex("000000090000004a00000000")
        val counter = 1
        val mine = ChaCha20.stream(key, nonce, counter, 64)
        val cipher = Cipher.getInstance("ChaCha20")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "ChaCha20"),
            ChaCha20ParameterSpec(nonce, counter),
        )
        val platform = cipher.doFinal(ByteArray(64)) // encrypting zeros == the keystream
        return mine.contentEquals(platform)
    }

    private fun checkHChaCha20(): Boolean {
        val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        val input = hex("000000090000004a0000000031415927")
        val expect = hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
        return ChaCha20.hchacha20(key, input).contentEquals(expect)
    }

    private fun checkX25519(): Boolean {
        val scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        val u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        val expect = hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        return X25519.scalarMult(scalar, u).contentEquals(expect)
    }

    private fun checkEd25519(): Boolean {
        if (!Ed25519Verify.isAvailable()) return false
        val pub = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        val sig = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555" +
                "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        return Ed25519Verify.verify(pub, ByteArray(0), sig)
    }

    private fun roundTrip(variant: SecretBox.Variant): Boolean {
        val key = ByteArray(32) { (it * 7 + 1).toByte() }
        val nonce = ByteArray(24) { (it * 3 + 2).toByte() }
        val msg = "the quick brown fox jumps over 13 lazy dogs".toByteArray()
        val boxed = SecretBox.seal(variant, key, nonce, msg)
        val opened = SecretBox.open(variant, key, nonce, boxed) ?: return false
        // Tamper check: flipping a ciphertext byte must fail open().
        val tampered = boxed.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        val mustBeNull = SecretBox.open(variant, key, nonce, tampered)
        return opened.contentEquals(msg) && mustBeNull == null
    }

    private fun hex(s: String): ByteArray {
        val clean = s.filterNot { it == ' ' || it == ':' || it == '\n' }
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            out[i] = ((digit(clean[i * 2]) shl 4) or digit(clean[i * 2 + 1])).toByte()
        }
        return out
    }

    private fun digit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("bad hex '$c'")
    }
}
