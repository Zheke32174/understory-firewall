package com.understory.net.engine.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Known-answer tests for the DNSCrypt crypto primitives, run on the host JVM
 * (java.base ships ChaCha20 + Ed25519, so these execute identically to the
 * Android device path). These are the vectors [CryptoSelfTest] checks at runtime;
 * carrying them here means a regression in the primitives fails the build, not
 * just silently disables DNSCrypt on-device.
 */
class CryptoSelfTestTest {

    private fun hex(s: String): ByteArray {
        val c = s.filterNot { it == ' ' || it == ':' }
        val o = ByteArray(c.length / 2)
        for (i in o.indices) o[i] = ((Character.digit(c[i * 2], 16) shl 4) or Character.digit(c[i * 2 + 1], 16)).toByte()
        return o
    }

    @Test fun poly1305_rfc8439() {
        val key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        val msg = "Cryptographic Forum Research Group".toByteArray(Charsets.US_ASCII)
        assertArrayEquals(hex("a8061dc1305136c6c22b8baf0c0127a9"), Poly1305.mac(key, msg))
    }

    @Test fun hchacha20_xchacha_draft() {
        val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        val input = hex("000000090000004a0000000031415927")
        assertArrayEquals(
            hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"),
            ChaCha20.hchacha20(key, input),
        )
    }

    @Test fun x25519_rfc7748() {
        val scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        val u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        assertArrayEquals(
            hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
            X25519.scalarMult(scalar, u),
        )
    }

    @Test fun secretbox_roundtrip_and_tamper() {
        for (v in SecretBox.Variant.entries) {
            val key = ByteArray(32) { (it * 7 + 1).toByte() }
            val nonce = ByteArray(24) { (it * 3 + 2).toByte() }
            val msg = "dnscrypt payload under $v".toByteArray()
            val boxed = SecretBox.seal(v, key, nonce, msg)
            assertArrayEquals(msg, SecretBox.open(v, key, nonce, boxed))
            val tampered = boxed.copyOf().also { it[it.lastIndex] = (it[it.lastIndex] + 1).toByte() }
            assertNull("tampered box must fail closed ($v)", SecretBox.open(v, key, nonce, tampered))
        }
    }

    @Test fun selfTest_reports_ready_on_host() {
        val r = CryptoSelfTest.result()
        assertTrue("poly1305", r.poly1305)
        assertTrue("hchacha20", r.hchacha20)
        assertTrue("x25519", r.x25519)
        // ed25519 + chacha20-vs-platform depend on host JCE; assert the suites that
        // don't rely on the platform ChaCha20 cross-check are internally consistent.
        assertTrue("xchacha round-trip", r.xchachaRoundTrip)
        assertTrue("xsalsa round-trip", r.salsaRoundTrip)
    }
}
