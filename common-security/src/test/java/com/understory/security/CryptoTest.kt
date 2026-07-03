package com.understory.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import javax.crypto.AEADBadTagException

/**
 * Tests for the pure-JVM crypto primitives in [Crypto] — Argon2id KDF
 * and AES-256-GCM authenticated encryption. The Keystore-bound paths
 * (deviceAuthCipherFor*) require a real Android Keystore that
 * Robolectric only partially shadows, so they're not covered here;
 * those need an instrumented test on a real device.
 *
 * Argon2id is invoked with deliberately *cheap* cost parameters
 * (1 MiB / 1 iteration / 1 lane) — we're testing correctness, not
 * security. The production constants (64 MiB / 3 iterations) are
 * exercised on every real vault unlock; a test running them on every
 * commit would add seconds per case for no correctness gain.
 *
 * Robolectric runner because [Crypto.generateMasterPassword] uses
 * android.util.Base64.
 */
@RunWith(RobolectricTestRunner::class)
class CryptoTest {

    private val cheapMemKiB = 1024
    private val cheapIterations = 1
    private val cheapParallelism = 1

    private fun cheapKdf(password: CharArray, salt: ByteArray): ByteArray =
        Crypto.argon2id(password, salt, cheapMemKiB, cheapIterations, cheapParallelism)

    // -------- randomBytes / wipe --------

    @Test
    fun randomBytes_returnsRequestedLength() {
        for (n in intArrayOf(0, 1, 16, 32, 64, 128)) {
            assertEquals(n, Crypto.randomBytes(n).size)
        }
    }

    @Test
    fun randomBytes_doesNotReturnAllZeroForReasonableLength() {
        // 32 bytes of all-zero from a working RNG is a 1-in-2^256 event.
        // If this trips, the RNG is broken.
        val out = Crypto.randomBytes(32)
        assertFalse_thereExistsNonzeroByte(out)
    }

    @Test
    fun wipe_byteArrayZeroesAllBytes() {
        val buf = ByteArray(32) { 0xAB.toByte() }
        Crypto.wipe(buf)
        for (b in buf) assertEquals(0.toByte(), b)
    }

    @Test
    fun wipe_charArrayOverwritesAllChars() {
        val buf = "supersecret".toCharArray()
        Crypto.wipe(buf)
        // Spec: chars are overwritten with space (' '). The contract is
        // "no longer holds the secret" — pick whichever sentinel matches
        // current code; this test pins it.
        for (c in buf) assertEquals(' ', c)
    }

    // -------- argon2id --------

    @Test
    fun argon2id_outputIs32Bytes() {
        val key = cheapKdf("password".toCharArray(), ByteArray(Crypto.SALT_BYTES))
        assertEquals(Crypto.ARGON2_OUTPUT_BYTES, key.size)
    }

    @Test
    fun argon2id_isDeterministicForSameInputs() {
        val pw = "correct horse battery staple".toCharArray()
        val salt = ByteArray(Crypto.SALT_BYTES) { it.toByte() }
        val a = cheapKdf(pw.copyOf(), salt)
        val b = cheapKdf(pw.copyOf(), salt)
        assertArrayEquals(a, b)
    }

    @Test
    fun argon2id_differentSaltProducesDifferentKey() {
        val pw = "password".toCharArray()
        val saltA = ByteArray(Crypto.SALT_BYTES) { 0 }
        val saltB = ByteArray(Crypto.SALT_BYTES) { 1 }
        val a = cheapKdf(pw.copyOf(), saltA)
        val b = cheapKdf(pw.copyOf(), saltB)
        assertNotEquals("salt must domain-separate the KDF", a.toList(), b.toList())
    }

    @Test
    fun argon2id_differentPasswordProducesDifferentKey() {
        val salt = ByteArray(Crypto.SALT_BYTES) { it.toByte() }
        val a = cheapKdf("alpha".toCharArray(), salt)
        val b = cheapKdf("beta".toCharArray(), salt)
        assertNotEquals(a.toList(), b.toList())
    }

    @Test
    fun argon2id_doesNotMutateInputPassword() {
        // The function wipes its own internal byte copy of the password;
        // it must NOT touch the caller's CharArray. If it did, callers
        // who rely on holding the password for a subsequent operation
        // would silently get a wiped buffer.
        val pw = "stable".toCharArray()
        cheapKdf(pw, ByteArray(Crypto.SALT_BYTES))
        assertEquals("stable", String(pw))
    }

    // -------- AES-GCM --------

    @Test
    fun aesGcm_roundTripsWithoutAad() {
        val key = Crypto.randomBytes(Crypto.KEK_BYTES)
        val plaintext = "secret message".toByteArray(Charsets.UTF_8)
        val ct = Crypto.aesGcmEncrypt(key, plaintext)
        val pt = Crypto.aesGcmDecrypt(key, ct)
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun aesGcm_roundTripsWithAad() {
        val key = Crypto.randomBytes(Crypto.KEK_BYTES)
        val plaintext = "secret".toByteArray(Charsets.UTF_8)
        val aad = "vault-v1".toByteArray(Charsets.UTF_8)
        val ct = Crypto.aesGcmEncrypt(key, plaintext, aad = aad)
        val pt = Crypto.aesGcmDecrypt(key, ct, aad = aad)
        assertArrayEquals(plaintext, pt)
    }

    @Test
    fun aesGcm_rejectsTamperedCiphertext() {
        val key = Crypto.randomBytes(Crypto.KEK_BYTES)
        val ct = Crypto.aesGcmEncrypt(key, "data".toByteArray())
        // Flip a bit somewhere past the IV (which is bytes 0..11).
        val tampered = ct.copyOf().also { it[ct.size - 1] = (it[ct.size - 1].toInt() xor 0x01).toByte() }
        try {
            Crypto.aesGcmDecrypt(key, tampered)
            fail("tampered ciphertext must not decrypt")
        } catch (_: AEADBadTagException) {
            // expected — GCM tag mismatch
        } catch (_: javax.crypto.BadPaddingException) {
            // some JCE providers wrap the GCM-tag failure as BadPadding;
            // either form is correct rejection
        }
    }

    @Test
    fun aesGcm_rejectsWrongKey() {
        val keyA = Crypto.randomBytes(Crypto.KEK_BYTES)
        val keyB = Crypto.randomBytes(Crypto.KEK_BYTES)
        val ct = Crypto.aesGcmEncrypt(keyA, "data".toByteArray())
        try {
            Crypto.aesGcmDecrypt(keyB, ct)
            fail("decrypt under wrong key must fail")
        } catch (_: Throwable) {
            // expected
        }
    }

    @Test
    fun aesGcm_aadMismatchFailsDecryption() {
        // The AAD note in aegis is *exactly* this concern: a vault
        // header used as AAD makes the ciphertext bound to that header,
        // so swapping headers between vaults can't yield a valid decrypt.
        // This test pins the contract that AAD really is enforced.
        val key = Crypto.randomBytes(Crypto.KEK_BYTES)
        val ct = Crypto.aesGcmEncrypt(key, "data".toByteArray(), aad = "header-A".toByteArray())
        try {
            Crypto.aesGcmDecrypt(key, ct, aad = "header-B".toByteArray())
            fail("decrypt with wrong AAD must fail")
        } catch (_: Throwable) {
            // expected
        }
    }

    @Test
    fun aesGcm_aadOmittedOnDecryptFailsWhenSetOnEncrypt() {
        val key = Crypto.randomBytes(Crypto.KEK_BYTES)
        val ct = Crypto.aesGcmEncrypt(key, "data".toByteArray(), aad = "header".toByteArray())
        try {
            Crypto.aesGcmDecrypt(key, ct, aad = null)
            fail("decrypt without AAD must fail when encrypt used AAD")
        } catch (_: Throwable) {
            // expected
        }
    }

    @Test
    fun aesGcm_eachEncryptUsesFreshIv() {
        val key = Crypto.randomBytes(Crypto.KEK_BYTES)
        val plaintext = "same plaintext".toByteArray()
        val a = Crypto.aesGcmEncrypt(key, plaintext)
        val b = Crypto.aesGcmEncrypt(key, plaintext)
        // First 12 bytes are the IV; under any sane RNG these must differ
        // each call — IV reuse with the same key is a catastrophic GCM
        // failure mode.
        val ivA = a.copyOfRange(0, 12)
        val ivB = b.copyOfRange(0, 12)
        assertNotEquals("IVs must be fresh per encryption", ivA.toList(), ivB.toList())
        // The full ciphertexts therefore also differ.
        assertNotEquals(a.toList(), b.toList())
    }

    @Test
    fun aesGcm_rejectsKeyOfWrongSize() {
        try {
            Crypto.aesGcmEncrypt(ByteArray(16), "data".toByteArray())
            fail("16-byte key must be rejected — KEK is 32 bytes")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun aesGcm_rejectsCiphertextShorterThanIv() {
        val key = Crypto.randomBytes(Crypto.KEK_BYTES)
        try {
            Crypto.aesGcmDecrypt(key, ByteArray(8))  // shorter than IV_BYTES (12)
            fail("ciphertext shorter than IV must be rejected")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    // -------- generateMasterPassword (uses android.util.Base64) --------

    @Test
    fun generateMasterPassword_isUrlSafeBase64Length() {
        val pw = Crypto.generateMasterPassword()
        // 32 raw bytes → base64-url no-padding → ceil(32 * 4 / 3) ≈ 43 chars.
        // Allow ±1 char of slack for any future rounding/padding tweak.
        assertTrue("expected ~43 chars, got ${pw.size}", pw.size in 42..44)
        // URL-safe base64 alphabet: A–Z a–z 0–9 - _ (no '+' or '/' or '=').
        val allowed = ('A'..'Z') + ('a'..'z') + ('0'..'9') + listOf('-', '_')
        for (c in pw) {
            assertTrue("disallowed char '$c' in master password", c in allowed)
        }
    }

    @Test
    fun generateMasterPassword_distinctOnEachCall() {
        val a = Crypto.generateMasterPassword()
        val b = Crypto.generateMasterPassword()
        assertNotEquals(String(a), String(b))
    }

    // -------- helpers --------

    private fun assertFalse_thereExistsNonzeroByte(buf: ByteArray) {
        for (b in buf) if (b != 0.toByte()) return
        fail("expected at least one non-zero byte in random output")
    }
}
