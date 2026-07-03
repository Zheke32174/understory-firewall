package com.understory.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Round-trip and normalization tests for [RecoveryKeyCodec] and the
 * verifier/verify path on [VaultRecovery.RecoveryKey]. Robolectric runner
 * because [RecoveryKeyCodec] uses android.util.Base64 (same reason as
 * [CryptoTest]).
 */
@RunWith(RobolectricTestRunner::class)
class RecoveryKeyCodecTest {

    @Test
    fun encodeDecode_roundTrips32Bytes() {
        val raw = ByteArray(VaultRecovery.RECOVERY_KEY_BYTES) { it.toByte() }
        val chars = RecoveryKeyCodec.encode(raw)
        val back = RecoveryKeyCodec.decode(chars)
        assertArrayEquals(raw, back)
    }

    @Test
    fun normalize_stripsSpacesBackToCanonical() {
        val raw = ByteArray(VaultRecovery.RECOVERY_KEY_BYTES) { (it * 7).toByte() }
        val canonical = RecoveryKeyCodec.encode(raw)
        // Whitespace anywhere in user-entered input is stripped to canonical.
        val spaced = canonical.joinToString(" ").toCharArray()
        assertArrayEquals(canonical, RecoveryKeyCodec.normalize(spaced))
        assertArrayEquals(raw, RecoveryKeyCodec.decode(spaced))
    }

    @Test
    fun normalize_stripsWhitespaceToo() {
        val raw = ByteArray(VaultRecovery.RECOVERY_KEY_BYTES) { 0x41 }
        val canonical = RecoveryKeyCodec.encode(raw)
        val spaced = canonical.joinToString(" ")
        assertArrayEquals(canonical, RecoveryKeyCodec.normalize(spaced.toCharArray()))
    }

    @Test
    fun newRecoveryKey_isDistinctEachCall() {
        val a = VaultRecovery.newRecoveryKey()
        val b = VaultRecovery.newRecoveryKey()
        assertFalse(a.chars.concatToString() == b.chars.concatToString())
        assertEquals(VaultRecovery.RECOVERY_KEY_BYTES,
            RecoveryKeyCodec.decode(a.chars).size)
        a.wipe(); b.wipe()
    }

    @Test
    fun verifier_verifiesCorrectKeyAndRejectsWrongOne() {
        val key = VaultRecovery.newRecoveryKey()
        val salt = Crypto.randomBytes(Crypto.SALT_BYTES)
        val verifier = key.verifier(salt)

        // Re-derive the SAME key from its text form (simulating the user
        // re-entering it on a new device) and verify it matches.
        val reentered = VaultRecovery.recoveryKeyFrom(key.chars.copyOf())
        assertTrue(VaultRecovery.verifyRecoveryKey(reentered, verifier, salt))

        val wrong = VaultRecovery.newRecoveryKey()
        assertFalse(VaultRecovery.verifyRecoveryKey(wrong, verifier, salt))

        key.wipe(); reentered.wipe(); wrong.wipe()
    }

    @Test
    fun enroll_producesVerifierThatMatchesTheKey() {
        val key = VaultRecovery.newRecoveryKey()
        val st = VaultRecovery.enroll(key, itemCount = 3)
        assertEquals(3, st.lastExportItemCount)
        assertEquals(0L, st.lastExportMs)
        val reentered = VaultRecovery.recoveryKeyFrom(key.chars.copyOf())
        assertTrue(VaultRecovery.verifyRecoveryKey(reentered, st.verifier, st.verifierSalt))
        key.wipe(); reentered.wipe()
    }
}
