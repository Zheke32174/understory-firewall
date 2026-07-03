package com.understory.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Crypto primitives for the local password vault.
 *
 *   Argon2id   — KDF, memory-hard, derives a 256-bit KEK from the user's
 *                master password (slows offline brute force on a stolen vault).
 *   AES-256-GCM — symmetric authenticated encryption of vault contents.
 *                 Considered post-quantum-safe (Grover halves effective key
 *                 strength to 128 bits, still well above any plausible attack).
 *   Android Keystore (AES-256-GCM, hardware-backed where available) — wraps
 *                 the user's Argon2id-derived key. Result: even with the
 *                 master password, the vault cannot be decrypted on a
 *                 different physical device.
 *
 * Phase 2 will add ML-KEM-1024 hybrid: an additional independent key wrap
 * whose private key is encrypted under the master password, making the
 * vault un-decryptable even if a CRQC ever broke the Keystore RSA/EC chain.
 */
object Crypto {

    private const val KEYSTORE = "AndroidKeyStore"
    // The device-auth-bound key that wraps the vault master KEK. Authentication
    // (BiometricPrompt with BIOMETRIC_STRONG | DEVICE_CREDENTIAL) is required
    // for every operation. The cipher must be wrapped in BiometricPrompt's
    // CryptoObject; only after onAuthenticationSucceeded does cipher.doFinal
    // succeed.
    private const val DEVICE_AUTH_KEY_ALIAS = "passgen_vault_device_auth_v1"
    private const val GCM_TAG_BITS = 128
    private const val IV_BYTES = 12
    const val SALT_BYTES = 32
    const val KEK_BYTES = 32

    const val ARGON2_MEMORY_KIB = 64 * 1024  // 64 MiB
    const val ARGON2_ITERATIONS = 3
    const val ARGON2_PARALLELISM = 1
    const val ARGON2_OUTPUT_BYTES = 32

    private val rng = SecureRandom()

    fun randomBytes(n: Int): ByteArray {
        val out = ByteArray(n)
        rng.nextBytes(out)
        return out
    }

    fun wipe(buf: ByteArray) { for (i in buf.indices) buf[i] = 0 }
    fun wipe(buf: CharArray) { for (i in buf.indices) buf[i] = ' ' }

    fun argon2id(
        password: CharArray,
        salt: ByteArray,
        memoryKiB: Int = ARGON2_MEMORY_KIB,
        iterations: Int = ARGON2_ITERATIONS,
        parallelism: Int = ARGON2_PARALLELISM,
    ): ByteArray {
        val passBytes = charArrayToUtf8(password)
        try {
            val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(memoryKiB)
                .withIterations(iterations)
                .withParallelism(parallelism)
                .withSalt(salt)
                .build()
            val gen = Argon2BytesGenerator()
            gen.init(params)
            val out = ByteArray(ARGON2_OUTPUT_BYTES)
            gen.generateBytes(passBytes, out)
            return out
        } finally {
            wipe(passBytes)
        }
    }

    fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        require(key.size == KEK_BYTES) { "key must be $KEK_BYTES bytes" }
        val iv = randomBytes(IV_BYTES)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        val ct = cipher.doFinal(plaintext)
        val out = ByteArray(IV_BYTES + ct.size)
        System.arraycopy(iv, 0, out, 0, IV_BYTES)
        System.arraycopy(ct, 0, out, IV_BYTES, ct.size)
        return out
    }

    fun aesGcmDecrypt(key: ByteArray, ivAndCiphertext: ByteArray, aad: ByteArray? = null): ByteArray {
        require(key.size == KEK_BYTES) { "key must be $KEK_BYTES bytes" }
        require(ivAndCiphertext.size > IV_BYTES) { "ciphertext too short" }
        val iv = ivAndCiphertext.copyOfRange(0, IV_BYTES)
        val ct = ivAndCiphertext.copyOfRange(IV_BYTES, ivAndCiphertext.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(ct)
    }

    /**
     * Returns a Cipher initialized for ENCRYPT under the device-auth-bound
     * Keystore key. Caller must wrap this in BiometricPrompt.CryptoObject and
     * authenticate before calling doFinal — the cipher will throw
     * UserNotAuthenticatedException otherwise.
     */
    fun deviceAuthCipherForEncrypt(): Cipher {
        val key = ensureDeviceAuthKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher
    }

    /**
     * Returns a Cipher initialized for DECRYPT under the device-auth key with
     * the supplied IV. Same authentication requirement as the encrypt path.
     */
    fun deviceAuthCipherForDecrypt(iv: ByteArray): Cipher {
        val key = readDeviceAuthKey() ?: error("device-auth key missing")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher
    }

    fun deviceAuthKeyExists(): Boolean = readDeviceAuthKey() != null

    private fun readDeviceAuthKey(): SecretKey? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(DEVICE_AUTH_KEY_ALIAS)) return null
        return (ks.getEntry(DEVICE_AUTH_KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private fun ensureDeviceAuthKey(): SecretKey {
        readDeviceAuthKey()?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            DEVICE_AUTH_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            // 0 timeout = require authentication for every cryptographic
            // operation. AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL allows
            // either fingerprint/face OR the device PIN/pattern as fallback.
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            // Invalidate the key if biometric enrollment changes (new
            // fingerprint added → wrap key destroyed → vault re-bind needed).
            .setInvalidatedByBiometricEnrollment(true)
            .apply { runCatching { setIsStrongBoxBacked(true) } }
            .build()
        kg.init(spec)
        return kg.generateKey()
    }

    fun deleteDeviceAuthKey() {
        runCatching {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            if (ks.containsAlias(DEVICE_AUTH_KEY_ALIAS)) ks.deleteEntry(DEVICE_AUTH_KEY_ALIAS)
        }
    }

    /**
     * Generate a vault master password. 32 random bytes → base64-url
     * (~43 chars, ~190 bits of entropy).
     */
    fun generateMasterPassword(): CharArray {
        val raw = randomBytes(32)
        try {
            val b64 = android.util.Base64.encodeToString(
                raw,
                android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE,
            )
            return b64.toCharArray()
        } finally {
            wipe(raw)
        }
    }

    private fun charArrayToUtf8(chars: CharArray): ByteArray {
        val cb = java.nio.CharBuffer.wrap(chars)
        val bb = java.nio.charset.StandardCharsets.UTF_8.encode(cb)
        val bytes = ByteArray(bb.remaining())
        bb.get(bytes)
        if (bb.hasArray()) {
            val arr = bb.array()
            for (i in arr.indices) arr[i] = 0
        }
        return bytes
    }
}
