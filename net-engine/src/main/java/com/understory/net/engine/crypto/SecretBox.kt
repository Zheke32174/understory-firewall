package com.understory.net.engine.crypto

/**
 * NaCl-style authenticated encryption (secretbox) over an extended-nonce stream
 * cipher + [Poly1305] — PURE JVM. This is the exact construction DNSCrypt uses
 * for its two cipher suites:
 *
 *   [Variant.XSALSA20] — X25519-XSalsa20Poly1305 (es-version 1), NaCl
 *       `crypto_secretbox_xsalsa20poly1305`.
 *   [Variant.XCHACHA20] — X25519-XChaCha20Poly1305 (es-version 2), libsodium
 *       `crypto_secretbox_xchacha20poly1305`.
 *
 * Layout (both variants): the cipher keystream's first 32 bytes are the Poly1305
 * one-time key; the ciphertext is the plaintext XORed with the keystream from
 * byte 32 on; the boxed output is `tag(16) ‖ ciphertext`. [open] recomputes and
 * constant-time-verifies the tag before returning plaintext, and FAILS CLOSED
 * (null) on any mismatch — a forged or corrupted response is never decrypted.
 */
internal object SecretBox {

    enum class Variant { XSALSA20, XCHACHA20 }

    private fun keystream(variant: Variant, key: ByteArray, nonce24: ByteArray, len: Int): ByteArray =
        when (variant) {
            Variant.XSALSA20 -> Salsa20.xStream(key, nonce24, len)
            Variant.XCHACHA20 -> ChaCha20.xStream(key, nonce24, len)
        }

    /** Seal [plaintext] → `tag(16) ‖ ciphertext`. */
    fun seal(variant: Variant, key: ByteArray, nonce24: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == 32 && nonce24.size == 24)
        val ks = keystream(variant, key, nonce24, 32 + plaintext.size)
        val ct = ByteArray(plaintext.size)
        for (i in plaintext.indices) ct[i] = (plaintext[i].toInt() xor ks[32 + i].toInt()).toByte()
        val macKey = ks.copyOfRange(0, 32)
        val tag = Poly1305.mac(macKey, ct)
        return tag + ct
    }

    /** Open `tag(16) ‖ ciphertext`. Returns null on a bad tag or a too-short box. */
    fun open(variant: Variant, key: ByteArray, nonce24: ByteArray, boxed: ByteArray): ByteArray? {
        require(key.size == 32 && nonce24.size == 24)
        if (boxed.size < 16) return null
        val ctLen = boxed.size - 16
        val ks = keystream(variant, key, nonce24, 32 + ctLen)
        val macKey = ks.copyOfRange(0, 32)
        val tag = Poly1305.mac(macKey, boxed, 16, ctLen)
        val given = boxed.copyOfRange(0, 16)
        if (!Poly1305.verify(tag, given)) return null
        val pt = ByteArray(ctLen)
        for (i in 0 until ctLen) pt[i] = (boxed[16 + i].toInt() xor ks[32 + i].toInt()).toByte()
        return pt
    }
}
