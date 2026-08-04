package com.understory.net.engine.crypto

/**
 * Salsa20 core + HSalsa20 + the XSalsa20 stream (Bernstein / NaCl) — PURE JVM.
 * The JDK ships no Salsa20, so DNSCrypt's es-version 1 cipher suite
 * (X25519-XSalsa20Poly1305, the same construction as NaCl `crypto_secretbox`)
 * has to be built here. Verified against the standard Salsa20 and NaCl HSalsa20
 * test vectors in [CryptoSelfTest]; if that self-test fails on a device, the
 * DNSCrypt es-version-1 path is refused rather than run with unverified crypto.
 *
 * All words are little-endian 32-bit, per the Salsa20 spec.
 */
internal object Salsa20 {

    private const val C0 = 0x61707865
    private const val C1 = 0x3320646e
    private const val C2 = 0x79622d32
    private const val C3 = 0x6b206574

    private fun rotl(v: Int, s: Int): Int = (v shl s) or (v ushr (32 - s))

    /** 20-round Salsa20 permutation of a 16-word state, in place. */
    private fun rounds(x: IntArray) {
        for (i in 0 until 10) {
            x[4] = x[4] xor rotl(x[0] + x[12], 7); x[8] = x[8] xor rotl(x[4] + x[0], 9)
            x[12] = x[12] xor rotl(x[8] + x[4], 13); x[0] = x[0] xor rotl(x[12] + x[8], 18)
            x[9] = x[9] xor rotl(x[5] + x[1], 7); x[13] = x[13] xor rotl(x[9] + x[5], 9)
            x[1] = x[1] xor rotl(x[13] + x[9], 13); x[5] = x[5] xor rotl(x[1] + x[13], 18)
            x[14] = x[14] xor rotl(x[10] + x[6], 7); x[2] = x[2] xor rotl(x[14] + x[10], 9)
            x[6] = x[6] xor rotl(x[2] + x[14], 13); x[10] = x[10] xor rotl(x[6] + x[2], 18)
            x[3] = x[3] xor rotl(x[15] + x[11], 7); x[7] = x[7] xor rotl(x[3] + x[15], 9)
            x[11] = x[11] xor rotl(x[7] + x[3], 13); x[15] = x[15] xor rotl(x[11] + x[7], 18)

            x[1] = x[1] xor rotl(x[0] + x[3], 7); x[2] = x[2] xor rotl(x[1] + x[0], 9)
            x[3] = x[3] xor rotl(x[2] + x[1], 13); x[0] = x[0] xor rotl(x[3] + x[2], 18)
            x[6] = x[6] xor rotl(x[5] + x[4], 7); x[7] = x[7] xor rotl(x[6] + x[5], 9)
            x[4] = x[4] xor rotl(x[7] + x[6], 13); x[5] = x[5] xor rotl(x[4] + x[7], 18)
            x[11] = x[11] xor rotl(x[10] + x[9], 7); x[8] = x[8] xor rotl(x[11] + x[10], 9)
            x[9] = x[9] xor rotl(x[8] + x[11], 13); x[10] = x[10] xor rotl(x[9] + x[8], 18)
            x[12] = x[12] xor rotl(x[15] + x[14], 7); x[13] = x[13] xor rotl(x[12] + x[15], 9)
            x[14] = x[14] xor rotl(x[13] + x[12], 13); x[15] = x[15] xor rotl(x[14] + x[13], 18)
        }
    }

    private fun le32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or
            ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or
            ((b[off + 3].toInt() and 0xFF) shl 24)

    private fun putLe32(b: ByteArray, off: Int, v: Int) {
        b[off] = v.toByte(); b[off + 1] = (v ushr 8).toByte()
        b[off + 2] = (v ushr 16).toByte(); b[off + 3] = (v ushr 24).toByte()
    }

    /**
     * HSalsa20: the keyed 16-byte→32-byte core used to derive the XSalsa20 subkey
     * and the X25519-XSalsa20 shared key (NaCl `crypto_core_hsalsa20`). Runs the
     * 20-round permutation with no feed-forward, then emits words 0,5,10,15,6,7,8,9.
     */
    fun hsalsa20(key: ByteArray, input16: ByteArray): ByteArray {
        require(key.size == 32 && input16.size == 16)
        val x = IntArray(16)
        x[0] = C0; x[5] = C1; x[10] = C2; x[15] = C3
        x[1] = le32(key, 0); x[2] = le32(key, 4); x[3] = le32(key, 8); x[4] = le32(key, 12)
        x[11] = le32(key, 16); x[12] = le32(key, 20); x[13] = le32(key, 24); x[14] = le32(key, 28)
        x[6] = le32(input16, 0); x[7] = le32(input16, 4); x[8] = le32(input16, 8); x[9] = le32(input16, 12)
        rounds(x)
        val out = ByteArray(32)
        putLe32(out, 0, x[0]); putLe32(out, 4, x[5]); putLe32(out, 8, x[10]); putLe32(out, 12, x[15])
        putLe32(out, 16, x[6]); putLe32(out, 20, x[7]); putLe32(out, 24, x[8]); putLe32(out, 28, x[9])
        return out
    }

    /** Salsa20 keystream (32-byte key, 8-byte nonce, 64-bit block counter from 0). */
    private fun stream(key: ByteArray, nonce8: ByteArray, len: Int): ByteArray {
        val out = ByteArray(len)
        var counter = 0L
        var pos = 0
        while (pos < len) {
            val x = IntArray(16)
            x[0] = C0; x[5] = C1; x[10] = C2; x[15] = C3
            x[1] = le32(key, 0); x[2] = le32(key, 4); x[3] = le32(key, 8); x[4] = le32(key, 12)
            x[11] = le32(key, 16); x[12] = le32(key, 20); x[13] = le32(key, 24); x[14] = le32(key, 28)
            x[6] = le32(nonce8, 0); x[7] = le32(nonce8, 4)
            x[8] = (counter and 0xffffffffL).toInt(); x[9] = (counter ushr 32).toInt()
            val orig = x.copyOf()
            rounds(x)
            val block = ByteArray(64)
            for (i in 0 until 16) putLe32(block, i * 4, x[i] + orig[i])
            val take = minOf(64, len - pos)
            System.arraycopy(block, 0, out, pos, take)
            pos += take
            counter++
        }
        return out
    }

    /**
     * XSalsa20 keystream: derive a subkey via [hsalsa20] over the first 16 nonce
     * bytes, then run Salsa20 with the remaining 8 nonce bytes. This is NaCl's
     * extended-nonce stream, the basis of `crypto_secretbox`.
     */
    fun xStream(key: ByteArray, nonce24: ByteArray, len: Int): ByteArray {
        require(key.size == 32 && nonce24.size == 24)
        val subkey = hsalsa20(key, nonce24.copyOfRange(0, 16))
        return stream(subkey, nonce24.copyOfRange(16, 24), len)
    }
}
