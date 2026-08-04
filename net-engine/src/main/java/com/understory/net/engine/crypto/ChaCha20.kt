package com.understory.net.engine.crypto

/**
 * ChaCha20 core + HChaCha20 + the XChaCha20 stream (RFC 8439 + draft-irtf-cfrg-
 * xchacha) — PURE JVM. The JDK's `ChaCha20-Poly1305` Cipher exists (API 28+) but
 * only in the 12-byte-nonce IETF AEAD form; DNSCrypt's es-version 2 suite uses the
 * NaCl-style X25519-XChaCha20Poly1305 secretbox (24-byte nonce, keystream-prefix
 * MAC key), so the stream is built here to match that construction exactly.
 * Verified against the RFC 8439 §2.4.2 ChaCha20 block and the XChaCha20 draft
 * HChaCha20 vector in [CryptoSelfTest]; a failing self-test disables the
 * es-version-2 path rather than running unverified crypto.
 */
internal object ChaCha20 {

    private const val C0 = 0x61707865
    private const val C1 = 0x3320646e
    private const val C2 = 0x79622d32
    private const val C3 = 0x6b206574

    private fun rotl(v: Int, s: Int): Int = (v shl s) or (v ushr (32 - s))

    private fun qr(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 16)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 12)
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 8)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 7)
    }

    private fun rounds(x: IntArray) {
        for (i in 0 until 10) {
            qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15)
            qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14)
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

    private fun initState(x: IntArray, key: ByteArray, counter: Int, nonce12: ByteArray) {
        x[0] = C0; x[1] = C1; x[2] = C2; x[3] = C3
        for (i in 0 until 8) x[4 + i] = le32(key, i * 4)
        x[12] = counter
        x[13] = le32(nonce12, 0); x[14] = le32(nonce12, 4); x[15] = le32(nonce12, 8)
    }

    /** HChaCha20: 32-byte key + 16-byte input → 32-byte subkey (no feed-forward). */
    fun hchacha20(key: ByteArray, input16: ByteArray): ByteArray {
        require(key.size == 32 && input16.size == 16)
        val x = IntArray(16)
        x[0] = C0; x[1] = C1; x[2] = C2; x[3] = C3
        for (i in 0 until 8) x[4 + i] = le32(key, i * 4)
        for (i in 0 until 4) x[12 + i] = le32(input16, i * 4)
        rounds(x)
        val out = ByteArray(32)
        putLe32(out, 0, x[0]); putLe32(out, 4, x[1]); putLe32(out, 8, x[2]); putLe32(out, 12, x[3])
        putLe32(out, 16, x[12]); putLe32(out, 20, x[13]); putLe32(out, 24, x[14]); putLe32(out, 28, x[15])
        return out
    }

    /** ChaCha20 (IETF) keystream: 32-byte key, 12-byte nonce, 32-bit counter from [initialCounter]. */
    fun stream(key: ByteArray, nonce12: ByteArray, initialCounter: Int, len: Int): ByteArray {
        val out = ByteArray(len)
        var counter = initialCounter
        var pos = 0
        while (pos < len) {
            val x = IntArray(16)
            initState(x, key, counter, nonce12)
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
     * XChaCha20 keystream: HChaCha20 subkey from key + first 16 nonce bytes, then
     * ChaCha20 with nonce (0x00000000 ‖ last 8 nonce bytes) and counter from 0.
     * This is libsodium's `crypto_stream_xchacha20`, the stream under the
     * es-version-2 secretbox.
     */
    fun xStream(key: ByteArray, nonce24: ByteArray, len: Int): ByteArray {
        require(key.size == 32 && nonce24.size == 24)
        val subkey = hchacha20(key, nonce24.copyOfRange(0, 16))
        val nonce12 = ByteArray(12)
        System.arraycopy(nonce24, 16, nonce12, 4, 8)
        return stream(subkey, nonce12, 0, len)
    }
}
