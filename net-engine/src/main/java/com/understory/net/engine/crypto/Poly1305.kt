package com.understory.net.engine.crypto

import java.math.BigInteger

/**
 * Poly1305 one-time authenticator (RFC 8439 §2.5) — PURE JVM, no platform crypto
 * dependency, so it is unit-testable off-device and behaves identically on every
 * Android version. Used by [SecretBox] to build the NaCl/DNSCrypt AEAD
 * constructions the JDK does not ship (XSalsa20-Poly1305, XChaCha20-Poly1305).
 *
 * Correctness over speed: the field arithmetic uses [BigInteger] mod (2^130 − 5)
 * rather than hand-rolled 26-bit limbs. DNS messages are tiny (a few hundred
 * bytes), so this is never on a hot path where the constant factor matters, and
 * BigInteger removes a whole class of carry-propagation bugs. Verified against
 * the RFC 8439 §2.5.2 test vector in [CryptoSelfTest].
 *
 * The MAC is a ONE-TIME authenticator: the 32-byte [key] (r‖s) must never be
 * reused across two messages. The AEAD callers derive a fresh key per message
 * from the cipher keystream, which is exactly this requirement.
 */
internal object Poly1305 {

    private val P: BigInteger = BigInteger.TWO.pow(130).subtract(BigInteger.valueOf(5))
    private val MASK128: BigInteger = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)

    /** Compute the 16-byte tag over [msg] with the 32-byte one-time [key] (r‖s). */
    fun mac(key: ByteArray, msg: ByteArray, msgOff: Int, msgLen: Int): ByteArray {
        require(key.size == 32) { "Poly1305 key must be 32 bytes" }
        val r = clampR(key)
        val s = leBytesToBigInt(key, 16, 16)

        var acc = BigInteger.ZERO
        var i = 0
        while (i < msgLen) {
            val block = minOf(16, msgLen - i)
            // n = little-endian block, then append a 1 bit above the top byte.
            var n = leBytesToBigInt(msg, msgOff + i, block)
            n = n.add(BigInteger.ONE.shiftLeft(8 * block))
            acc = acc.add(n).multiply(r).mod(P)
            i += block
        }
        acc = acc.add(s).and(MASK128)
        return bigIntToLeBytes(acc, 16)
    }

    fun mac(key: ByteArray, msg: ByteArray): ByteArray = mac(key, msg, 0, msg.size)

    /** Constant-ish comparison of two 16-byte tags. */
    fun verify(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    private fun clampR(key: ByteArray): BigInteger {
        val r = key.copyOfRange(0, 16)
        r[3] = (r[3].toInt() and 15).toByte()
        r[7] = (r[7].toInt() and 15).toByte()
        r[11] = (r[11].toInt() and 15).toByte()
        r[15] = (r[15].toInt() and 15).toByte()
        r[4] = (r[4].toInt() and 252).toByte()
        r[8] = (r[8].toInt() and 252).toByte()
        r[12] = (r[12].toInt() and 252).toByte()
        return leBytesToBigInt(r, 0, 16)
    }

    private fun leBytesToBigInt(b: ByteArray, off: Int, len: Int): BigInteger {
        var acc = BigInteger.ZERO
        for (i in len - 1 downTo 0) {
            acc = acc.shiftLeft(8).or(BigInteger.valueOf((b[off + i].toInt() and 0xFF).toLong()))
        }
        return acc
    }

    private fun bigIntToLeBytes(v: BigInteger, len: Int): ByteArray {
        val out = ByteArray(len)
        var acc = v
        val ff = BigInteger.valueOf(0xFF)
        for (i in 0 until len) {
            out[i] = acc.and(ff).toInt().toByte()
            acc = acc.shiftRight(8)
        }
        return out
    }
}
