package com.understory.net.engine.crypto

import java.math.BigInteger
import java.security.SecureRandom

/**
 * X25519 Diffie-Hellman (RFC 7748) — PURE JVM. Android's `KeyAgreement("XDH")`
 * exists at API 33, but importing a resolver's raw 32-byte public key into an
 * `XECPublicKey` is fiddly and version-sensitive; a self-contained Montgomery
 * ladder over `BigInteger` is deterministic, unit-testable against the RFC 7748
 * §5.2 vectors (see [CryptoSelfTest]), and behaves identically on every device.
 * DNS key agreement is not a hot path, so the BigInteger constant factor is
 * irrelevant.
 *
 * Used by [com.understory.net.engine.dnscrypt.DnscryptClient] to derive the
 * shared secret with a resolver's short-term public key; the NaCl shared KEY is
 * then HSalsa20/HChaCha20 of this secret (done in the client, not here).
 */
internal object X25519 {

    private val P: BigInteger = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))
    private val A24: BigInteger = BigInteger.valueOf(121665)
    private const val BITS = 255

    /** The X25519 base point u = 9. */
    val BASE_POINT: ByteArray = ByteArray(32).also { it[0] = 9 }

    /** A fresh clamped-on-use 32-byte private scalar. */
    fun generatePrivateKey(rng: SecureRandom = SecureRandom()): ByteArray =
        ByteArray(32).also { rng.nextBytes(it) }

    /** Public key for a private scalar: scalarMult(scalar, basePoint). */
    fun publicKey(privateKey: ByteArray): ByteArray = scalarMult(privateKey, BASE_POINT)

    /** X25519(scalar, uPoint) → 32-byte little-endian u-coordinate. */
    fun scalarMult(scalar: ByteArray, uPoint: ByteArray): ByteArray {
        require(scalar.size == 32 && uPoint.size == 32)
        val k = decodeScalar(scalar)
        val x1 = decodeU(uPoint)

        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0

        for (t in BITS - 1 downTo 0) {
            val kt = if (k.testBit(t)) 1 else 0
            swap = swap xor kt
            if (swap == 1) { val tx = x2; x2 = x3; x3 = tx; val tz = z2; z2 = z3; z3 = tz }
            swap = kt

            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)
            x3 = da.add(cb).mod(P).let { it.multiply(it).mod(P) }
            z3 = da.subtract(cb).mod(P).let { it.multiply(it).mod(P) }.multiply(x1).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e).mod(P)).mod(P)).mod(P)
        }
        if (swap == 1) { val tx = x2; x2 = x3; x3 = tx; val tz = z2; z2 = z3; z3 = tz }

        val res = x2.multiply(z2.modInverse(P)).mod(P)
        return encodeLe(res)
    }

    private fun decodeScalar(s: ByteArray): BigInteger {
        val e = s.copyOf()
        e[0] = (e[0].toInt() and 248).toByte()
        e[31] = (e[31].toInt() and 127).toByte()
        e[31] = (e[31].toInt() or 64).toByte()
        return leToBig(e)
    }

    private fun decodeU(u: ByteArray): BigInteger {
        val e = u.copyOf()
        e[31] = (e[31].toInt() and 127).toByte() // mask the unused top bit
        return leToBig(e).mod(P)
    }

    private fun leToBig(b: ByteArray): BigInteger {
        var acc = BigInteger.ZERO
        for (i in b.indices.reversed()) {
            acc = acc.shiftLeft(8).or(BigInteger.valueOf((b[i].toInt() and 0xFF).toLong()))
        }
        return acc
    }

    private fun encodeLe(v: BigInteger): ByteArray {
        val out = ByteArray(32)
        var acc = v.mod(P)
        val ff = BigInteger.valueOf(0xFF)
        for (i in 0 until 32) {
            out[i] = acc.and(ff).toInt().toByte()
            acc = acc.shiftRight(8)
        }
        return out
    }
}
