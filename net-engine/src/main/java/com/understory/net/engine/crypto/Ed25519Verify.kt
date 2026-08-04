package com.understory.net.engine.crypto

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Ed25519 signature verification via the PLATFORM provider (Conscrypt), which
 * ships "Ed25519" from Android 13 (API 33) — this module's minSdk. A resolver's
 * DNSCrypt certificate is signed by the provider's long-term Ed25519 key; we
 * verify that signature before trusting any short-term key inside the cert, so a
 * MITM cannot substitute its own short-term key.
 *
 * A raw 32-byte Ed25519 public key is imported by wrapping it in the fixed
 * SubjectPublicKeyInfo DER prefix and handing that to an X.509 KeyFactory —
 * avoiding the version-sensitive `EdECPoint` decode path. [isAvailable] +
 * [CryptoSelfTest] confirm the provider actually verifies the RFC 8032 vector on
 * this device; if not, DNSCrypt refuses to run (it will not skip signature
 * checks).
 */
internal object Ed25519Verify {

    // SPKI header for an Ed25519 public key: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (32) }
    private val SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
        0x70, 0x03, 0x21, 0x00,
    )

    /** Verify [signature] (64 bytes) over [message] under the raw 32-byte [publicKey]. */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        return try {
            val spki = SPKI_PREFIX + publicKey
            val pub = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki))
            Signature.getInstance("Ed25519").run {
                initVerify(pub)
                update(message)
                verify(signature)
            }
        } catch (_: Throwable) {
            false
        }
    }

    /** True if the platform exposes an Ed25519 KeyFactory + Signature at all. */
    fun isAvailable(): Boolean = try {
        KeyFactory.getInstance("Ed25519")
        Signature.getInstance("Ed25519")
        true
    } catch (_: Throwable) {
        false
    }
}
