package com.understory.net.engine.dnscrypt

import com.understory.net.engine.crypto.ChaCha20
import com.understory.net.engine.crypto.Salsa20
import com.understory.net.engine.crypto.SecretBox
import com.understory.net.engine.crypto.X25519
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.NamedParameterSpec

/**
 * End-to-end DNSCrypt v2 protocol test. A synthetic resolver does exactly what a
 * real resolver does — sign a certificate with Ed25519, X25519-key-agree, open the
 * client's secretbox, seal a response — and the real [DnscryptClient] round-trips a
 * query through it. This proves the whole client protocol interoperates: cert
 * parse + Ed25519 verification, tamper rejection, shared-key derivation
 * (HSalsa20/HChaCha20 of the X25519 output), query encryption + ISO7816-4 padding,
 * nonce handling, response decryption, and client-nonce forgery rejection — for
 * BOTH cipher suites.
 *
 * Runs on the host JVM (java.base ships Ed25519 at JDK 15+; CI is 17).
 */
class DnscryptClientRoundTripTest {

    @Test fun es1_xsalsa20_roundtrip() = roundTrip(1)
    @Test fun es2_xchacha20_roundtrip() = roundTrip(2)

    /** The Anonymized-DNSCrypt wrap must match the spec's worked example byte-for-byte. */
    @Test fun anon_wrap_matches_spec_example() {
        val query = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val serverIp = byteArrayOf(192.toByte(), 0, 2, 1) // 192.0.2.1
        val wrapped = DnscryptClient.wrapAnonymized(query, serverIp, 443)
        // spec: anon-magic(10) ++ ::ffff:c0000201 (16) ++ 0x01bb (2) ++ query
        val expectedPrefix = byteArrayOf(
            -1, -1, -1, -1, -1, -1, -1, -1, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0xC0.toByte(), 0x00, 0x02, 0x01,
            0x01, 0xBB.toByte(),
        )
        assertArrayEquals(expectedPrefix + query, wrapped)
    }

    private fun roundTrip(esVersion: Int) {
        val rng = SecureRandom()
        val edKp = KeyPairGenerator.getInstance("Ed25519")
            .apply { initialize(NamedParameterSpec.ED25519) }.generateKeyPair()
        val providerPk = edKp.public.encoded.let { it.copyOfRange(it.size - 32, it.size) }
        val resolverSk = X25519.generatePrivateKey(rng)
        val resolverPk = X25519.publicKey(resolverSk)
        val clientMagic = ByteArray(8) { (0x10 + it).toByte() }

        val signed = resolverPk + clientMagic + u32(1L) + u32(1_000L) + u32(4_000_000_000L) // 52 bytes
        val sig = Signature.getInstance("Ed25519").run { initSign(edKp.private); update(signed); sign() }
        val cert = byteArrayOf(0x44, 0x4e, 0x53, 0x43) + u16(esVersion) + u16(0) + sig + signed
        assertEquals(124, cert.size)

        val txtResp = txtResponse("2.dnscrypt-cert.test", cert)
        val certs = DnscryptClient.parseCertificates(txtResp, providerPk, nowEpochSec = 2_000L, supportedEsVersions = setOf(1, 2))
        assertEquals(1, certs.size)
        assertEquals(esVersion, certs[0].esVersion)

        // A tampered (re-signed-over) cert must fail Ed25519 verification.
        val badCert = cert.copyOf().also { it[80] = (it[80] + 1).toByte() }
        assertTrue(DnscryptClient.parseCertificates(txtResponse("2.dnscrypt-cert.test", badCert), providerPk, 2_000L, setOf(1, 2)).isEmpty())

        val session = DnscryptClient.newSession(certs[0], rng)
        val query = dnsQuery("example.com")
        val clientPacket = DnscryptClient.encryptQuery(session, query, rng)

        // Resolver independently derives the shared key and opens the query.
        assertArrayEquals(clientMagic, clientPacket.copyOfRange(0, 8))
        val clientPk = clientPacket.copyOfRange(8, 40)
        val clientNonce = clientPacket.copyOfRange(40, 52)
        val boxed = clientPacket.copyOfRange(52, clientPacket.size)
        val dh = X25519.scalarMult(resolverSk, clientPk)
        val variant = if (esVersion == 2) SecretBox.Variant.XCHACHA20 else SecretBox.Variant.XSALSA20
        val sharedKey = if (esVersion == 2) ChaCha20.hchacha20(dh, ByteArray(16)) else Salsa20.hsalsa20(dh, ByteArray(16))
        val opened = SecretBox.open(variant, sharedKey, clientNonce + ByteArray(12), boxed)
        assertArrayEquals(query, opened?.let(::stripPad))

        // Resolver seals a response; the client decrypts it.
        val answer = query.copyOf().also { it[2] = 0x81.toByte(); it[3] = 0x80.toByte() }
        val resolverNonce = ByteArray(12) { (0x40 + it).toByte() }
        val respBoxed = SecretBox.seal(variant, sharedKey, clientNonce + resolverNonce, pad(answer))
        val respPacket = "r6fnvWj8".toByteArray(Charsets.US_ASCII) + clientNonce + resolverNonce + respBoxed
        assertArrayEquals(answer, DnscryptClient.decryptResponse(session, clientPacket, respPacket))

        // A response echoing the wrong client-nonce must be rejected.
        val forged = "r6fnvWj8".toByteArray(Charsets.US_ASCII) + ByteArray(12) + resolverNonce + respBoxed
        assertNull(DnscryptClient.decryptResponse(session, clientPacket, forged))
    }

    private fun pad(msg: ByteArray): ByteArray {
        var t = msg.size + 1
        if (t < 256 - 68) t = 256 - 68
        if (t % 64 != 0) t = ((t / 64) + 1) * 64
        return ByteArray(t).also { System.arraycopy(msg, 0, it, 0, msg.size); it[msg.size] = 0x80.toByte() }
    }

    private fun stripPad(p: ByteArray): ByteArray? {
        var i = p.size - 1
        while (i >= 0 && p[i].toInt() == 0) i--
        return if (i >= 0 && (p[i].toInt() and 0xff) == 0x80) p.copyOfRange(0, i) else null
    }

    private fun dnsQuery(name: String): ByteArray {
        val labels = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } + 0.toByte()
        return byteArrayOf(0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) + labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
    }

    private fun txtResponse(provider: String, cert: ByteArray): ByteArray {
        val q = dnsQuery(provider)
        val header = q.copyOfRange(0, 12).also { it[2] = 0x81.toByte(); it[3] = 0x80.toByte(); it[6] = 0; it[7] = 1 }
        val rdata = byteArrayOf(cert.size.toByte()) + cert
        val answer = byteArrayOf(0xC0.toByte(), 0x0C, 0, 16, 0, 1, 0, 0, 0, 60) + u16(rdata.size) + rdata
        return header + q.copyOfRange(12, q.size) + answer
    }

    private fun u16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())
    private fun u32(v: Long) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
}
