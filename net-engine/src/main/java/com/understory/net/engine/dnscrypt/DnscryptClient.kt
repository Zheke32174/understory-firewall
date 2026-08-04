package com.understory.net.engine.dnscrypt

import com.understory.net.engine.crypto.ChaCha20
import com.understory.net.engine.crypto.Ed25519Verify
import com.understory.net.engine.crypto.Salsa20
import com.understory.net.engine.crypto.SecretBox
import com.understory.net.engine.crypto.X25519
import java.security.SecureRandom

/**
 * DNSCrypt v2 client protocol — PURE JVM, transport-agnostic. This is the native
 * equivalent of the dnscrypt-proxy that InviZible Pro bundles: it does the key
 * agreement, certificate verification, query encryption, and response decryption
 * itself, so no resolver daemon binary has to be shipped or run. The caller
 * supplies the actual sockets (the firewall dials them `VpnService.protect`ed);
 * everything here is bytes-in / bytes-out and never touches the network.
 *
 * Protocol (dnscrypt.info "DNSCrypt version 2" spec):
 *   1. Fetch the resolver's signed certificate via a plaintext DNS TXT query for
 *      the provider name; verify its Ed25519 signature against the provider
 *      public key from the stamp; pick the highest-serial in-window cert whose
 *      es-version this device's crypto self-test supports.
 *   2. Derive the NaCl shared key from an ephemeral X25519 exchange with the
 *      cert's short-term resolver key (HSalsa20/HChaCha20 of the X25519 output).
 *   3. Encrypt each query with `client-magic ‖ client-pk ‖ client-nonce ‖
 *      secretbox(padded-query)`; decrypt the response, which fails CLOSED on a
 *      bad tag (a forged answer is dropped, never returned).
 */
object DnscryptClient {

    private const val CERT_MAGIC = 0x444e5343 // "DNSC"
    private val RESOLVER_MAGIC = byteArrayOf(0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38) // "r6fnvWj8"
    private const val ES_XSALSA = 1
    private const val ES_XCHACHA = 2
    private const val MIN_QUERY = 256

    /** A verified certificate, ready to key a session. */
    data class Certificate(
        val esVersion: Int,
        val resolverPk: ByteArray,
        val clientMagic: ByteArray,
        val serial: Long,
        val tsStart: Long,
        val tsEnd: Long,
    )

    /** An established DNSCrypt session for one resolver: keys + chosen suite. */
    class Session internal constructor(
        val cert: Certificate,
        internal val clientPk: ByteArray,
        internal val sharedKey: ByteArray,
        internal val variant: SecretBox.Variant,
    ) {
        val esVersion: Int get() = cert.esVersion
    }

    /** Build a plaintext DNS TXT query for [providerName] (used to fetch the cert). */
    fun buildCertQuery(providerName: String, rng: SecureRandom = SecureRandom()): ByteArray =
        DnsCodec.buildQuery(providerName, TYPE_TXT, rng)

    /**
     * Parse + verify certificates out of a DNS TXT response. [providerPk] is the
     * long-term Ed25519 key from the stamp; only signature-valid, in-window certs
     * whose es-version is [supportedEsVersions] are returned, highest serial first.
     */
    fun parseCertificates(
        dnsResponse: ByteArray,
        providerPk: ByteArray,
        nowEpochSec: Long,
        supportedEsVersions: Set<Int>,
    ): List<Certificate> {
        val txts = DnsCodec.extractTxtRecords(dnsResponse)
        val out = ArrayList<Certificate>()
        for (rd in txts) {
            val c = parseOneCert(rd, providerPk, nowEpochSec, supportedEsVersions) ?: continue
            out.add(c)
        }
        return out.sortedByDescending { it.serial }
    }

    private fun parseOneCert(
        b: ByteArray,
        providerPk: ByteArray,
        now: Long,
        supported: Set<Int>,
    ): Certificate? {
        if (b.size < 124) return null
        if (u32(b, 0).toInt() != CERT_MAGIC) return null
        val es = u16(b, 4)
        if (es !in supported) return null
        val signature = b.copyOfRange(8, 72)
        val signed = b.copyOfRange(72, 124) // resolver-pk ‖ client-magic ‖ serial ‖ ts-start ‖ ts-end
        if (!Ed25519Verify.verify(providerPk, signed, signature)) return null
        val resolverPk = b.copyOfRange(72, 104)
        val clientMagic = b.copyOfRange(104, 112)
        val serial = u32(b, 112)
        val tsStart = u32(b, 116)
        val tsEnd = u32(b, 120)
        if (now < tsStart || now > tsEnd) return null
        return Certificate(es, resolverPk, clientMagic, serial, tsStart, tsEnd)
    }

    /** Establish a session against a verified [cert] using a fresh ephemeral key. */
    fun newSession(cert: Certificate, rng: SecureRandom = SecureRandom()): Session {
        val clientSk = X25519.generatePrivateKey(rng)
        val clientPk = X25519.publicKey(clientSk)
        val dh = X25519.scalarMult(clientSk, cert.resolverPk)
        val zero16 = ByteArray(16)
        return when (cert.esVersion) {
            ES_XCHACHA -> Session(cert, clientPk, ChaCha20.hchacha20(dh, zero16), SecretBox.Variant.XCHACHA20)
            else -> Session(cert, clientPk, Salsa20.hsalsa20(dh, zero16), SecretBox.Variant.XSALSA20)
        }
    }

    /** Encrypt a DNS [query] into a DNSCrypt client packet. */
    fun encryptQuery(session: Session, query: ByteArray, rng: SecureRandom = SecureRandom()): ByteArray {
        val clientNonce = ByteArray(12).also { rng.nextBytes(it) }
        val nonce = clientNonce + ByteArray(12) // 24-byte nonce, second half zero
        val padded = padQuery(query)
        val boxed = SecretBox.seal(session.variant, session.sharedKey, nonce, padded)
        return session.cert.clientMagic + session.clientPk + clientNonce + boxed
    }

    /**
     * Decrypt a DNSCrypt response packet back to a DNS message, or null if the
     * magic/nonce don't match or the tag fails (fail closed). [expectClientPacket]
     * is the packet returned by [encryptQuery], used to recover the client-nonce
     * we must see echoed.
     */
    fun decryptResponse(session: Session, expectClientPacket: ByteArray, packet: ByteArray): ByteArray? {
        if (packet.size < 8 + 12 + 12) return null
        for (i in 0 until 8) if (packet[i] != RESOLVER_MAGIC[i]) return null
        val respClientNonce = packet.copyOfRange(8, 20)
        // The client-nonce sits right after client-magic(8)+client-pk(32) in our packet.
        val sentClientNonce = expectClientPacket.copyOfRange(40, 52)
        if (!respClientNonce.contentEquals(sentClientNonce)) return null
        val nonce = packet.copyOfRange(8, 32) // client-nonce(12) ‖ resolver-nonce(12)
        val encrypted = packet.copyOfRange(32, packet.size)
        val padded = SecretBox.open(session.variant, session.sharedKey, nonce, encrypted) ?: return null
        return stripPadding(padded)
    }

    /** ISO/IEC 7816-4 padding to a multiple of 64, at least [MIN_QUERY] total packet. */
    private fun padQuery(query: ByteArray): ByteArray {
        // Total packet overhead: client-magic(8)+pk(32)+nonce(12)+tag(16) = 68.
        val minPadded = MIN_QUERY - 68
        var target = query.size + 1 // room for the 0x80 marker
        if (target < minPadded) target = minPadded
        if (target % 64 != 0) target = ((target / 64) + 1) * 64
        val out = ByteArray(target)
        System.arraycopy(query, 0, out, 0, query.size)
        out[query.size] = 0x80.toByte()
        return out
    }

    private fun stripPadding(padded: ByteArray): ByteArray? {
        var i = padded.size - 1
        while (i >= 0 && padded[i].toInt() == 0x00) i--
        if (i < 0 || padded[i].toInt() and 0xFF != 0x80) return null
        return padded.copyOfRange(0, i)
    }

    /** Anonymized DNSCrypt magic prefix: 0xff×8 then 0x00 0x00. */
    private val ANON_MAGIC = byteArrayOf(-1, -1, -1, -1, -1, -1, -1, -1, 0, 0)

    /**
     * Wrap a DNSCrypt client packet for Anonymized DNSCrypt (spec ANONYMIZED-DNSCRYPT §2):
     * `<anon-magic> <server-ip:16> <server-port:2> <dnscrypt-query>`, sent to a RELAY instead of
     * the resolver. The relay forwards the inner packet to the server unmodified, so the server
     * never sees the client's IP. [serverAddr] is the resolver's raw address (4 or 16 bytes; IPv4
     * is mapped to `::ffff:<v4>`). The response comes back as an ordinary DNSCrypt response, so
     * [decryptResponse] handles it unchanged.
     */
    fun wrapAnonymized(dnscryptQuery: ByteArray, serverAddr: ByteArray, serverPort: Int): ByteArray {
        val v6 = when (serverAddr.size) {
            16 -> serverAddr
            4 -> byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1) + serverAddr // ::ffff:<v4>
            else -> throw IllegalArgumentException("server address must be 4 or 16 bytes")
        }
        val port = byteArrayOf((serverPort ushr 8).toByte(), serverPort.toByte())
        return ANON_MAGIC + v6 + port + dnscryptQuery
    }

    private const val TYPE_TXT = 16

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    private fun u32(b: ByteArray, o: Int): Long {
        var v = 0L
        for (k in 0 until 4) v = (v shl 8) or (b[o + k].toLong() and 0xFF)
        return v
    }
}
