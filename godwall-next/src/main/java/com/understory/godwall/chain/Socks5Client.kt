package com.understory.godwall.chain

import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * A REAL SOCKS5 client handshake (RFC 1928, with RFC 1929 username/password auth).
 *
 * This deliberately operates on an ALREADY-CONNECTED stream pair rather than owning
 * a socket, which is what makes hops composable: after [connectThrough] returns, the
 * same stream carries traffic to the requested target, so the next hop's handshake
 * can run over it unchanged. That is how [ChainDialer] builds a multi-hop chain out
 * of single-hop primitives.
 *
 * Pure userspace — no external dependency, nothing native. This is one of the two
 * transports Godwall implements itself rather than declaring as a seam.
 */
internal object Socks5Client {

    private const val VERSION = 0x05
    private const val CMD_CONNECT = 0x01
    private const val RSV = 0x00

    private const val METHOD_NO_AUTH = 0x00
    private const val METHOD_USER_PASS = 0x02
    private const val METHOD_NONE_ACCEPTABLE = 0xFF

    private const val ATYP_IPV4 = 0x01
    private const val ATYP_DOMAIN = 0x03
    private const val ATYP_IPV6 = 0x04

    private const val AUTH_VERSION = 0x01
    private const val REP_SUCCEEDED = 0x00

    /**
     * Negotiate with the SOCKS5 proxy on [input]/[output] so the stream afterwards
     * carries traffic to [targetHost]:[targetPort].
     *
     * The target is sent as a DOMAIN when it is not a literal IP, so DNS resolution
     * happens AT THE PROXY — never locally. Resolving locally would leak the
     * destination to the local resolver and defeat the point of the hop.
     *
     * @throws IOException on any protocol failure. Failing loudly matters: a silent
     *   fallback to a direct connection would leak traffic the user asked to proxy.
     */
    fun connectThrough(
        input: InputStream,
        output: OutputStream,
        targetHost: String,
        targetPort: Int,
        username: String = "",
        password: String = "",
    ) {
        val din = DataInputStream(input)
        val offerUserPass = username.isNotEmpty()

        // --- Greeting: which auth methods we support ---
        val methods = if (offerUserPass) {
            byteArrayOf(METHOD_NO_AUTH.toByte(), METHOD_USER_PASS.toByte())
        } else {
            byteArrayOf(METHOD_NO_AUTH.toByte())
        }
        output.write(byteArrayOf(VERSION.toByte(), methods.size.toByte()) + methods)
        output.flush()

        val greetVer = din.readUnsignedByte()
        if (greetVer != VERSION) throw IOException("SOCKS5: bad version in greeting reply ($greetVer)")
        when (val method = din.readUnsignedByte()) {
            METHOD_NO_AUTH -> Unit
            METHOD_USER_PASS -> {
                if (!offerUserPass) throw IOException("SOCKS5: proxy demanded auth but no credentials were configured")
                userPassAuth(din, output, username, password)
            }
            METHOD_NONE_ACCEPTABLE -> throw IOException("SOCKS5: proxy rejected all offered auth methods")
            else -> throw IOException("SOCKS5: proxy chose unsupported auth method $method")
        }

        // --- CONNECT request ---
        val request = java.io.ByteArrayOutputStream()
        request.write(VERSION)
        request.write(CMD_CONNECT)
        request.write(RSV)
        writeAddress(request, targetHost)
        request.write((targetPort ushr 8) and 0xFF)
        request.write(targetPort and 0xFF)
        output.write(request.toByteArray())
        output.flush()

        // --- CONNECT reply ---
        val replyVer = din.readUnsignedByte()
        if (replyVer != VERSION) throw IOException("SOCKS5: bad version in connect reply ($replyVer)")
        val rep = din.readUnsignedByte()
        if (rep != REP_SUCCEEDED) throw IOException("SOCKS5: CONNECT refused — ${replyMessage(rep)}")
        din.readUnsignedByte() // RSV
        // The bound address MUST be consumed even though we ignore it, or the very
        // first bytes of tunnelled payload would be mis-read as address bytes.
        skipAddress(din)
        din.readUnsignedByte() // BND.PORT hi
        din.readUnsignedByte() // BND.PORT lo
    }

    private fun userPassAuth(din: DataInputStream, output: OutputStream, username: String, password: String) {
        val u = username.toByteArray(Charsets.UTF_8)
        val p = password.toByteArray(Charsets.UTF_8)
        if (u.size > 255 || p.size > 255) throw IOException("SOCKS5: username/password exceeds 255 bytes")
        val buf = java.io.ByteArrayOutputStream()
        buf.write(AUTH_VERSION)
        buf.write(u.size); buf.write(u)
        buf.write(p.size); buf.write(p)
        output.write(buf.toByteArray())
        output.flush()

        val ver = din.readUnsignedByte()
        if (ver != AUTH_VERSION) throw IOException("SOCKS5: bad auth reply version ($ver)")
        val status = din.readUnsignedByte()
        if (status != 0x00) throw IOException("SOCKS5: username/password rejected (status $status)")
    }

    /** Write ATYP + address. Literal IPs go as IPv4/IPv6; everything else as a domain. */
    private fun writeAddress(out: java.io.ByteArrayOutputStream, host: String) {
        val v4 = parseIpv4(host)
        if (v4 != null) {
            out.write(ATYP_IPV4)
            out.write(v4)
            return
        }
        if (host.contains(':')) {
            // Literal IPv6 — let the platform parse it, but never let it do a DNS lookup.
            val addr = runCatching { java.net.InetAddress.getByName(host) }.getOrNull()
            val bytes = addr?.address
            if (bytes != null && bytes.size == 16) {
                out.write(ATYP_IPV6)
                out.write(bytes)
                return
            }
        }
        val domain = host.toByteArray(Charsets.US_ASCII)
        if (domain.isEmpty() || domain.size > 255) throw IOException("SOCKS5: hostname length out of range")
        out.write(ATYP_DOMAIN)
        out.write(domain.size)
        out.write(domain)
    }

    /** Consume a SOCKS5 address field whose length depends on its ATYP byte. */
    private fun skipAddress(din: DataInputStream) {
        when (val atyp = din.readUnsignedByte()) {
            ATYP_IPV4 -> din.skipFully(4)
            ATYP_IPV6 -> din.skipFully(16)
            ATYP_DOMAIN -> din.skipFully(din.readUnsignedByte())
            else -> throw IOException("SOCKS5: unknown address type $atyp in reply")
        }
    }

    /** [InputStream.skip] may skip fewer bytes than asked; a short skip would desync the stream. */
    private fun DataInputStream.skipFully(n: Int) {
        var left = n
        val scratch = ByteArray(minOf(n, 256))
        while (left > 0) {
            val r = read(scratch, 0, minOf(left, scratch.size))
            if (r < 0) throw IOException("SOCKS5: stream ended mid-address")
            left -= r
        }
    }

    /** Parse a dotted-quad WITHOUT touching DNS. Returns null when [host] is not a literal IPv4. */
    private fun parseIpv4(host: String): ByteArray? {
        val parts = host.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val v = parts[i].toIntOrNull() ?: return null
            if (v !in 0..255) return null
            // Reject "01" style — a literal IP is canonical or it is not an IP for our purposes.
            if (parts[i].length > 1 && parts[i][0] == '0') return null
            out[i] = v.toByte()
        }
        return out
    }

    /** RFC 1928 §6 reply codes, as human text for the honest error surface. */
    private fun replyMessage(rep: Int): String = when (rep) {
        0x01 -> "general SOCKS server failure"
        0x02 -> "connection not allowed by ruleset"
        0x03 -> "network unreachable"
        0x04 -> "host unreachable"
        0x05 -> "connection refused"
        0x06 -> "TTL expired"
        0x07 -> "command not supported"
        0x08 -> "address type not supported"
        else -> "unknown reply code $rep"
    }
}
