package com.understory.net.engine.dnscrypt

import java.util.Base64

/**
 * DNS Stamp (`sdns://…`) parser — the wire format InviZible Pro / dnscrypt-proxy
 * resolver and relay lists are written in (see the DNSCrypt "stamps"
 * specification). A stamp is `sdns://` + base64url(no padding) of a type byte
 * followed by a protocol-specific body. This parses every stamp protocol so the
 * bundled resolver lists load in full; the DNSCrypt-protocol stamps ([Proto.DNSCRYPT])
 * feed the native [DnscryptClient], and the DoH/DoT stamps reuse the existing
 * verified-TLS upstream.
 *
 * PURE JVM + total: a malformed stamp yields null from [parse], never an
 * exception. Verified by round-trip and by fixed real-world stamps in the unit
 * tests.
 */
data class DnsStamp(
    val proto: Proto,
    /** Property flags (bit0 DNSSEC, bit1 no-logs, bit2 no-filter). */
    val props: Long,
    /** `ip[:port]` for DNSCrypt/DoT/relay; may be empty for DoH/ODoH (use [hostname]). */
    val address: String,
    /** DNSCrypt provider signing public key (32 bytes), else empty. */
    val publicKey: ByteArray,
    /** DNSCrypt provider name (e.g. `2.dnscrypt-cert.example.com`), else empty. */
    val providerName: String,
    /** TLS certificate pin hashes for DoH/DoT, else empty. */
    val hashes: List<ByteArray>,
    /** Server hostname (DoH/DoT/DoQ/ODoH), else empty. */
    val hostname: String,
    /** URL path (DoH/ODoH), else empty. */
    val path: String,
    /** Optional bootstrap resolver IPs. */
    val bootstrapIps: List<String>,
    /** Original `sdns://…` text. */
    val raw: String,
) {
    enum class Proto(val code: Int) {
        PLAIN(0x00),
        DNSCRYPT(0x01),
        DOH(0x02),
        DOT(0x03),
        DOQ(0x04),
        ODOH_TARGET(0x05),
        DNSCRYPT_RELAY(0x81),
        ODOH_RELAY(0x85),
        UNKNOWN(-1),
    }

    val dnssec: Boolean get() = props and 0x1L != 0L
    val noLogs: Boolean get() = props and 0x2L != 0L
    val noFilter: Boolean get() = props and 0x4L != 0L

    /** IP part of [address] with no port. */
    fun addressIp(): String {
        val a = address
        if (a.isBlank()) return ""
        // IPv6 in [..]:port form
        if (a.startsWith("[")) return a.substringAfter('[').substringBefore(']')
        return if (a.count { it == ':' } == 1) a.substringBefore(':') else a
    }

    fun addressPort(default: Int): Int {
        val a = address
        if (a.startsWith("[")) return a.substringAfterLast("]:", "").toIntOrNull() ?: default
        if (a.count { it == ':' } == 1) return a.substringAfter(':').toIntOrNull() ?: default
        return default
    }

    override fun equals(other: Any?): Boolean =
        other is DnsStamp && other.raw == raw

    override fun hashCode(): Int = raw.hashCode()

    companion object {
        private const val PREFIX = "sdns://"

        fun parse(stamp: String): DnsStamp? {
            val s = stamp.trim()
            if (!s.startsWith(PREFIX)) return null
            val b = decodeUrl(s.substring(PREFIX.length)) ?: return null
            if (b.isEmpty()) return null
            val cur = Cursor(b)
            val code = cur.u8()
            val proto = Proto.entries.firstOrNull { it.code == code } ?: Proto.UNKNOWN

            return try {
                when (proto) {
                    Proto.PLAIN -> {
                        val props = cur.u64()
                        val addr = cur.lpStr()
                        base(proto, props, addr, raw = s)
                    }
                    Proto.DNSCRYPT -> {
                        val props = cur.u64()
                        val addr = cur.lpStr()
                        val pk = cur.lp()
                        val provider = cur.lpStr()
                        base(proto, props, addr, publicKey = pk, providerName = provider, raw = s)
                    }
                    Proto.DOH, Proto.DOT, Proto.DOQ, Proto.ODOH_RELAY -> {
                        val props = cur.u64()
                        val addr = cur.lpStr()
                        val hashes = cur.vlp()
                        val host = cur.lpStr()
                        val path = if (proto == Proto.DOH || proto == Proto.ODOH_RELAY) cur.lpStr() else ""
                        val boot = if (cur.remaining() > 0) cur.vlpStr() else emptyList()
                        base(proto, props, addr, hashes = hashes, hostname = host, path = path, bootstrapIps = boot, raw = s)
                    }
                    Proto.ODOH_TARGET -> {
                        val props = cur.u64()
                        val host = cur.lpStr()
                        val path = cur.lpStr()
                        base(proto, props, "", hostname = host, path = path, raw = s)
                    }
                    Proto.DNSCRYPT_RELAY -> {
                        val addr = cur.lpStr()
                        base(proto, 0L, addr, raw = s)
                    }
                    Proto.UNKNOWN -> null
                }
            } catch (_: Throwable) {
                null
            }
        }

        private fun base(
            proto: Proto,
            props: Long,
            address: String,
            publicKey: ByteArray = ByteArray(0),
            providerName: String = "",
            hashes: List<ByteArray> = emptyList(),
            hostname: String = "",
            path: String = "",
            bootstrapIps: List<String> = emptyList(),
            raw: String,
        ) = DnsStamp(proto, props, address, publicKey, providerName, hashes, hostname, path, bootstrapIps, raw)

        private fun decodeUrl(s: String): ByteArray? = try {
            // base64url, tolerate missing padding
            val padded = when (s.length % 4) {
                2 -> "$s=="
                3 -> "$s="
                else -> s
            }
            Base64.getUrlDecoder().decode(padded)
        } catch (_: Throwable) {
            null
        }
    }

    /** Little-endian byte cursor with length-prefix helpers. */
    private class Cursor(val b: ByteArray) {
        var i = 0
        fun remaining() = b.size - i
        fun u8(): Int {
            if (i >= b.size) throw IndexOutOfBoundsException()
            return b[i++].toInt() and 0xFF
        }
        fun u64(): Long {
            var v = 0L
            for (k in 0 until 8) v = v or ((b[i + k].toLong() and 0xFF) shl (8 * k))
            i += 8
            return v
        }
        fun bytes(n: Int): ByteArray {
            if (i + n > b.size) throw IndexOutOfBoundsException()
            val out = b.copyOfRange(i, i + n)
            i += n
            return out
        }
        /** Single length-prefixed field. */
        fun lp(): ByteArray = bytes(u8())
        fun lpStr(): String = String(lp(), Charsets.UTF_8)
        /** Vector of length-prefixed fields (high bit of the length byte = "more follow"). */
        fun vlp(): List<ByteArray> {
            val out = ArrayList<ByteArray>()
            while (true) {
                val len = u8()
                val more = (len and 0x80) != 0
                val n = len and 0x7F
                val chunk = bytes(n)
                if (n > 0 || more) out.add(chunk)
                if (!more) break
            }
            return out
        }
        fun vlpStr(): List<String> = vlp().map { String(it, Charsets.UTF_8) }
    }
}
