package com.understory.net.engine.dnscrypt

import java.security.SecureRandom

/**
 * Just-enough DNS message coding for the DNSCrypt cert exchange — PURE JVM,
 * total, bounds-checked. Builds a query for one QNAME/QTYPE and extracts TXT
 * record rdata (following compression pointers) from a response. Deliberately
 * separate from [com.understory.net.engine.DnsMessage] (which handles the
 * query-side of the adblock tunnel); this side needs the answer section for TXT.
 */
internal object DnsCodec {

    /** Build a standard recursive query for [name] with [qtype]. */
    fun buildQuery(name: String, qtype: Int, rng: SecureRandom): ByteArray {
        val labels = encodeName(name)
        val out = ByteArray(12 + labels.size + 4)
        val id = rng.nextInt(0x10000)
        out[0] = (id ushr 8).toByte(); out[1] = id.toByte()
        out[2] = 0x01; out[3] = 0x00 // RD
        out[4] = 0x00; out[5] = 0x01 // QDCOUNT 1
        // ANCOUNT/NSCOUNT/ARCOUNT already zero
        System.arraycopy(labels, 0, out, 12, labels.size)
        var p = 12 + labels.size
        out[p++] = (qtype ushr 8).toByte(); out[p++] = qtype.toByte()
        out[p++] = 0x00; out[p] = 0x01 // QCLASS IN
        return out
    }

    private fun encodeName(name: String): ByteArray {
        val trimmed = name.trim().trimEnd('.')
        if (trimmed.isEmpty()) return byteArrayOf(0)
        val bytes = ArrayList<Byte>()
        for (label in trimmed.split('.')) {
            val l = label.toByteArray(Charsets.UTF_8)
            if (l.isEmpty() || l.size > 63) continue
            bytes.add(l.size.toByte())
            l.forEach { bytes.add(it) }
        }
        bytes.add(0)
        return bytes.toByteArray()
    }

    /** Extract each TXT record's rdata (character-strings concatenated) from a response. */
    fun extractTxtRecords(msg: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        try {
            if (msg.size < 12) return out
            val qd = u16(msg, 4)
            val an = u16(msg, 6)
            var p = 12
            repeat(qd) {
                p = skipName(msg, p)
                p += 4 // QTYPE + QCLASS
            }
            repeat(an) {
                p = skipName(msg, p)
                if (p + 10 > msg.size) return out
                val type = u16(msg, p)
                val rdlen = u16(msg, p + 8)
                val rdStart = p + 10
                if (rdStart + rdlen > msg.size) return out
                if (type == 16) {
                    // TXT rdata = one or more <len><chars> character-strings.
                    val acc = ArrayList<Byte>()
                    var q = rdStart
                    val end = rdStart + rdlen
                    while (q < end) {
                        val clen = msg[q].toInt() and 0xFF
                        q++
                        var k = 0
                        while (k < clen && q < end) { acc.add(msg[q]); q++; k++ }
                    }
                    out.add(acc.toByteArray())
                }
                p = rdStart + rdlen
            }
        } catch (_: Throwable) {
            return out
        }
        return out
    }

    /** Return the offset just past the name at [start], following compression. */
    private fun skipName(msg: ByteArray, start: Int): Int {
        var p = start
        while (p < msg.size) {
            val len = msg[p].toInt() and 0xFF
            when {
                len == 0 -> return p + 1
                (len and 0xC0) == 0xC0 -> return p + 2 // pointer terminates the name here
                else -> p += 1 + len
            }
        }
        return p
    }

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
}
