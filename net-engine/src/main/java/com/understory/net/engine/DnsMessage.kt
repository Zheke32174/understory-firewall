package com.understory.net.engine

/**
 * Minimal DNS *query* message parser + blocked-answer synthesizer — PURE JVM
 * (no `java.net`, no Android), total, and bounds-checked. The response-side
 * parsing (A/AAAA answer extraction) already lives in [DnsRedirector]; this
 * file is its query-side counterpart, needed by the opt-in adblock-DNS tunnel
 * (S6) to (a) learn which domain an app asked about and (b) craft a sinkhole
 * answer for a blocked domain without a real upstream round-trip.
 *
 * DNS message layout (RFC 1035 §4):
 *   Header (12 bytes): ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
 *   Question section (QDCOUNT entries): QNAME (length-prefixed labels ending in
 *     a zero byte), QTYPE(2), QCLASS(2)
 *
 * The parser reads ONLY the first question (QDCOUNT is almost always 1 in
 * practice; multi-question queries are vanishingly rare and unsupported by most
 * resolvers). It does NOT follow compression pointers in the question — a
 * question QNAME is never compressed (there is nothing before it to point at).
 */
object DnsMessage {

    /** Header size in bytes. */
    const val HEADER_LEN = 12

    const val TYPE_A = 1
    const val TYPE_AAAA = 28

    /** A parsed DNS question: the queried [name] (lowercased, no trailing dot)
     *  and the [qtype]. [name] is empty for the root or an unparseable QNAME. */
    data class Question(val name: String, val qtype: Int, val qclass: Int)

    /**
     * Parse the FIRST question from a raw DNS query payload ([dns] is the DNS
     * message only — no IP/UDP headers). Returns null if the message is too
     * short, has no question, or the QNAME runs off the end. Never throws.
     *
     * The returned name is lowercased and dot-joined ("ads.example.com"), which
     * is the canonical form the blocklist is keyed on.
     */
    fun parseFirstQuestion(dns: ByteArray): Question? {
        val n = dns.size
        if (n < HEADER_LEN) return null
        val qd = u16(dns, 4)
        if (qd < 1) return null

        val sb = StringBuilder()
        var pos = HEADER_LEN
        while (pos < n) {
            val len = dns[pos].toInt() and 0xFF
            when {
                len == 0 -> { pos += 1; break } // end of QNAME
                (len and 0xC0) == 0xC0 -> return null // pointer in a question — malformed
                else -> {
                    val start = pos + 1
                    val end = start + len
                    if (end > n) return null
                    if (sb.isNotEmpty()) sb.append('.')
                    // Labels are ASCII in practice; treat bytes as ISO-8859-1 so
                    // any byte maps 1:1, then lowercase. Non-hostname bytes just
                    // won't match a blocklist entry, which is the safe outcome.
                    for (i in start until end) {
                        sb.append((dns[i].toInt() and 0xFF).toChar())
                    }
                    pos = end
                }
            }
        }
        if (pos + 4 > n) return null // need QTYPE + QCLASS
        val qtype = u16(dns, pos)
        val qclass = u16(dns, pos + 2)
        return Question(sb.toString().lowercase(), qtype, qclass)
    }

    /**
     * Synthesize a "blocked" DNS response for a query, in the SINKHOLE style
     * the caller chooses:
     *
     *   [BlockAnswer.NXDOMAIN]  — RCODE=3 (name does not exist). The cleanest
     *       block: the app gets a definitive "no such host" and stops. Preferred.
     *   [BlockAnswer.ZERO_IP]   — a single A 0.0.0.0 (and/or AAAA ::) answer, so
     *       the app "connects" to a dead address. Some apps handle NXDOMAIN
     *       poorly and retry; a zero-IP answer stops those cleanly.
     *
     * The response echoes the query's ID + question section (required by
     * resolvers/apps to match the response to the request) and sets QR=1
     * (response), RA=1 (recursion available). It is built from the raw query
     * bytes so the question is copied verbatim — no re-encoding bugs.
     *
     * Returns null if the query is too short to contain a header + question.
     */
    fun buildBlockedResponse(query: ByteArray, style: BlockAnswer): ByteArray? {
        val n = query.size
        if (n < HEADER_LEN) return null

        // Find the end of the question section (QNAME + QTYPE + QCLASS) so we
        // can copy [0, questionEnd) verbatim as the echoed header+question.
        val q = parseFirstQuestion(query) ?: return null
        val questionEnd = questionSectionEnd(query) ?: return null
        val qtype = q.qtype

        val header = query.copyOfRange(0, questionEnd)
        // Flags: byte 2 = QR(1) Opcode(4) AA(1) TC(1) RD(1); byte 3 = RA(1) Z(3) RCODE(4).
        // Preserve the request's RD bit; set QR=1, RA=1.
        val rd = (header[2].toInt() and 0x01)
        header[2] = ((0x80) or (rd)).toByte() // QR=1, opcode=0, AA=0, TC=0, RD=rd
        val rcode = if (style == BlockAnswer.NXDOMAIN) 0x03 else 0x00
        header[3] = ((0x80) or rcode).toByte() // RA=1, Z=0, RCODE

        // QDCOUNT stays as-is (we copied it). Set NSCOUNT/ARCOUNT to 0.
        putU16(header, 8, 0)  // NSCOUNT
        putU16(header, 10, 0) // ARCOUNT

        return when (style) {
            BlockAnswer.NXDOMAIN -> {
                putU16(header, 6, 0) // ANCOUNT = 0
                header
            }
            BlockAnswer.ZERO_IP -> {
                // One answer RR only when the query is A or AAAA; otherwise fall
                // back to an empty NOERROR (nothing to sinkhole for, e.g. a TXT).
                val rr = when (qtype) {
                    TYPE_A -> zeroAnswer(TYPE_A, ByteArray(4))
                    TYPE_AAAA -> zeroAnswer(TYPE_AAAA, ByteArray(16))
                    else -> null
                }
                if (rr == null) {
                    putU16(header, 6, 0)
                    header
                } else {
                    putU16(header, 6, 1) // ANCOUNT = 1
                    header + rr
                }
            }
        }
    }

    /** How a blocked domain is answered. */
    enum class BlockAnswer { NXDOMAIN, ZERO_IP }

    // ---------------------------------------------------------------
    // internals
    // ---------------------------------------------------------------

    /** Byte offset just past the first question's QTYPE+QCLASS, or null. */
    private fun questionSectionEnd(dns: ByteArray): Int? {
        val n = dns.size
        if (n < HEADER_LEN) return null
        var pos = HEADER_LEN
        while (pos < n) {
            val len = dns[pos].toInt() and 0xFF
            when {
                len == 0 -> { pos += 1; break }
                (len and 0xC0) == 0xC0 -> return null
                else -> {
                    pos += 1 + len
                    if (pos > n) return null
                }
            }
        }
        val end = pos + 4 // QTYPE + QCLASS
        return if (end <= n) end else null
    }

    /**
     * Build a single answer RR that points [type] (A or AAAA) at the supplied
     * zero [addr]. Uses a compression pointer (0xC00C) to reference the
     * question's QNAME at offset 12 — valid because [buildBlockedResponse]
     * always emits the header+question first, so offset 12 is the QNAME start.
     */
    private fun zeroAnswer(type: Int, addr: ByteArray): ByteArray {
        val rr = ByteArray(2 + 2 + 2 + 4 + 2 + addr.size)
        var p = 0
        // NAME: pointer to 0x000C (the question QNAME).
        rr[p++] = 0xC0.toByte(); rr[p++] = 0x0C
        // TYPE
        rr[p++] = (type ushr 8).toByte(); rr[p++] = (type and 0xFF).toByte()
        // CLASS = IN (1)
        rr[p++] = 0x00; rr[p++] = 0x01
        // TTL = 0 (do not cache the sinkhole)
        rr[p++] = 0; rr[p++] = 0; rr[p++] = 0; rr[p++] = 0
        // RDLENGTH
        rr[p++] = (addr.size ushr 8).toByte(); rr[p++] = (addr.size and 0xFF).toByte()
        // RDATA
        for (b in addr) rr[p++] = b
        return rr
    }

    private fun u16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    private fun putU16(buf: ByteArray, off: Int, value: Int) {
        buf[off] = (value ushr 8).toByte()
        buf[off + 1] = (value and 0xFF).toByte()
    }
}
