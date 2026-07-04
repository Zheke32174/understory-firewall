package com.understory.net.engine

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * DNS-rebinding classifier — PURE JVM (only `java.net`), total, and
 * side-effect free.
 *
 * DNS rebinding is the attack where a *public* hostname the victim's browser
 * (or app) has already been allowed to reach resolves to a *private* / reserved
 * IP, so a page loaded from "evil.example.com" can then talk to
 * 127.0.0.1 or 192.168.1.1 under that origin. The defense a resolver-side
 * guard applies is: a name that is not itself a local/intranet name must NOT
 * answer with a reserved address.
 *
 * This class encodes exactly that predicate so it can be:
 *   - unit-tested off the device (see RebindClassifierTest), and
 *   - called from the companion on-demand auditor (RebindAuditScreen), and
 *   - called from the opt-in Standalone DNS-redirect engine
 *     ([DnsRedirector.rebindRiskInResponse]) to drop/rewrite a lying answer.
 *
 * It makes NO network calls and reads NO Android state; the caller supplies the
 * already-resolved [InetAddress]es.
 */
object RebindClassifier {

    /**
     * True iff [ip] is in a range that a *public* name should never legitimately
     * resolve to — i.e. answering with it is a rebinding signal.
     *
     * IPv4 ranges (reason strings below track these):
     *   0.0.0.0/8         "this network" / unspecified source
     *   10.0.0.0/8        RFC 1918 private
     *   127.0.0.0/8       loopback
     *   169.254.0.0/16    link-local (APIPA)
     *   172.16.0.0/12     RFC 1918 private
     *   192.168.0.0/16    RFC 1918 private
     *   100.64.0.0/10     RFC 6598 CGNAT shared address space
     *   192.0.2.0/24      TEST-NET-1
     *   198.51.100.0/24   TEST-NET-2
     *   203.0.113.0/24    TEST-NET-3
     *
     * IPv6:
     *   ::1               loopback
     *   ::                unspecified
     *   fe80::/10         link-local
     *   fc00::/7          unique local (ULA)
     * IPv4-mapped IPv6 (::ffff:0:0/96) is unwrapped and tested as its v4 address.
     */
    fun isReservedForRebinding(ip: InetAddress): Boolean {
        // Standard java.net predicates catch loopback / link-local / any-local
        // / site-local for both families; we add the ranges those miss
        // (CGNAT, TEST-NET, ULA fc00::/7, and IPv4-mapped v6).
        if (ip.isAnyLocalAddress) return true      // 0.0.0.0 / ::
        if (ip.isLoopbackAddress) return true      // 127/8, ::1
        if (ip.isLinkLocalAddress) return true     // 169.254/16, fe80::/10
        if (ip.isSiteLocalAddress) return true     // 10/8, 172.16/12, 192.168/16

        val v4 = as4(ip)
        if (v4 != null) return isReservedV4(v4)

        if (ip is Inet6Address) {
            val b = ip.address
            // fc00::/7 — unique local address (isSiteLocalAddress does NOT
            // cover ULA in the JDK, so test the top 7 bits explicitly).
            if ((b[0].toInt() and 0xFE) == 0xFC) return true
        }
        return false
    }

    /**
     * Return the 4-byte IPv4 address for [ip] if it is an IPv4 address or an
     * IPv4-mapped IPv6 address (::ffff:a.b.c.d), else null. Unwrapping the
     * mapped form lets a v6 answer that embeds a private v4 be caught.
     */
    private fun as4(ip: InetAddress): ByteArray? {
        if (ip is Inet4Address) return ip.address
        if (ip is Inet6Address) {
            val b = ip.address
            // ::ffff:0:0/96 — first 10 bytes zero, bytes 10-11 = 0xFF.
            val mapped = (0 until 10).all { b[it].toInt() == 0 } &&
                (b[10].toInt() and 0xFF) == 0xFF &&
                (b[11].toInt() and 0xFF) == 0xFF
            if (mapped) return byteArrayOf(b[12], b[13], b[14], b[15])
        }
        return null
    }

    /** Test the extra IPv4 ranges the java.net predicates don't flag. */
    private fun isReservedV4(b: ByteArray): Boolean {
        val a = b[0].toInt() and 0xFF
        val c = b[1].toInt() and 0xFF
        val d = b[2].toInt() and 0xFF
        // 0.0.0.0/8 "this network"
        if (a == 0) return true
        // 10.0.0.0/8
        if (a == 10) return true
        // 127.0.0.0/8 loopback
        if (a == 127) return true
        // 169.254.0.0/16 link-local
        if (a == 169 && c == 254) return true
        // 172.16.0.0/12
        if (a == 172 && c in 16..31) return true
        // 192.168.0.0/16
        if (a == 192 && c == 168) return true
        // 100.64.0.0/10 CGNAT (100.64.0.0 – 100.127.255.255)
        if (a == 100 && c in 64..127) return true
        // 192.0.2.0/24 TEST-NET-1
        if (a == 192 && c == 0 && d == 2) return true
        // 198.51.100.0/24 TEST-NET-2
        if (a == 198 && c == 51 && d == 100) return true
        // 203.0.113.0/24 TEST-NET-3
        if (a == 203 && c == 0 && d == 113) return true
        return false
    }

    /**
     * True iff [host] is a name we treat as legitimately-local, so a reserved
     * answer for it is expected and NOT a rebinding signal:
     *   - a literal IP address (IPv4 or IPv6),
     *   - "localhost",
     *   - or a name in a local/intranet TLD: .local, .lan, .internal, .home.arpa.
     *
     * Comparison is case-insensitive and tolerant of a trailing dot (FQDN root).
     */
    fun isLocalName(host: String): Boolean {
        val h = host.trim().trimEnd('.').lowercase()
        if (h.isEmpty()) return false
        if (h == "localhost") return true
        if (isLiteralIp(h)) return true
        return LOCAL_SUFFIXES.any { h == it.trimStart('.') || h.endsWith(it) }
    }

    /**
     * True iff [host] parses as a literal IP address without a DNS lookup.
     * Uses only textual checks (never [InetAddress.getByName] on a name, which
     * would resolve) — an IPv4 dotted quad or a bracket-free IPv6 literal.
     */
    private fun isLiteralIp(host: String): Boolean {
        // IPv6 literal may arrive bracketed: [::1]
        val bare = host.removePrefix("[").removeSuffix("]")
        // Strip a zone id (fe80::1%wlan0) before the colon/hex check.
        val noZone = bare.substringBefore('%')
        if (looksLikeIpv4(noZone)) return true
        // IPv6 literal: contains a colon and only hex/':' characters.
        if (noZone.contains(':') &&
            noZone.all { it == ':' || it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
        ) {
            // Reject a bare "::"? "::" is still a valid literal (unspecified).
            return true
        }
        return false
    }

    private fun looksLikeIpv4(s: String): Boolean {
        val parts = s.split('.')
        if (parts.size != 4) return false
        return parts.all { p ->
            p.isNotEmpty() && p.length <= 3 && p.all { it.isDigit() } &&
                p.toInt() in 0..255
        }
    }

    /** Verdict for one (host, answers) pair. */
    data class Verdict(val rebindRisk: Boolean, val reasons: List<String>)

    /**
     * Classify a resolution: risk iff [host] is NOT a local name AND at least
     * one of [answers] is a reserved address. The reasons list names each
     * offending answer with the range it hit; empty when there is no risk.
     */
    fun classify(host: String, answers: List<InetAddress>): Verdict {
        if (isLocalName(host)) {
            return Verdict(rebindRisk = false, reasons = emptyList())
        }
        val reasons = ArrayList<String>()
        for (ip in answers) {
            if (isReservedForRebinding(ip)) {
                reasons.add("${ip.hostAddress} is a reserved/private address (${rangeLabel(ip)})")
            }
        }
        return Verdict(rebindRisk = reasons.isNotEmpty(), reasons = reasons)
    }

    /** Human-readable label for which reserved family/range [ip] fell in. */
    private fun rangeLabel(ip: InetAddress): String {
        if (ip.isAnyLocalAddress) return "unspecified"
        if (ip.isLoopbackAddress) return "loopback"
        if (ip.isLinkLocalAddress) return "link-local"
        val v4 = as4(ip)
        if (v4 != null) {
            val a = v4[0].toInt() and 0xFF
            val c = v4[1].toInt() and 0xFF
            val d = v4[2].toInt() and 0xFF
            return when {
                a == 10 || (a == 172 && c in 16..31) || (a == 192 && c == 168) -> "RFC1918 private"
                a == 100 && c in 64..127 -> "CGNAT"
                a == 192 && c == 0 && d == 2 -> "TEST-NET-1"
                a == 198 && c == 51 && d == 100 -> "TEST-NET-2"
                a == 203 && c == 0 && d == 113 -> "TEST-NET-3"
                a == 0 -> "this-network"
                else -> "reserved"
            }
        }
        if (ip is Inet6Address && (ip.address[0].toInt() and 0xFE) == 0xFC) return "IPv6 ULA"
        return "reserved"
    }

    /** Local/intranet suffixes that make a reserved answer expected. */
    private val LOCAL_SUFFIXES = listOf(".local", ".lan", ".internal", ".home.arpa")
}
