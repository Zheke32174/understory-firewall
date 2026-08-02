package com.understory.godwall.dns

import android.content.Context
import com.understory.godwall.chain.EndpointChain
import com.understory.net.engine.DnsMessage

/**
 * The in-app upstream test.
 *
 * This exists because "encrypted DNS is configured" and "encrypted DNS works"
 * are different claims, and only the second one is worth showing a user. The
 * probe builds a real A query, sends it through the CONFIGURED transport (the
 * same [UpstreamResolver] the tunnel uses, through the same egress chain), and
 * reports what actually came back. A certificate failure, an unreachable
 * resolver or a refused chain all surface here as a failure, off-tunnel, before
 * the user arms anything.
 */
object DnsProbe {

    data class Result(val ok: Boolean, val line: String)

    /** Run the probe. Blocking network I/O — call off the main thread. */
    fun run(ctx: Context, name: String = "example.com"): Result {
        val resolver = DnsSettings.resolver(ctx)
        val hops = EndpointChain.hops(ctx)
        val chainOn = EndpointChain.isEnabled(ctx)
        val query = buildQuery(name)

        val started = System.currentTimeMillis()
        // service = null: the probe is deliberately run OUTSIDE the tunnel, so it
        // tests the upstream itself rather than the tunnel's plumbing.
        val response = resolver.resolve(service = null, query = query, hops = hops, chainOn = chainOn)
        val elapsed = System.currentTimeMillis() - started

        val via = if (chainOn && hops.isNotEmpty()) {
            " via " + hops.joinToString(" → ") { it.label() }
        } else {
            ""
        }

        if (response == null) {
            return Result(
                ok = false,
                line = "FAILED after ${elapsed}ms — ${resolver.describe()}$via. " +
                    "No answer was accepted. Nothing fell back to plaintext.",
            )
        }
        val answers = answerCount(response)
        val echoed = DnsMessage.parseFirstQuestion(response)?.name
        val idOk = response.size >= 2 && response[0] == query[0] && response[1] == query[1]
        return if (!idOk) {
            Result(false, "FAILED — the reply's transaction id did not match the query.")
        } else {
            Result(
                ok = true,
                line = "OK in ${elapsed}ms — ${resolver.describe()}$via. " +
                    "Answered '${echoed ?: name}' with $answers record(s).",
            )
        }
    }

    /**
     * A minimal DNS query: 12-byte header with RD set, one question, QTYPE=A,
     * QCLASS=IN. Labels are length-prefixed and the name is root-terminated.
     */
    fun buildQuery(name: String, id: Int = (System.nanoTime() and 0xffff).toInt()): ByteArray {
        val labels = name.trim().trim('.').split('.').filter { it.isNotEmpty() }
        var qnameLen = 1
        for (l in labels) qnameLen += 1 + l.toByteArray(Charsets.US_ASCII).size
        val out = ByteArray(12 + qnameLen + 4)

        out[0] = ((id ushr 8) and 0xff).toByte()
        out[1] = (id and 0xff).toByte()
        out[2] = 0x01 // RD
        out[3] = 0x00
        out[4] = 0x00; out[5] = 0x01 // QDCOUNT = 1

        var pos = 12
        for (l in labels) {
            val b = l.toByteArray(Charsets.US_ASCII)
            out[pos++] = b.size.toByte()
            System.arraycopy(b, 0, out, pos, b.size)
            pos += b.size
        }
        out[pos++] = 0 // root label
        out[pos++] = 0x00; out[pos++] = 0x01 // QTYPE  A
        out[pos++] = 0x00; out[pos] = 0x01 // QCLASS IN
        return out
    }

    /** ANCOUNT from a response header, or 0 when the buffer is too short. */
    private fun answerCount(dns: ByteArray): Int =
        if (dns.size < 8) 0
        else ((dns[6].toInt() and 0xff) shl 8) or (dns[7].toInt() and 0xff)
}
