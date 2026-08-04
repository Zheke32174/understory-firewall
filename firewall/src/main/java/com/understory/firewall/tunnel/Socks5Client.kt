package com.understory.firewall.tunnel

import java.net.InetSocketAddress
import java.net.Socket

/**
 * A minimal userspace SOCKS5 client (RFC 1928 / 1929) — the "no external
 * dependency, pure in-tunnel" hop the egress-chain design calls for as build-order
 * step 1. Godwall dials a SOCKS5 proxy (Orbot for Tor on 127.0.0.1:9050, the I2P
 * router's SOCKS on 127.0.0.1:4447, or any user proxy), does the greeting +
 * optional username/password auth, and issues a CONNECT to a target host:port.
 * The returned [Socket]'s streams are then plain app data over the proxied circuit.
 *
 * The caller supplies [protect] so the connection to the proxy bypasses Godwall's
 * own tun (the loopback proxy port isn't captured anyway, but protecting is
 * belt-and-suspenders and correct if the proxy is ever non-loopback). Everything
 * here is total: any protocol error closes the socket and returns null.
 */
object Socks5Client {

    private const val VER = 0x05
    private const val NO_AUTH = 0x00
    private const val USER_PASS = 0x02
    private const val CMD_CONNECT = 0x01
    private const val ATYP_IPV4 = 0x01
    private const val ATYP_DOMAIN = 0x03
    private const val ATYP_IPV6 = 0x04

    /**
     * Open a proxied TCP connection to [targetHost]:[targetPort] through the SOCKS5
     * proxy at [proxyHost]:[proxyPort]. Returns a connected [Socket] on success, or
     * null (and closes any partial socket) on any failure.
     */
    fun connect(
        proxyHost: String,
        proxyPort: Int,
        targetHost: String,
        targetPort: Int,
        timeoutMs: Int,
        protect: (Socket) -> Boolean,
        username: String = "",
        password: String = "",
    ): Socket? {
        val socket = Socket()
        return try {
            if (!protect(socket)) { socket.close(); return null }
            socket.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)
            socket.soTimeout = timeoutMs
            val out = socket.getOutputStream()
            val ins = socket.getInputStream()

            // Greeting: offer no-auth and (if creds present) user/pass.
            val methods = if (username.isNotEmpty()) byteArrayOf(NO_AUTH.toByte(), USER_PASS.toByte())
            else byteArrayOf(NO_AUTH.toByte())
            out.write(byteArrayOf(VER.toByte(), methods.size.toByte()) + methods)
            out.flush()
            val ver = ins.read(); val method = ins.read()
            if (ver != VER) return fail(socket)
            when (method) {
                NO_AUTH -> {}
                USER_PASS -> if (!authUserPass(ins, out, username, password)) return fail(socket)
                else -> return fail(socket) // 0xFF = no acceptable methods
            }

            // CONNECT request.
            val req = ArrayList<Byte>()
            req.add(VER.toByte()); req.add(CMD_CONNECT.toByte()); req.add(0.toByte())
            val ip = parseIpv4(targetHost)
            if (ip != null) {
                req.add(ATYP_IPV4.toByte()); ip.forEach { req.add(it) }
            } else {
                val host = targetHost.toByteArray(Charsets.US_ASCII)
                req.add(ATYP_DOMAIN.toByte()); req.add(host.size.toByte()); host.forEach { req.add(it) }
            }
            req.add((targetPort ushr 8).toByte()); req.add(targetPort.toByte())
            out.write(req.toByteArray()); out.flush()

            // Reply: VER, REP(0=ok), RSV, ATYP, BND.ADDR, BND.PORT.
            val rver = ins.read(); val rep = ins.read(); ins.read() // RSV
            if (rver != VER || rep != 0x00) return fail(socket)
            if (!skipBoundAddress(ins)) return fail(socket)
            socket
        } catch (_: Throwable) {
            fail(socket)
        }
    }

    /** Fast reachability probe: can we complete a SOCKS5 greeting with the proxy? */
    fun isReachable(proxyHost: String, proxyPort: Int, timeoutMs: Int, protect: (Socket) -> Boolean): Boolean {
        val socket = Socket()
        return try {
            if (!protect(socket)) return false
            socket.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)
            socket.soTimeout = timeoutMs
            socket.getOutputStream().write(byteArrayOf(VER.toByte(), 1, NO_AUTH.toByte()))
            socket.getOutputStream().flush()
            val ver = socket.getInputStream().read()
            socket.getInputStream().read() // method
            ver == VER
        } catch (_: Throwable) {
            false
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun authUserPass(ins: java.io.InputStream, out: java.io.OutputStream, u: String, p: String): Boolean {
        val ub = u.toByteArray(Charsets.US_ASCII)
        val pb = p.toByteArray(Charsets.US_ASCII)
        val msg = ArrayList<Byte>()
        msg.add(0x01.toByte()) // sub-negotiation version
        msg.add(ub.size.toByte()); ub.forEach { msg.add(it) }
        msg.add(pb.size.toByte()); pb.forEach { msg.add(it) }
        out.write(msg.toByteArray()); out.flush()
        val ver = ins.read(); val status = ins.read()
        return ver == 0x01 && status == 0x00
    }

    private fun skipBoundAddress(ins: java.io.InputStream): Boolean {
        return when (ins.read()) {
            ATYP_IPV4 -> { repeat(4) { ins.read() }; repeat(2) { ins.read() }; true }
            ATYP_IPV6 -> { repeat(16) { ins.read() }; repeat(2) { ins.read() }; true }
            ATYP_DOMAIN -> { val n = ins.read(); if (n < 0) return false; repeat(n + 2) { ins.read() }; true }
            else -> false
        }
    }

    private fun parseIpv4(host: String): ByteArray? {
        val parts = host.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val v = parts[i].toIntOrNull() ?: return null
            if (v !in 0..255) return null
            out[i] = v.toByte()
        }
        return out
    }

    private fun fail(socket: Socket): Socket? {
        runCatching { socket.close() }
        return null
    }
}
