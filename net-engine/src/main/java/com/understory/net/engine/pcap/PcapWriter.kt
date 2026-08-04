package com.understory.net.engine.pcap

import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.DataOutputStream
import java.io.OutputStream

/**
 * Classic libpcap ("pcap", not pcapng) file writer — PURE JVM, so it is
 * unit-testable off-device and produces files Wireshark / tcpdump / PCAPdroid
 * open directly. Used by the firewall's packet-capture feature to record the raw
 * IP packets flowing through the tun.
 *
 * Link type is [LINKTYPE_RAW] (101): each record's bytes begin with the IP header
 * (no Ethernet framing), which is exactly what a VpnService tun delivers. The file
 * is big-endian (magic 0xA1B2C3D4); microsecond-resolution timestamps.
 *
 * Thread-safe: [writePacket] is synchronized, so the DNS-filter loop and the
 * app-drop reader can both feed one writer. A packet longer than [snapLen] is
 * truncated in the file (incl_len) but its true length is preserved (orig_len),
 * the honest pcap convention — never a silent full-capture claim.
 */
class PcapWriter(
    rawOut: OutputStream,
    private val snapLen: Int = 65_535,
) : Closeable {

    private val out = DataOutputStream(BufferedOutputStream(rawOut))
    private var packets = 0L
    private var bytes = 0L

    init {
        writeGlobalHeader()
    }

    private fun writeGlobalHeader() {
        out.writeInt(MAGIC)          // magic_number
        out.writeShort(2)            // version_major
        out.writeShort(4)            // version_minor
        out.writeInt(0)              // thiszone (GMT)
        out.writeInt(0)              // sigfigs
        out.writeInt(snapLen)        // snaplen
        out.writeInt(LINKTYPE_RAW)   // network
    }

    /** Append one raw IP packet captured at [tsMillis]. */
    @Synchronized
    fun writePacket(data: ByteArray, off: Int, len: Int, tsMillis: Long) {
        val inclLen = minOf(len, snapLen)
        val tsSec = (tsMillis / 1000L).toInt()
        val tsUsec = ((tsMillis % 1000L) * 1000L).toInt()
        out.writeInt(tsSec)
        out.writeInt(tsUsec)
        out.writeInt(inclLen)        // incl_len (bytes actually stored)
        out.writeInt(len)            // orig_len (true packet length)
        out.write(data, off, inclLen)
        packets++
        bytes += inclLen
    }

    fun writePacket(data: ByteArray, tsMillis: Long) = writePacket(data, 0, data.size, tsMillis)

    @Synchronized fun packetCount(): Long = packets
    @Synchronized fun byteCount(): Long = bytes

    @Synchronized fun flush() = out.flush()

    @Synchronized
    override fun close() {
        runCatching { out.flush() }
        runCatching { out.close() }
    }

    companion object {
        const val MAGIC = 0xA1B2C3D4.toInt()
        /** LINKTYPE_RAW — record starts with the IP header (v4 or v6, by version nibble). */
        const val LINKTYPE_RAW = 101
    }
}
