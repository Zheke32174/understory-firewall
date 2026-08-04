package com.understory.net.engine.pcap

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream

/**
 * Round-trip: bytes written by [PcapWriter] parse back as a well-formed classic
 * pcap file (big-endian, LINKTYPE_RAW), so Wireshark / tcpdump / PCAPdroid open it.
 */
class PcapWriterTest {

    @Test fun writesReadableClassicPcap() {
        val bos = ByteArrayOutputStream()
        val pkt1 = byteArrayOf(0x45, 0x00, 0x00, 0x1c, 1, 2, 3, 4)
        val pkt2 = ByteArray(40) { it.toByte() }
        PcapWriter(bos).use { w ->
            w.writePacket(pkt1, 1_700_000_000_123L)
            w.writePacket(pkt2, 1_700_000_001_456L)
            assertEquals(2L, w.packetCount())
            assertEquals((pkt1.size + pkt2.size).toLong(), w.byteCount())
        }

        val din = DataInputStream(ByteArrayInputStream(bos.toByteArray()))
        assertEquals(PcapWriter.MAGIC, din.readInt())
        assertEquals(2, din.readShort().toInt())          // version_major
        assertEquals(4, din.readShort().toInt())          // version_minor
        assertEquals(0, din.readInt())                    // thiszone
        assertEquals(0, din.readInt())                    // sigfigs
        assertEquals(65_535, din.readInt())               // snaplen
        assertEquals(PcapWriter.LINKTYPE_RAW, din.readInt())

        // record 1
        assertEquals(1_700_000_000L, din.readInt().toLong() and 0xffffffffL)
        assertEquals(123_000, din.readInt())              // usec
        assertEquals(pkt1.size, din.readInt())            // incl_len
        assertEquals(pkt1.size, din.readInt())            // orig_len
        val r1 = ByteArray(pkt1.size); din.readFully(r1)
        assertArrayEquals(pkt1, r1)

        // record 2
        din.readInt(); assertEquals(456_000, din.readInt())
        assertEquals(pkt2.size, din.readInt())
        assertEquals(pkt2.size, din.readInt())
        val r2 = ByteArray(pkt2.size); din.readFully(r2)
        assertArrayEquals(pkt2, r2)
    }
}
