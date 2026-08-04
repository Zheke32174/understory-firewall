package com.understory.firewall.tunnel

import android.content.Context
import com.understory.net.engine.pcap.PcapWriter
import com.understory.security.Diagnostics
import java.io.File

/**
 * Packet capture for the DNS-filter / app-drop tuns — the PCAPdroid-style feature,
 * scoped honestly to what a rootless single-tun VPN can actually see.
 *
 * WHAT IT CAPTURES (honest boundary): the raw IP packets that enter Godwall's own
 * tun. In DNS-filter mode that's every app's DNS query + the synthesized/forwarded
 * response (a real, per-app DNS packet capture). In app-drop mode it's the packets
 * from restricted apps that the engine drops. It is NOT a whole-device capture —
 * PCAPdroid routes ALL traffic through a userspace TCP/IP stack; Godwall's tun
 * claims only the DNS route (filter mode) or the restricted apps (drop mode), and
 * the UI states this. Files are standard libpcap (LINKTYPE_RAW), openable in
 * Wireshark / tcpdump / PCAPdroid.
 *
 * [record] is the hot-path entry the tun loops call; it is a cheap null-check when
 * capture is off. Capture auto-stops at [MAX_BYTES] so it can never fill the disk.
 */
object PcapController {

    private const val TAG = "firewall.tunnel.PcapController"
    private const val PREF = "firewall_pcap"
    private const val K_ENABLED = "pcap_enabled"
    private const val DIR = "pcap"
    private const val MAX_BYTES = 64L * 1024 * 1024

    @Volatile private var writer: PcapWriter? = null
    @Volatile private var currentFile: File? = null
    @Volatile private var truncated = false

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    /** User intent to capture the next time the tun establishes. Default OFF. */
    fun isCaptureEnabled(ctx: Context): Boolean = prefs(ctx).getBoolean(K_ENABLED, false)
    fun setCaptureEnabled(ctx: Context, on: Boolean) = prefs(ctx).edit().putBoolean(K_ENABLED, on).apply()

    fun isCapturing(): Boolean = writer != null

    fun currentFileName(): String? = currentFile?.name

    fun packetCount(): Long = writer?.packetCount() ?: 0L
    fun byteCount(): Long = writer?.byteCount() ?: 0L
    fun wasTruncated(): Boolean = truncated

    private fun dir(ctx: Context): File = File(ctx.filesDir, DIR).apply { mkdirs() }

    /** Begin a new capture file. No-op if already capturing. Returns the file, or null on failure. */
    @Synchronized
    fun start(ctx: Context): File? {
        if (writer != null) return currentFile
        return try {
            truncated = false
            val f = File(dir(ctx), "godwall-${System.currentTimeMillis()}.pcap")
            writer = PcapWriter(f.outputStream())
            currentFile = f
            Diagnostics.log(TAG, "capture started: ${f.name}")
            f
        } catch (t: Throwable) {
            Diagnostics.error(TAG, "capture start failed: ${t.javaClass.simpleName}")
            writer = null; currentFile = null
            null
        }
    }

    @Synchronized
    fun stop() {
        writer?.let { runCatching { it.close() } }
        writer = null
        Diagnostics.log(TAG, "capture stopped: ${currentFile?.name}")
    }

    /** Hot path: append one raw IP packet if capturing. Auto-stops at [MAX_BYTES]. */
    fun record(data: ByteArray, off: Int, len: Int) {
        val w = writer ?: return
        try {
            if (w.byteCount() >= MAX_BYTES) {
                truncated = true
                stop()
                return
            }
            w.writePacket(data, off, len, System.currentTimeMillis())
        } catch (_: Throwable) {
            // A write failure (disk full, closed fd) must never take down the tun loop.
        }
    }

    /** Existing capture files, newest first. */
    fun captures(ctx: Context): List<File> =
        dir(ctx).listFiles { f -> f.isFile && f.name.endsWith(".pcap") }
            ?.sortedByDescending { it.lastModified() } ?: emptyList()

    fun deleteAll(ctx: Context): Int {
        val files = captures(ctx)
        var n = 0
        for (f in files) if (f != currentFile && runCatching { f.delete() }.getOrDefault(false)) n++
        return n
    }
}
