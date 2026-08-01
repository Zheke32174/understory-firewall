package com.ant.emichaosbg

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Native microphone analyser — the fallback for when WebView's own `getUserMedia` refuses.
 *
 * WHY THIS EXISTS. On a Samsung SM-S948U (Android 16), `getUserMedia` failed with
 * `NotReadableError` while a native `AudioRecord` in the *same process, at the same moment*
 * opened and reached RECORDSTATE_RECORDING with zero other recorders and the mic unmuted.
 * That proves the refusal lives in the WebView audio stack, not in the OS, the permission,
 * or the foreground-service type. A missing `MODIFY_AUDIO_SETTINGS` is the likely cause and
 * is now declared — but relying on that alone would leave the feature one WebView quirk away
 * from breaking again on a device nobody here can test.
 *
 * So the mic features run off this instead when the web path fails. Everything the app
 * actually needs from the microphone is a handful of derived numbers, all computed here:
 *   - speech-band RMS (voice-activity detection),
 *   - ultrasonic-band energy (the inaudible-command-injection heuristic),
 *   - a coarse magnitude spectrum for the analyser and formant readouts.
 *
 * PRIVACY INVARIANT, unchanged and enforced by construction: audio is analysed in the
 * capture loop and **discarded in the same iteration**. Nothing is buffered beyond the
 * current window, written to disk, or sent anywhere. Only the derived numbers above ever
 * leave this class — the same guarantee the WebView path made, kept in a different place.
 */
class NativeMic(private val ctx: Context) {

    @Volatile private var running = false
    private var thread: Thread? = null
    private var record: AudioRecord? = null

    // Latest derived values, replaced wholesale each window. No history is retained.
    @Volatile private var speechLevel = 0.0
    @Volatile private var ultraLevel = 0.0
    @Volatile private var rate = 48000
    @Volatile private var spectrum: FloatArray = FloatArray(0)
    @Volatile private var lastError: String? = null

    private val N = 2048                       // FFT size
    private val re = FloatArray(N)
    private val im = FloatArray(N)
    private val window = FloatArray(N) { 0.5f - 0.5f * cos(2.0 * Math.PI * it / (N - 1)).toFloat() }

    fun isRunning() = running
    fun error() = lastError

    fun start(): String {
        // "ok" prefix, not a bare status string. The JS side treats any reply that does not
        // start with "ok" as a failure and falls through to a "mic is busy" toast — so
        // reporting an ALREADY-WORKING capture with the words "already running" made a
        // healthy mic read as a broken one. It is running; that is a success.
        if (running) return "ok@$rate (already running)"
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED)
            return "RECORD_AUDIO not granted"

        // The retry loop used to vary only the sample rate while pinning the source to
        // UNPROCESSED. UNPROCESSED is optional — a device that does not implement it fails
        // to initialise at EVERY rate, so the loop tried twice and gave up with the mic
        // perfectly available through any other source. Source is now part of the search.
        //
        // Order is deliberate. UNPROCESSED first because the platform's AGC and noise
        // suppression roll off exactly the ultrasonic band the injection heuristic reads;
        // VOICE_RECOGNITION next because it is the least-processed of the common sources;
        // MIC last because it always exists.
        val sources = intArrayOf(
            MediaRecorder.AudioSource.UNPROCESSED,
            MediaRecorder.AudioSource.VOICE_RECOGNITION,
            MediaRecorder.AudioSource.MIC
        )
        // 48k preferred: the ultrasonic heuristic looks above 18kHz, which 44.1k barely
        // reaches and 16k cannot represent at all.
        val rates = intArrayOf(48000, 44100, 16000)
        val tried = StringBuilder()

        for (src in sources) for (r in rates) {
            val minBuf = AudioRecord.getMinBufferSize(r, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
            if (minBuf <= 0) { tried.append("$src@$r:badBufSize "); continue }
            val rec = try {
                AudioRecord(src, r, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT,
                    maxOf(minBuf, N * 4))
            } catch (e: Exception) { tried.append("$src@$r:${e.javaClass.simpleName} "); null } ?: continue
            if (rec.state != AudioRecord.STATE_INITIALIZED) {
                tried.append("$src@$r:notInitialised "); rec.release(); continue
            }
            record = rec; rate = r; source = src
            running = true
            thread = Thread { loop(rec) }.also { it.isDaemon = true; it.start() }
            return "ok@$r/src$src"
        }
        lastError = "no capture configuration opened — tried: $tried"
        return lastError!!
    }

    @Volatile private var source = -1

    fun stop() {
        running = false
        try { thread?.join(500) } catch (_: Exception) {}
        thread = null
        try { record?.stop() } catch (_: Exception) {}
        try { record?.release() } catch (_: Exception) {}
        record = null
        speechLevel = 0.0; ultraLevel = 0.0; spectrum = FloatArray(0)
    }

    private fun loop(rec: AudioRecord) {
        val buf = ShortArray(N)
        try {
            rec.startRecording()
            while (running) {
                var off = 0
                while (off < N && running) {
                    val n = rec.read(buf, off, N - off)
                    if (n <= 0) break
                    off += n
                }
                if (!running || off < N) continue
                analyse(buf)
                // buf is overwritten next iteration; nothing retains the samples.
            }
        } catch (e: Exception) {
            lastError = e.message
        } finally {
            try { rec.stop() } catch (_: Exception) {}
        }
    }

    private fun analyse(buf: ShortArray) {
        for (i in 0 until N) { re[i] = (buf[i] / 32768f) * window[i]; im[i] = 0f }
        fft(re, im)
        val bins = N / 2
        val binHz = rate.toDouble() / N
        val mag = FloatArray(bins)
        for (i in 0 until bins) mag[i] = sqrt(re[i] * re[i] + im[i] * im[i])

        fun bandRms(loHz: Double, hiHz: Double): Double {
            val a = (loHz / binHz).toInt().coerceIn(0, bins - 1)
            val b = (hiHz / binHz).toInt().coerceIn(a, bins - 1)
            var s = 0.0; var c = 0
            for (i in a..b) { s += mag[i] * mag[i]; c++ }
            return if (c > 0) sqrt(s / c) else 0.0
        }
        speechLevel = (bandRms(300.0, 3400.0) * 12.0).coerceIn(0.0, 1.0)
        ultraLevel = (bandRms(18000.0, min(23000.0, rate / 2.0 - 500)) * 40.0).coerceIn(0.0, 1.0)

        // Coarse 128-bin magnitude for the analyser/formant displays — enough resolution to
        // be useful, small enough to hand across the bridge many times a second.
        val out = FloatArray(128)
        val per = bins / 128
        for (i in 0 until 128) {
            var m = 0f
            for (j in 0 until per) { val v = mag[i * per + j]; if (v > m) m = v }
            out[i] = m
        }
        spectrum = out
    }

    /** Iterative radix-2 FFT, in place. N is a power of two by construction. */
    private fun fft(re: FloatArray, im: FloatArray) {
        var j = 0
        for (i in 1 until N) {
            var bit = N shr 1
            while (j and bit != 0) { j = j xor bit; bit = bit shr 1 }
            j = j or bit
            if (i < j) {
                var t = re[i]; re[i] = re[j]; re[j] = t
                t = im[i]; im[i] = im[j]; im[j] = t
            }
        }
        var len = 2
        while (len <= N) {
            val ang = -2.0 * Math.PI / len
            val wr = cos(ang).toFloat(); val wi = sin(ang).toFloat()
            var i = 0
            while (i < N) {
                var cr = 1f; var ci = 0f
                for (k in 0 until len / 2) {
                    val ur = re[i + k]; val ui = im[i + k]
                    val vr = re[i + k + len / 2] * cr - im[i + k + len / 2] * ci
                    val vi = re[i + k + len / 2] * ci + im[i + k + len / 2] * cr
                    re[i + k] = ur + vr; im[i + k] = ui + vi
                    re[i + k + len / 2] = ur - vr; im[i + k + len / 2] = ui - vi
                    val ncr = cr * wr - ci * wi
                    ci = cr * wi + ci * wr; cr = ncr
                }
                i += len
            }
            len = len shl 1
        }
    }

    /** Derived values only — never samples. */
    fun snapshot(): String {
        val o = JSONObject()
        o.put("running", running)
        o.put("sampleRate", rate)
        o.put("source", source)
        o.put("speech", speechLevel)
        o.put("ultra", ultraLevel)
        lastError?.let { o.put("error", it) }
        val sp = spectrum
        if (sp.isNotEmpty()) {
            val a = JSONArray()
            // 0..255 to match what the WebView analyser produced, so the JS side is identical.
            for (v in sp) a.put((v * 900f).coerceIn(0f, 255f).toInt())
            o.put("bins", a)
        }
        return o.toString()
    }
}
