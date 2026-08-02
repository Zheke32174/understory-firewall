package com.ant.emichaosbg.audio

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioTrack
import org.json.JSONObject
import kotlin.math.*
import kotlin.random.Random

/**
 * NATIVE MASKING SYNTHESIS. The whole audio engine, on an AudioTrack, on its own
 * thread. This is the ONLY masker in this module.
 *
 * WHY THAT SENTENCE MATTERS. This class already existed in the previous build and
 * had ZERO references anywhere in the app — it compiled and was never called. The
 * masker that actually ran was a Web Audio graph inside a 472 KB page, and keeping
 * it alive after the app was swiped away required standing up a SECOND browser
 * instance inside the service to click a button on that page. The replacement was
 * built and then not used. Here it is used, and there is no page left to fall back
 * to.
 *
 * WHAT IT COVERS, stated rather than implied: a shaped (pink-ish) noise floor, a
 * wandering filtered spur, arc/impulse events, sub rumble, a switching comb, and
 * ultrasonic pilots that stay silent unless explicitly turned up. Three chaos cores
 * — logistic, Henon, Lorenz — drive the modulation. That is the masking function
 * itself, and it is built so sources can be added one at a time.
 *
 * WHAT IT DOES NOT COVER: the old page engine's 49-source toggle set, its
 * modulation matrix and the BadJack DSP rack are NOT ported. Claiming parity would
 * be a lie, and there is no page to defer to.
 *
 * SAFETY. The output limiter is the k-norm saturator y = x / (1 + |x|^k)^(1/k):
 * unit slope at the origin, so it CANNOT apply makeup gain, and a ceiling of
 * exactly 1.0 for any k. The curve it replaced amplified quiet material by up to
 * 3.87x while never actually limiting.
 */
class NativeMasker {

    companion object {
        const val SR = 48000
        private const val CH = 2
    }

    @Volatile private var running = false
    private var track: AudioTrack? = null
    private var thread: Thread? = null

    // ---- live parameters, all safe to write from any thread ----
    @Volatile var level = 0.35f          // master, 0..1
    @Volatile var density = 0.6f         // event rate for impulsive sources
    @Volatile var brightness = 0.5f      // tilt of the noise floor
    @Volatile var chaosAmt = 0.7f        // how hard the attractors modulate
    @Volatile var subLevel = 0.25f
    @Volatile var ultraLevel = 0.0f      // 18k+ pilots; off unless asked for
    @Volatile var sweepAmt = 0.4f
    @Volatile var combAmt = 0.35f

    /** Consumed per sample: 0 = normal, hold = repeat last, drop = silence. */
    @Volatile private var holdSamples = 0
    @Volatile private var dropSamples = 0
    private var lastL = 0f
    private var lastR = 0f

    fun glitch(hold: Int, drop: Int) { holdSamples = hold; dropSamples = drop }

    // ---- chaos cores: the attractors that give the mask its character ----
    private var lx = 0.4711
    private var hx = 0.1; private var hy = 0.3
    private var ex = 0.9; private var ey = 1.1; private var ez = 1.3

    /** Logistic map — sharp, discontinuous, good for event timing. */
    private fun logistic(): Double { lx = 3.9995 * lx * (1 - lx); return lx }

    /** Hénon — two correlated streams, good for paired parameters. */
    private fun henon(): Double {
        val nx = 1.0 - 1.4 * hx * hx + hy
        hy = 0.3 * hx; hx = nx
        return (hx.coerceIn(-1.6, 1.6)) / 1.6
    }

    /** Lorenz, integrated coarsely — slow continuous drift under everything. */
    private fun lorenz(dt: Double): Double {
        val s = 10.0; val r = 28.0; val b = 8.0 / 3.0
        val dx = s * (ey - ex); val dy = ex * (r - ez) - ey; val dz = ex * ey - b * ez
        ex += dx * dt; ey += dy * dt; ez += dz * dt
        return (ex / 20.0).coerceIn(-1.0, 1.0)
    }

    // ---- source state ----
    private val rnd = Random(System.nanoTime())
    private var pinkB0 = 0.0; private var pinkB1 = 0.0; private var pinkB2 = 0.0
    private var lpL = 0.0; private var lpR = 0.0
    private var hpPrevIn = 0.0; private var hpPrevOut = 0.0
    private var sweepPhase = 0.0
    private var subPhase = 0.0
    private var ultraPhase = 0.0
    private var combBuf = FloatArray(4800)
    private var combIdx = 0
    private var arcEnv = 0.0
    private var arcDecay = 0.0

    fun isRunning() = running

    fun start(): String {
        if (running) return "already running"
        val min = AudioTrack.getMinBufferSize(SR,
            AudioFormat.CHANNEL_OUT_STEREO, AudioFormat.ENCODING_PCM_FLOAT)
        if (min <= 0) return "bad buffer size"
        // A generous buffer: this engine is a background masker, not an instrument, and
        // latency does not matter. Headroom is what keeps it glitch-free while the DOM
        // hammer is deliberately starving the main thread — which the audio thread no
        // longer shares.
        val bytes = maxOf(min, SR / 4 * CH * 4)
        val t = try {
            AudioTrack.Builder()
                .setAudioAttributes(AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                    .build())
                .setAudioFormat(AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_FLOAT)
                    .setSampleRate(SR)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_STEREO)
                    .build())
                .setBufferSizeInBytes(bytes)
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()
        } catch (e: Throwable) { return "AudioTrack failed: ${e.javaClass.simpleName}" }

        track = t
        running = true
        thread = Thread { loop(t) }.apply {
            isDaemon = true
            // Above default so synthesis is not descheduled by ordinary work; deliberately not
            // URGENT_AUDIO, which is for latency-critical paths this is not.
            priority = Thread.MAX_PRIORITY - 1
            start()
        }
        return "ok"
    }

    fun stop() {
        running = false
        try { thread?.join(400) } catch (_: Exception) {}
        thread = null
        try { track?.stop() } catch (_: Exception) {}
        try { track?.release() } catch (_: Exception) {}
        track = null
    }

    private fun loop(t: AudioTrack) {
        val n = 1024
        val buf = FloatArray(n * CH)
        try {
            t.play()
            while (running) {
                render(buf, n)
                var off = 0
                while (off < buf.size && running) {
                    val w = t.write(buf, off, buf.size - off, AudioTrack.WRITE_BLOCKING)
                    if (w <= 0) break
                    off += w
                }
            }
        } catch (_: Throwable) {
        } finally {
            try { t.stop() } catch (_: Exception) {}
        }
    }

    private fun render(out: FloatArray, frames: Int) {
        val lvl = level.coerceIn(0f, 1f)
        val bright = brightness.coerceIn(0f, 1f)
        val chaos = chaosAmt.coerceIn(0f, 1f)
        val dens = density.coerceIn(0f, 1f)
        val dt = 1.0 / SR

        for (i in 0 until frames) {
            // Slow continuous drift from Lorenz; fast decisions from logistic/Hénon.
            val drift = lorenz(dt * 6.0) * chaos
            val h = henon()

            // --- shaped noise floor (pink-ish via Voss-McCartney style filtering) ---
            val white = rnd.nextDouble() * 2 - 1
            pinkB0 = 0.99765 * pinkB0 + white * 0.0990460
            pinkB1 = 0.96300 * pinkB1 + white * 0.2965164
            pinkB2 = 0.57000 * pinkB2 + white * 1.0526913
            val pink = (pinkB0 + pinkB1 + pinkB2 + white * 0.1848) * 0.12

            // Brightness tilts between the pink floor and raw white.
            var s = pink * (1.0 - bright) + white * 0.06 * bright

            // --- wandering spur: a filtered tone that never settles ---
            sweepPhase += (2 * PI * (220.0 + 1800.0 * (0.5 + 0.5 * drift)) ) * dt
            if (sweepPhase > 2 * PI) sweepPhase -= 2 * PI
            s += sin(sweepPhase) * 0.05 * sweepAmt

            // --- arc / impulse events, rate driven by the logistic map ---
            if (logistic() > 1.0 - 0.02 * dens) {
                arcEnv = 0.7 + 0.3 * abs(h)
                arcDecay = 0.9990 - 0.0008 * dens
            }
            if (arcEnv > 1e-4) {
                s += (rnd.nextDouble() * 2 - 1) * arcEnv * 0.5
                arcEnv *= arcDecay
            }

            // --- sub rumble ---
            subPhase += 2 * PI * (34.0 + 8.0 * drift) * dt
            if (subPhase > 2 * PI) subPhase -= 2 * PI
            s += sin(subPhase) * subLevel * 0.35

            // --- ultrasonic pilots (only if explicitly enabled) ---
            if (ultraLevel > 0.001f) {
                ultraPhase += 2 * PI * (19000.0 + 900.0 * drift) * dt
                if (ultraPhase > 2 * PI) ultraPhase -= 2 * PI
                s += sin(ultraPhase) * ultraLevel * 0.25
            }

            // --- switching comb: short modulated delay, the metallic character ---
            val fl = s.toFloat()
            val delaySamples = (240 + (1800 * (0.5 + 0.5 * h))).toInt().coerceIn(8, combBuf.size - 2)
            val readIdx = ((combIdx - delaySamples) + combBuf.size) % combBuf.size
            val delayed = combBuf[readIdx]
            combBuf[combIdx] = fl + delayed * 0.45f * combAmt
            combIdx = (combIdx + 1) % combBuf.size
            s += delayed * combAmt * 0.5

            // --- one-pole tilt filters, decorrelated per channel for width ---
            lpL += (s - lpL) * (0.05 + 0.35 * bright)
            lpR += (s - lpR) * (0.05 + 0.35 * bright) * 0.94   // slight offset = stereo width
            // DC block
            val hpIn = lpL
            val hpOut = hpIn - hpPrevIn + 0.9985 * hpPrevOut
            hpPrevIn = hpIn; hpPrevOut = hpOut

            var l = (hpOut * lvl).toFloat()
            var r = (lpR * lvl).toFloat()

            // --- deliberate stutter, when [glitch] has been armed ---
            when {
                holdSamples > 0 -> { holdSamples--; l = lastL; r = lastR }
                dropSamples > 0 -> { dropSamples--; l = 0f; r = 0f }
                else -> { lastL = l; lastR = r }
            }

            // --- soft limiter: unit slope at origin, ceiling exactly 1.0 ---
            l = knorm(l); r = knorm(r)
            if (!l.isFinite()) l = 0f
            if (!r.isFinite()) r = 0f

            out[i * 2] = l
            out[i * 2 + 1] = r
        }
    }

    /**
     * y = x / (1 + |x|^k)^(1/k). k = 3 is a gentle knee. Cannot exceed unity and cannot amplify
     * — the property the previous "soft limiter" lacked, which is why it boosted quiet material
     * by up to 3.87x instead of limiting it.
     */
    private fun knorm(x: Float): Float {
        val a = abs(x)
        if (a < 1e-6f) return x
        val d = (1.0 + a.toDouble().pow(3.0)).pow(1.0 / 3.0)
        return ((if (x < 0) -a else a) / d).toFloat()
    }

    fun status(): String = JSONObject()
        .put("running", running)
        .put("engine", "native AudioTrack")
        .put("sampleRate", SR)
        .put("level", level)
        .put("sources", "noise floor, wandering spur, arc/impulse, sub rumble, " +
            "switching comb, ultrasonic pilots")
        .put("coverage", "Core masking synthesis and the chaos cores that drive it. The old " +
            "page engine's 49-source set, modulation matrix and BadJack rack are NOT ported. " +
            "Stated rather than implied.")
        .put("note", "Runs on its own thread through AudioTrack, so synthesis never shares the " +
            "main thread with rendering.")
        .toString()
}
