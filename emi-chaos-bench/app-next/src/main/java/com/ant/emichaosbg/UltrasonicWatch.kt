package com.ant.emichaosbg

import android.os.Handler
import android.os.HandlerThread
import org.json.JSONObject

/**
 * ULTRASONIC / NEAR-ULTRASONIC ENERGY WATCH.
 *
 * WHY IT IS HERE. In the previous build this detection existed ONLY as JavaScript
 * inside assets/index.html — it was the one the user actually observed firing on
 * device, and a "fully native" rebuild that silently lost it would be the "1%
 * change" verdict all over again. [NativeMic] already computes exactly the number
 * it needs (band RMS over 18kHz-23kHz, or up to Nyquist-500Hz when the device
 * would not open at 48k), so the native detection is this class and nothing more.
 *
 * WHAT IT DOES. Samples [NativeMic] on a 1s cadence off the main thread. A single
 * loud window means nothing — a key jangling, a door, a bat — so a finding needs
 * SUSTAINED energy: [SUSTAIN_WINDOWS] consecutive samples above [THRESHOLD]. The
 * finding goes straight into the encrypted vault, and repeats are coalesced.
 *
 * HONEST LIMITS, and they are large. Phone microphones and their AGC roll off hard
 * above ~18kHz, most consumer speakers barely reproduce it, and plenty of ordinary
 * electronics emit there. This says "there is sustained energy in a band you
 * cannot hear", which is a reason to look. It does NOT demodulate a beacon, does
 * not identify a sender, and cannot tell an ultrasonic cross-device tracking pilot
 * from a switching power supply. The screen says so in those words.
 */
class UltrasonicWatch(private val mic: NativeMic, private val log: SecureLog) {

    companion object {
        /** Normalised band RMS from NativeMic.snapshot()'s `ultra`, 0..1. */
        private const val THRESHOLD = 0.10
        private const val SUSTAIN_WINDOWS = 6      // ~6s at the 1s cadence
        private const val SAMPLE_MS = 1000L
        private const val COALESCE_MS = 5 * 60_000L
    }

    @Volatile private var running = false
    private var thread: HandlerThread? = null
    private var handler: Handler? = null

    @Volatile private var streak = 0
    @Volatile private var peak = 0.0
    @Volatile private var lastUltra = 0.0
    @Volatile private var lastSpeech = 0.0
    @Volatile private var samples = 0L
    @Volatile private var alerts = 0L
    @Volatile private var lastRaisedAt = 0L
    @Volatile private var lastFinding: String? = null

    fun isRunning() = running

    fun start() {
        if (running) return
        running = true
        val t = HandlerThread("orb-ultra").also { it.start() }
        thread = t
        handler = Handler(t.looper)
        schedule()
    }

    fun stop() {
        running = false
        handler?.removeCallbacksAndMessages(null)
        runCatching { thread?.quitSafely() }
        thread = null; handler = null
        streak = 0
    }

    private fun schedule() {
        handler?.postDelayed({ if (running) { tick(); schedule() } }, SAMPLE_MS)
    }

    private fun tick() {
        val snap = runCatching { JSONObject(mic.snapshot()) }.getOrNull() ?: return
        if (!snap.optBoolean("running")) { streak = 0; return }
        samples++
        val ultra = snap.optDouble("ultra", 0.0)
        lastUltra = ultra
        lastSpeech = snap.optDouble("speech", 0.0)
        if (ultra > peak) peak = ultra

        if (ultra >= THRESHOLD) streak++ else streak = 0
        if (streak < SUSTAIN_WINDOWS) return

        val now = System.currentTimeMillis()
        if (now - lastRaisedAt < COALESCE_MS) return
        lastRaisedAt = now
        val rate = snap.optInt("sampleRate", 0)
        val msg = "Sustained energy in the near-ultrasonic band (18kHz upward) for " +
            "${streak}s, peaking at ${"%.2f".format(peak)} of full scale, captured at ${rate}Hz. " +
            "You cannot hear this band, which is exactly why it is used for device-to-device " +
            "beacons and cross-device tracking pilots. It is ALSO produced by switching power " +
            "supplies, some LED drivers, ultrasonic motion sensors, pest repellers and a good " +
            "deal of ordinary electronics — and phone microphones roll off hard up here, so the " +
            "absolute number means little. Treat this as: something nearby is emitting where you " +
            "cannot hear it. Move and see whether it follows."
        lastFinding = msg
        if (runCatching { log.append(2, msg, "ultrasonic", "native") }.getOrDefault(false)) alerts++
    }

    fun snapshot(): String = JSONObject()
        .put("running", running)
        .put("micRunning", mic.isRunning())
        .put("samples", samples)
        .put("ultra", lastUltra)
        .put("speech", lastSpeech)
        .put("peak", peak)
        .put("streak", streak)
        .put("sustainNeeded", SUSTAIN_WINDOWS)
        .put("threshold", THRESHOLD)
        .put("alerts", alerts)
        .apply { lastFinding?.let { put("lastFinding", it) } }
        .apply { mic.error()?.let { put("micError", it) } }
        .put("note", "A finding needs $SUSTAIN_WINDOWS consecutive seconds above the threshold, " +
            "because one loud window is a key, a door or a bat. This detects ENERGY, not a " +
            "message: nothing here demodulates a beacon or identifies a sender.")
        .toString()
}
