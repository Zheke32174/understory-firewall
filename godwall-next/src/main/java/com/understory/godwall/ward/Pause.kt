package com.understory.godwall.ward

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * "Pause protection" with a countdown — RethinkDNS's `PauseTimer`, ported.
 *
 * ## How the donor does it, and why that shape is kept
 *
 * Rethink does **not** stop its VpnService to pause. It sets a paused-until stamp, keeps the tun,
 * and makes the rule evaluation pass everything through while the stamp is in the future; the
 * pause screen counts down and offers ±1-minute buttons and a Resume. Tearing the tunnel down
 * instead would drop every connection on the device, ask Android for the slot again afterwards,
 * and — on a device that has since given the slot to something else — silently fail to come back.
 *
 * So this is a timestamp, checked on the DNS path, and nothing else. Godwall keeps holding the
 * slot the whole time, which is also what makes the countdown honest: there is no window where
 * the UI says "paused, 3:20 left" while the engine is actually gone.
 *
 * The arithmetic here is pure and unit-tested; only [now] touches the platform clock.
 */
object Pause {

    /** Rethink's default pause, and its adjustment step. */
    const val DEFAULT_MS = 15 * 60 * 1000L
    const val STEP_MS = 60 * 1000L

    /** Nothing pauses for longer than this in one go; re-pause if you want more. */
    const val MAX_MS = 3 * 60 * 60 * 1000L

    private val _until = MutableStateFlow(0L)

    /** Epoch millis the pause ends, or 0 when not paused. Observed by the ward screen. */
    val until: StateFlow<Long> = _until

    private fun now(): Long = System.currentTimeMillis()

    /**
     * True while filtering is suspended.
     *
     * Read on the DNS hot path, so it is one volatile read and a comparison — no allocation.
     */
    fun isPaused(): Boolean = _until.value > now()

    fun remainingMs(): Long = remainingAt(_until.value, now())

    /** Start (or restart) a pause of [ms], clamped to [MAX_MS]. */
    fun pause(ms: Long = DEFAULT_MS) {
        _until.value = now() + clampDuration(ms)
    }

    /**
     * Move the end stamp by [deltaMs] — the donor's `+`/`-` buttons.
     *
     * Adjusting a pause that has already expired does nothing rather than resurrecting it, and
     * an adjustment that lands at or before now resumes immediately.
     */
    fun adjust(deltaMs: Long) {
        val current = _until.value
        val t = now()
        if (current <= t) return
        val remaining = clampDuration(remainingAt(current, t) + deltaMs)
        _until.value = if (remaining <= 0L) 0L else t + remaining
    }

    fun resume() {
        _until.value = 0L
    }

    // -- pure arithmetic, tested off-device -------------------------------------------------

    /** Remaining millis for an end stamp of [until] at wall-clock [at]; never negative. */
    fun remainingAt(until: Long, at: Long): Long = (until - at).coerceAtLeast(0L)

    /** Clamp a requested duration into (0, [MAX_MS]]. A non-positive request clamps to 0. */
    fun clampDuration(ms: Long): Long = ms.coerceAtMost(MAX_MS).coerceAtLeast(0L)

    /** `m:ss` for the countdown. Minutes are not zero-padded; seconds always are. */
    fun format(remainingMs: Long): String {
        val total = (remainingMs + 999L) / 1000L // round up so "0:00" only shows at the end
        val m = total / 60
        val s = total % 60
        return "$m:" + s.toString().padStart(2, '0')
    }
}
