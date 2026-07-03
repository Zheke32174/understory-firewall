package com.understory.security

import android.os.SystemClock
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentLinkedDeque

/**
 * In-process diagnostic ring buffer. Each app logs lifecycle, button
 * taps, launcher invocations, result callbacks, exceptions etc. so a
 * user with no terminal / adb can navigate to a Diagnostics screen
 * inside the app, read or screenshot the recent event sequence, and
 * relay it back. Exists specifically to compress the
 * "ship → install → eyeball → describe-symptoms-in-chat" loop on
 * Samsung One UI, where the only feedback I get is the user's prose.
 *
 * Storage shape: process-singleton ConcurrentLinkedDeque, capped at
 * MAX_EVENTS. Older events evicted from the front. Survives across
 * Compose recompositions and activity recreation (within the same
 * process). Lost on process death — that's intentional, this is a
 * dev/test diagnostic, not a forensics tool.
 *
 * Privacy: do NOT log secrets, recovery keys, biometric material, or
 * URI contents. Log SHAPE — "encrypt button tapped", "saf launcher
 * invoked with mime=any", "result callback fired with uri=non-null" —
 * not the data flowing through. The screen is FLAG_SECURE-protected
 * but the user might still screenshot on a device they don't trust.
 */
object Diagnostics {

    enum class Level { INFO, WARN, ERROR }

    data class Event(
        val timestampMs: Long,
        val elapsedMs: Long,
        val tag: String,
        val level: Level,
        val message: String,
    )

    private const val MAX_EVENTS = 250

    private val events = ConcurrentLinkedDeque<Event>()

    /**
     * Sink for log events. Engineering builds register a
     * [DiagnosticsDump] sink that mirrors every event to a rolling
     * file in shared storage; production builds register nothing and
     * the dispatch is a single deque iteration over an empty list.
     *
     * Sinks are called synchronously on the logging thread — they
     * MUST be fast and non-throwing. The file-mirror sink uses an
     * in-memory buffer + 1-second background flush to avoid blocking.
     */
    interface Sink {
        fun onEvent(ev: Event)
    }

    private val sinks = ConcurrentLinkedDeque<Sink>()

    fun addSink(sink: Sink) {
        sinks.add(sink)
    }

    fun removeSink(sink: Sink) {
        sinks.remove(sink)
    }

    fun log(tag: String, message: String, level: Level = Level.INFO) {
        val ev = Event(
            timestampMs = System.currentTimeMillis(),
            elapsedMs = SystemClock.elapsedRealtime(),
            tag = tag,
            level = level,
            message = message,
        )
        events.add(ev)
        // Bound the ring. Removal from front is O(1) on a deque.
        while (events.size > MAX_EVENTS) events.pollFirst()
        // Mirror to logcat too — useful when adb IS available.
        when (level) {
            Level.INFO -> android.util.Log.i("UnderstoryDiag", "[$tag] $message")
            Level.WARN -> android.util.Log.w("UnderstoryDiag", "[$tag] $message")
            Level.ERROR -> android.util.Log.e("UnderstoryDiag", "[$tag] $message")
        }
        // Dispatch to registered sinks. Sink failures are swallowed —
        // a broken sink must not destabilize logging itself.
        for (sink in sinks) {
            runCatching { sink.onEvent(ev) }
        }
    }

    fun warn(tag: String, message: String) = log(tag, message, Level.WARN)

    fun error(tag: String, message: String) = log(tag, message, Level.ERROR)

    /**
     * Convenience for wrapping a block. Logs entry, exit, and any
     * exception. Returns the block's result.
     */
    inline fun <T> trace(tag: String, action: String, block: () -> T): T {
        log(tag, "$action: enter")
        return try {
            val result = block()
            log(tag, "$action: ok")
            result
        } catch (t: Throwable) {
            error(tag, "$action: threw ${t.javaClass.simpleName}: ${t.message}")
            throw t
        }
    }

    /** Snapshot for UI rendering; returns oldest-first. */
    fun snapshot(): List<Event> = events.toList()

    fun clear() {
        events.clear()
        log("Diagnostics", "ring cleared")
    }

    private val tsFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    fun formatForExport(): String {
        val sb = StringBuilder()
        sb.append("=== Understory diagnostics dump ===\n")
        sb.append("captured: ${System.currentTimeMillis()}\n\n")
        for (ev in events) {
            sb.append(tsFormat.format(Date(ev.timestampMs)))
            sb.append(" [")
            sb.append(ev.level.name)
            sb.append("] ")
            sb.append(ev.tag)
            sb.append(": ")
            sb.append(ev.message)
            sb.append('\n')
        }
        return sb.toString()
    }
}
