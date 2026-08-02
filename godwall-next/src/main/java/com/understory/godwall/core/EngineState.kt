package com.understory.godwall.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Whether Godwall currently holds the VPN slot, published so the UI reflects the engine rather
 * than the user's last tap.
 *
 * The distinction is the whole point. Godwall's predecessor drove its shield indicator from the
 * toggle that requested arming, so the UI read "protected" from the moment the user asked —
 * including when consent was denied, when the tun failed to establish, and after Android
 * revoked the slot to give it to another app. A security control whose indicator reports intent
 * instead of state is worse than no indicator: it is confidently wrong in exactly the situation
 * that matters.
 *
 * So only [GodwallVpnService] writes here, and it writes what actually happened.
 */
object EngineState {

    enum class Phase {
        /** Not holding the slot. Nothing is filtered. */
        DOWN,

        /** Consent granted and the service is establishing the tun. */
        STARTING,

        /** The tun is up and the DNS filter is running. */
        UP,

        /** The engine tried to come up and failed; [detail] says why. */
        FAILED,
    }

    data class Snapshot(
        val phase: Phase = Phase.DOWN,
        val detail: String = "",
        /** Monotonic-ish millis when the current phase began; 0 when never armed. */
        val sinceMs: Long = 0L,
    ) {
        val armed: Boolean get() = phase == Phase.UP
    }

    private val _state = MutableStateFlow(Snapshot())
    val state: StateFlow<Snapshot> = _state

    internal fun publish(phase: Phase, detail: String = "") {
        _state.value = Snapshot(
            phase = phase,
            detail = detail,
            sinceMs = System.currentTimeMillis(),
        )
    }

    /** Read-only convenience for non-Compose callers. */
    val armed: Boolean get() = _state.value.armed
}
