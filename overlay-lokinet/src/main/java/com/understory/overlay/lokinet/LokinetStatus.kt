package com.understory.overlay.lokinet

import androidx.compose.runtime.mutableStateOf

/**
 * Process-shared status of the Lokinet supervisor. Mirror of
 * [com.understory.overlay.i2p.I2pStatus] — same shape so consumer UI
 * (browser ProxyScreen, firewall OverlayRouting) can iterate the
 * three networks uniformly.
 *
 * Phase α (this commit): the lokinet binary is **not** bundled. State
 * pins at [State.BinaryMissing] from process start. UI consumers
 * disable the "Route via Lokinet" toggle and explain.
 *
 * Phase β (binary landing): a LokinetProxyService will own this state
 * and walk it through Idle → Starting → Ready / Error as the daemon
 * boots. Same lifecycle as i2pd; keep the shape identical.
 */
object LokinetStatus {

    sealed class State {
        /** Supervisor not started. Default at process boot. */
        object Idle : State()

        /**
         * Phase α default: the lokinet binary isn't bundled in the
         * APK yet. UI should disable the "Route via Lokinet" toggle
         * and explain that this is scaffold-only until the NDK build
         * lands. Tracked in RELEASE_BLOCKERS.md.
         */
        object BinaryMissing : State()

        /** Daemon is up; bootstrap underway. Lokinet bootstrap takes
         *  20-60 seconds typically (snode discovery + path build). */
        object Starting : State()

        /**
         * Daemon ready. SOCKS proxy listens at [socksPort]. Lokinet
         * exposes a single SOCKS5 listener; no separate HTTP outproxy.
         */
        data class Ready(val socksPort: Int) : State()

        /** A failure that needs user attention. [reason] is short. */
        data class Error(val reason: String) : State()
    }

    private val _state = mutableStateOf<State>(State.BinaryMissing)

    /** Current state. Reading from a Composable subscribes to changes. */
    val state: State get() = _state.value

    /** Internal: only the supervisor service should call this. */
    internal fun update(newState: State) {
        _state.value = newState
    }
}
