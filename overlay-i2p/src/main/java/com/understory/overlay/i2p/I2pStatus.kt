package com.understory.overlay.i2p

import androidx.compose.runtime.mutableStateOf

/**
 * Process-shared status of the I2P proxy supervisor. Read from any
 * Composable in the consumer app — the property accessor reads the
 * underlying [androidx.compose.runtime.MutableState], so Compose's
 * snapshot system tracks the read and re-renders on update.
 *
 * Updates come from [I2pProxyService] as the supervised binary's
 * lifecycle progresses. Phase α (no binary bundled): state moves
 * Idle → BinaryMissing the moment the service starts and stays there.
 *
 * The state is a sealed class so consumer UI can exhaustively branch:
 * Compose's `when` will warn if a future state (e.g. `Throttled`) is
 * added without a UI handler.
 */
object I2pStatus {

    sealed class State {
        /** Supervisor not started yet. The default state at process boot. */
        object Idle : State()

        /**
         * The user's app does not bundle the i2pd binary. This is the
         * expected state in phase α: the scaffolding lives in the suite
         * but the NDK-compiled binary lands later. UI should disable
         * the "Route via I2P" toggle and explain.
         */
        object BinaryMissing : State()

        /**
         * Supervisor process is up; binary is starting. Userspace I2P
         * routers take 60-90 seconds to bootstrap (peer discovery + a
         * few tunnel hops) so the UI must indicate this is non-trivial.
         */
        object Starting : State()

        /**
         * Binary is up and accepting connections. Browser ProxyController
         * can be pointed at [httpPort]. SOCKS clients use [socksPort].
         */
        data class Ready(val httpPort: Int, val socksPort: Int) : State()

        /** A failure that needs user attention. [reason] is short, user-facing. */
        data class Error(val reason: String) : State()
    }

    private val _state = mutableStateOf<State>(State.Idle)

    /** Current state. Reading from a Composable subscribes to changes. */
    val state: State get() = _state.value

    /** Internal: only the supervisor service should call this. */
    internal fun update(newState: State) {
        _state.value = newState
    }
}
