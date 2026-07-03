package com.understory.overlay.yggdrasil

import androidx.compose.runtime.mutableStateOf

/**
 * Process-shared status of the Yggdrasil supervisor. Mirror of
 * [com.understory.overlay.i2p.I2pStatus] and
 * [com.understory.overlay.lokinet.LokinetStatus] — identical shape so
 * consumer UI iterates the three networks uniformly.
 *
 * Phase α (this commit): the yggdrasil binary is **not** bundled.
 * State pins at [State.BinaryMissing]. UI consumers disable
 * "Route via Yggdrasil" and explain.
 *
 * Phase β (binary landing): unlike i2pd / lokinet (both userspace
 * SOCKS), yggdrasil exposes a full IPv6 mesh — its transport is a tun
 * interface, not a SOCKS port. The supervisor will need a VpnService
 * wrapper rather than a foreground daemon. The [State.Ready] payload
 * here is shaped accordingly: there's no SOCKS port to advertise; the
 * payload is the mesh IPv6 the device acquired plus the count of
 * active peer sessions.
 */
object YggdrasilStatus {

    sealed class State {
        /** Supervisor not started. Default at process boot. */
        object Idle : State()

        /**
         * Phase α default: yggdrasil isn't bundled. UI should disable
         * the routing toggle and explain. Tracked in
         * RELEASE_BLOCKERS.md.
         */
        object BinaryMissing : State()

        /** Daemon up; peer discovery underway. */
        object Starting : State()

        /**
         * Mesh up. The device has acquired its mesh IPv6 ([meshIp])
         * and has [peerCount] active peer sessions. There is no SOCKS
         * proxy — yggdrasil presents as IPv6 routing on the tun.
         */
        data class Ready(val meshIp: String, val peerCount: Int) : State()

        /** Failure that needs user attention. [reason] is short. */
        data class Error(val reason: String) : State()
    }

    private val _state = mutableStateOf<State>(State.BinaryMissing)

    val state: State get() = _state.value

    internal fun update(newState: State) {
        _state.value = newState
    }
}
