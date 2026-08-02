package com.understory.godwall.ward

import android.content.Context
import android.content.Intent
import android.provider.Settings

/**
 * The kill switch — "block connections without VPN".
 *
 * ## Whose switch this is
 *
 * On Android this control belongs to the platform, not to the VPN app. `Always-on VPN` and
 * `Block connections without VPN` live in Settings, and there is **no API for an app to turn them
 * on**: an app may only declare `SERVICE_META_DATA_SUPPORTS_ALWAYS_ON` and read back, from inside
 * its own running service, whether the user enabled them (`VpnService.isAlwaysOn`,
 * `isLockdownEnabled`).
 *
 * Tailscale and RethinkDNS both do exactly that: report the state, and send the user to the
 * system screen. Anything else would be a toggle that flips and changes nothing, which is the one
 * thing this app must never ship. So this object does two honest things — it holds what the
 * service last observed, and it opens the screen where the switch actually lives.
 *
 * [observed] is false until the service has run at least once this process, because Android will
 * not tell us otherwise; the UI states that rather than guessing "off".
 */
object KillSwitch {

    /** What the running service last read from the platform. */
    data class State(
        val observed: Boolean,
        val alwaysOn: Boolean,
        val lockdown: Boolean,
    )

    @Volatile
    private var state = State(observed = false, alwaysOn = false, lockdown = false)

    fun current(): State = state

    /** Called by [com.understory.godwall.core.GodwallVpnService] once the slot is held. */
    fun publish(alwaysOn: Boolean, lockdown: Boolean) {
        state = State(observed = true, alwaysOn = alwaysOn, lockdown = lockdown)
    }

    /**
     * The system VPN settings screen — where always-on and its lockdown checkbox live.
     *
     * Returns false when the device has no such screen (some ROMs remove it), so the caller can
     * say so instead of a tap doing nothing.
     */
    fun openSystemVpnSettings(ctx: Context): Boolean = runCatching {
        ctx.startActivity(
            Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
        true
    }.getOrDefault(false)
}
