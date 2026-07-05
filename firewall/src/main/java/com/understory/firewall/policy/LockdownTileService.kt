package com.understory.firewall.policy

import android.content.Context
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import com.understory.elevation.Elevation
import com.understory.security.Diagnostics
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Quick-Settings tile: a fast "Lockdown" toggle (Stage-3 §4).
 *
 * Tap flips the global default policy: ON = [DefaultPolicy.BLOCK_ALL] (every
 * non-exempt app blocked; the allow set is cleared), OFF = back to
 * [DefaultPolicy.ALLOW_ALL] (the explicit blocked set only). Exemptions still
 * win at apply time, so a lockdown from here can NEVER sever Tailscale.
 *
 * Degrades honestly: when no Shizuku shell tier is available the tile shows an
 * UNAVAILABLE state and a tap does nothing but re-state that it needs Shizuku —
 * there is no way to "lock down" without the shell, and the tile never pretends
 * otherwise.
 *
 * Registered in the manifest with BIND_QUICK_SETTINGS_TILE + the QS metadata.
 */
@RequiresApi(Build.VERSION_CODES.N)
class LockdownTileService : TileService() {

    private var scope: CoroutineScope? = null

    override fun onStartListening() {
        super.onStartListening()
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
        refreshTile()
    }

    override fun onStopListening() {
        super.onStopListening()
        scope?.cancel()
        scope = null
    }

    override fun onClick() {
        super.onClick()
        val appCtx = applicationContext

        if (!Elevation.canRunShell(appCtx)) {
            // No shell tier — cannot enforce anything. Reflect unavailable and
            // stop; do not fake a lockdown.
            Diagnostics.log(TAG, "tile click ignored — no Shizuku shell")
            renderUnavailable()
            return
        }

        // Optimistic UI: show the target state immediately, then do the work.
        val manager = BackendManager.get(appCtx)
        val goingIntoLockdown = !manager.isLockdown()
        setTileActive(goingIntoLockdown, subtitle = if (goingIntoLockdown) "Locking down…" else "Lifting…")

        scope?.launch {
            val result = withContext(Dispatchers.IO) {
                val installed = manager.installedNonSelfPackages()
                if (goingIntoLockdown) manager.applyLockdown(installed)
                else manager.liftLockdown(installed)
            }
            Diagnostics.log(
                TAG,
                "lockdown ${if (goingIntoLockdown) "engaged" else "lifted"}: " +
                    "changed=${result.changed} failed=${result.failed}",
            )
            refreshTile()
        }
    }

    /** Re-read live state and paint the tile. */
    private fun refreshTile() {
        val appCtx = applicationContext
        if (!Elevation.canRunShell(appCtx)) {
            renderUnavailable()
            return
        }
        val locked = BackendManager.get(appCtx).isLockdown()
        setTileActive(locked, subtitle = if (locked) "Lockdown on" else "Lockdown off")
    }

    private fun renderUnavailable() {
        val tile = qsTile ?: return
        tile.state = Tile.STATE_UNAVAILABLE
        tile.label = LABEL
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = "Needs Shizuku"
        }
        tile.contentDescription = "Lockdown unavailable — needs the Shizuku shell"
        tile.updateTile()
    }

    private fun setTileActive(active: Boolean, subtitle: String) {
        val tile = qsTile ?: return
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = LABEL
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = subtitle
        }
        tile.contentDescription =
            if (active) "Lockdown on — all non-exempt apps blocked (Tailscale exempt)"
            else "Lockdown off — only explicitly blocked apps are blocked"
        tile.updateTile()
    }

    companion object {
        private const val TAG = "firewall.policy.LockdownTile"
        private const val LABEL = "Lockdown"
    }
}
