package com.understory.elevation.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.understory.elevation.ElevTier
import com.understory.elevation.Elevation
import com.understory.security.SecureButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Immutable snapshot of elevation state for the UI. Held by [rememberElevationState]
 * so an app can drive its own custom UI if the drop-in [ElevationCard] does not fit.
 */
data class ElevationUiState(
    val granted: ElevTier,
    val available: Set<ElevTier>,
) {
    val isElevated: Boolean get() = granted != ElevTier.NONE

    /** A tier that is installed/reachable but not yet granted — the "you could enable" set. */
    val grantable: Set<ElevTier>
        get() = available.filter { it != ElevTier.NONE }.toSet()
}

/**
 * Computes [ElevationUiState] off the main thread and recomputes on [refreshKey]
 * change (bump it after returning from a grant flow). Exposed so an app that
 * wants a bespoke layout still gets the honest, capability-first state without
 * re-deriving it.
 */
@Composable
fun rememberElevationState(refreshKey: Any? = Unit): ElevationUiState {
    val ctx = LocalContext.current
    return produceState(
        initialValue = ElevationUiState(ElevTier.NONE, emptySet()),
        key1 = refreshKey,
    ) {
        value = withContext(Dispatchers.Default) {
            ElevationUiState(
                granted = Elevation.grantedTier(ctx),
                available = Elevation.availableTiers(ctx),
            )
        }
    }.value
}

/**
 * The drop-in elevation card. Renders current tier, an honest "what this
 * unlocks / rootless fallback" explanation, and a grant button that ONLY
 * appears when a tier is actually grantable — never a dead/disabled button.
 *
 * Honest degradation contract:
 *  - Granted:   shows the active tier and what it enables.
 *  - Grantable: shows a request button for the reachable tier.
 *  - Neither:   shows the rootless fallback line ([rootlessFallback]) and, if
 *               provided, a deep-link action ([onRootlessFallback]) — e.g. open
 *               the relevant system Settings screen — so the user is never left
 *               at a dead end.
 *
 * Token-native: all color/spacing/type come from [UnderstoryTheme] via
 * [SuiteCard]; no hex, no bare dp.
 *
 * @param unlocks short lines describing the extra actions elevation lights up.
 * @param rootlessFallback the plain rootless path shown when nothing is granted.
 * @param onRootlessFallback optional action (e.g. Settings deep-link); shown as
 *   a secondary button when non-null.
 */
@Composable
fun ElevationCard(
    unlocks: List<String>,
    rootlessFallback: String,
    modifier: Modifier = Modifier,
    onRootlessFallback: (() -> Unit)? = null,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var refreshKey by remember { mutableStateOf(0) }
    val state = rememberElevationState(refreshKey)

    SuiteCard(modifier = modifier) {
        Text(
            text = when (state.granted) {
                ElevTier.NONE -> "Elevation: off (rootless)"
                ElevTier.SHIZUKU -> "Elevation: Shizuku"
                ElevTier.DHIZUKU -> "Elevation: Dhizuku (Device Owner)"
            },
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = UnderstoryTheme.spacing.sm),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
        ) {
            if (state.isElevated) {
                Text(
                    text = "Extra actions unlocked:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                unlocks.forEach { line ->
                    Text(
                        text = "• $line",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                Text(
                    text = "This app works fully without elevation. Optionally grant " +
                        "Shizuku or Dhizuku to unlock: " + unlocks.joinToString("; ") + ".",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = "Rootless path: $rootlessFallback",
                    style = MaterialTheme.typography.bodySmall,
                    color = UnderstoryTheme.semantic.dim,
                )
            }
        }

        // Grant button ONLY when a tier is reachable-but-ungranted. Never a
        // dead/disabled button: if nothing is grantable we show the fallback
        // action instead (or nothing but the honest copy above).
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = UnderstoryTheme.spacing.md),
            horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val activity = ctx.findActivity()
            val grantable = state.grantable
            if (grantable.contains(ElevTier.SHIZUKU) && state.granted != ElevTier.SHIZUKU && activity != null) {
                SecureButton(onClick = {
                    scope.launch {
                        Elevation.requestShizuku(activity)
                        refreshKey++
                    }
                }) { Text("Enable Shizuku") }
            }
            if (grantable.contains(ElevTier.DHIZUKU) && state.granted != ElevTier.DHIZUKU && activity != null) {
                SecureButton(onClick = {
                    scope.launch {
                        Elevation.requestDhizuku(activity)
                        refreshKey++
                    }
                }) { Text("Enable Dhizuku") }
            }
            if (grantable.isEmpty() && !state.isElevated && onRootlessFallback != null) {
                SecureButton(onClick = onRootlessFallback) { Text("Open Settings") }
            }
        }
    }
}

/** Walk the ContextWrapper chain to the hosting Activity, or null. */
private fun android.content.Context.findActivity(): android.app.Activity? {
    var c: android.content.Context? = this
    while (c is android.content.ContextWrapper) {
        if (c is android.app.Activity) return c
        c = c.baseContext
    }
    return null
}
