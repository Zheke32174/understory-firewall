package com.understory.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AssistChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import com.understory.elevation.Elevation
import com.understory.elevation.Outcome
import com.understory.security.Diagnostics
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch

/**
 * Mock-location screen (location-privacy, NOT a network control). Lets the user
 * pick a coordinate — typed or from a preset — an accuracy, and optional jitter,
 * then drives [MockLocationService] to feed that point to the OS via the
 * LocationManager test-provider API.
 *
 * HONEST DEGRADE: this only works while THIS app holds the single OS
 * "mock location app" slot. If [MockLocationController.isEnabled] is false the
 * Start controls are replaced with clear instructions to either (a) enable
 * Developer Options and select Understory as the mock location app, or (b) when
 * a Shizuku shell is granted, an "Enable via Shizuku" button that runs the
 * appop. No dead controls: Start is only offered when the slot is held.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun MockLocationScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    // Whether this app is the selected mock-location app right now.
    var enabled by remember { mutableStateOf(MockLocationController.isEnabled(ctx)) }
    // Whether a feed is currently running (owned by the service/controller).
    var feeding by remember { mutableStateOf(MockLocationController.isFeeding) }

    var latText by remember { mutableStateOf("") }
    var lonText by remember { mutableStateOf("") }
    var accuracyText by remember { mutableStateOf("5") }
    var jitterOn by remember { mutableStateOf(false) }

    // A one-line status/result message under the controls.
    var status by remember { mutableStateOf<String?>(null) }

    // Re-probe the slot when the screen (re)enters — the user may have toggled
    // Developer Options in another app and come back.
    LaunchedEffect(Unit) {
        enabled = MockLocationController.isEnabled(ctx)
        feeding = MockLocationController.isFeeding
    }

    SuiteScaffold(
        title = stringResource(R.string.mock_location_title),
        onBack = onBack,
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))

            Text(
                text = stringResource(R.string.mock_location_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (!enabled) {
                NotSelectedCard(
                    canShizuku = Elevation.canRunShell(ctx),
                    onEnableShizuku = {
                        scope.launch {
                            status = when (val r = MockLocationController.enableViaShizuku(ctx)) {
                                is Outcome.Success -> {
                                    enabled = MockLocationController.isEnabled(ctx)
                                    r.detail ?: ctx.getString(R.string.mock_location_status_enabled)
                                }
                                is Outcome.Unsupported -> r.reason
                                is Outcome.Failed -> r.message
                            }
                        }
                    },
                    onOpenDevOptions = { openDeveloperOptions(ctx) },
                    onRecheck = { enabled = MockLocationController.isEnabled(ctx) },
                )
            } else {
                // Coordinate presets.
                SuiteCard {
                    Text(
                        stringResource(R.string.mock_location_presets),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
                        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
                    ) {
                        for (preset in PRESETS) {
                            AssistChip(
                                onClick = {
                                    latText = preset.lat.toString()
                                    lonText = preset.lon.toString()
                                },
                                label = { Text(preset.label) },
                            )
                        }
                    }
                }

                // Coordinate + accuracy inputs.
                SuiteCard {
                    OutlinedTextField(
                        value = latText,
                        onValueChange = { latText = it },
                        label = { Text(stringResource(R.string.mock_location_lat)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    OutlinedTextField(
                        value = lonText,
                        onValueChange = { lonText = it },
                        label = { Text(stringResource(R.string.mock_location_lon)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    OutlinedTextField(
                        value = accuracyText,
                        onValueChange = { accuracyText = it },
                        label = { Text(stringResource(R.string.mock_location_accuracy)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                SwitchRow(
                    label = stringResource(R.string.mock_location_jitter),
                    checked = jitterOn,
                    onCheckedChange = { jitterOn = it },
                    supporting = stringResource(R.string.mock_location_jitter_supporting),
                )

                // Start / Stop controls.
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
                ) {
                    SecureButton(
                        onClick = {
                            val lat = latText.trim().toDoubleOrNull()
                            val lon = lonText.trim().toDoubleOrNull()
                            val acc = accuracyText.trim().toFloatOrNull() ?: 5f
                            if (lat == null || lon == null) {
                                status = ctx.getString(R.string.mock_location_status_need_coords)
                                return@SecureButton
                            }
                            // Re-check the slot right before starting: it may have
                            // been taken by another app since we last probed.
                            if (!MockLocationController.isEnabled(ctx)) {
                                enabled = false
                                status = ctx.getString(R.string.mock_location_status_slot_lost)
                                return@SecureButton
                            }
                            val jitter = if (jitterOn) DEFAULT_JITTER_M else 0f
                            // Pre-validate through the controller so we surface an
                            // honest reason instead of firing a service that self-
                            // stops silently.
                            when (val r = MockLocationController.start(ctx, lat, lon, acc, jitter)) {
                                is MockLocationController.StartResult.Started -> {
                                    // Hand off to the FGS to own the feed lifetime.
                                    MockLocationController.stop(ctx)
                                    MockLocationService.start(ctx, lat, lon, acc, jitter)
                                    feeding = true
                                    status = ctx.getString(R.string.mock_location_status_started)
                                }
                                is MockLocationController.StartResult.NotMockApp -> {
                                    enabled = false
                                    status = ctx.getString(R.string.mock_location_status_slot_lost)
                                }
                                is MockLocationController.StartResult.InvalidCoordinates ->
                                    status = r.reason
                                is MockLocationController.StartResult.Failed ->
                                    status = ctx.getString(R.string.mock_location_status_failed, r.message)
                            }
                        },
                        enabled = !feeding,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(stringResource(R.string.mock_location_start))
                    }
                    SecureOutlinedButton(
                        onClick = {
                            MockLocationService.stop(ctx)
                            MockLocationController.stop(ctx)
                            feeding = false
                            status = ctx.getString(R.string.mock_location_status_stopped)
                        },
                        enabled = feeding,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(stringResource(R.string.mock_location_stop))
                    }
                }

                // Live status line.
                Text(
                    text = if (feeding) {
                        stringResource(
                            R.string.mock_location_status_live,
                            latText.ifBlank { "?" },
                            lonText.ifBlank { "?" },
                        )
                    } else {
                        stringResource(R.string.mock_location_status_idle)
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (feeding) UnderstoryTheme.semantic.success
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            status?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }

            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}

/**
 * The honest-degrade card shown when this app is NOT the selected mock-location
 * app. Always offers the Developer Options route; offers the Shizuku appop route
 * only when a Shizuku shell is actually granted (never a dead button).
 */
@Composable
private fun NotSelectedCard(
    canShizuku: Boolean,
    onEnableShizuku: () -> Unit,
    onOpenDevOptions: () -> Unit,
    onRecheck: () -> Unit,
) {
    SuiteCard {
        Text(
            stringResource(R.string.mock_location_not_selected_title),
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            stringResource(R.string.mock_location_not_selected_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.md))
        SecureButton(
            onClick = onOpenDevOptions,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.mock_location_open_dev_options))
        }
        if (canShizuku) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SecureOutlinedButton(
                onClick = onEnableShizuku,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.mock_location_enable_shizuku))
            }
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SecureOutlinedButton(
            onClick = onRecheck,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.mock_location_recheck))
        }
    }
}

/** Open Android's Developer Options where "Select mock location app" lives.
 *  Falls back to the app's own details, then top-level Settings. */
private fun openDeveloperOptions(ctx: android.content.Context) {
    val dev = android.content.Intent(
        android.provider.Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS,
    ).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { ctx.startActivity(dev) }
        .recoverCatching {
            ctx.startActivity(
                android.content.Intent(android.provider.Settings.ACTION_SETTINGS)
                    .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
        .onFailure {
            Diagnostics.log("firewall.MockLocationScreen", "openDeveloperOptions failed: ${it.message}")
        }
}

/** Default jitter radius applied when the jitter switch is on. */
private const val DEFAULT_JITTER_M = 8f

/** A small set of coordinate presets so the user isn't forced to type. */
private data class Preset(val label: String, val lat: Double, val lon: Double)

private val PRESETS = listOf(
    Preset("Null Island", 0.0, 0.0),
    Preset("New York", 40.7128, -74.0060),
    Preset("London", 51.5074, -0.1278),
    Preset("Tokyo", 35.6762, 139.6503),
    Preset("Sydney", -33.8688, 151.2093),
)
