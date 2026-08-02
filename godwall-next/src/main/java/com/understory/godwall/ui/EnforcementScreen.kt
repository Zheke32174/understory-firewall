package com.understory.godwall.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.understory.godwall.R
import com.understory.godwall.ward.BackendProbe
import com.understory.godwall.ward.Enforcement
import com.understory.godwall.ward.EnforcementBackend
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.LoadingState
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.withContext

/**
 * Where the WARD enforcement badge taps through to.
 *
 * De1984 and Fyrypt both expose the backend choice rather than hiding it, because on Android the
 * answer differs per device: a rooted phone gets iptables, an Android 13 phone with a privileged
 * shell gets the netd firewall chain, and everything else gets whatever the app itself can do
 * inside its own tunnel. Hiding that means the same toggle means five different things on five
 * devices and the user cannot tell which.
 *
 * So every backend is listed with the result of a **real probe run on this device** — the
 * iptables row is a `command -v` through the Yojimbo shell, the two `cmd` rows ask the shell for
 * its service list. Selecting an unavailable backend is not possible; pinning one that later
 * becomes unavailable shows the fallback on the badge and says the pin is not in force.
 */
@Composable
fun EnforcementScreen(padding: PaddingValues) {
    val ctx = LocalContext.current
    var refresh by remember { mutableIntStateOf(0) }
    var manual by remember { mutableIntStateOf(0) } // bumped to re-read the stored pin

    val probes by produceState<List<BackendProbe>?>(initialValue = null, refresh) {
        value = withContext(Bg.io) { Enforcement.probe(ctx) }
    }

    val list = probes
    if (list == null) {
        LoadingState(label = stringResource(R.string.ward_enforcement_probing))
        return
    }

    // `manual` participates so the radio selection recomposes after a pin change.
    val pinned = remember(manual) { Enforcement.manual(ctx) }
    val selection = Enforcement.select(list, pinned)

    Column(
        Modifier
            .fillMaxWidth()
            .padding(padding)
            .verticalScroll(rememberScrollState()),
    ) {
        SuiteCard(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
            Text(
                stringResource(R.string.enf_screen_intro),
                style = MaterialTheme.typography.bodyMedium,
            )
            selection.chosen?.let {
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text(
                    stringResource(R.string.ward_enforcement_badge, backendLabel(it)),
                    style = MaterialTheme.typography.titleSmall,
                )
            }
            if (selection.manualOverridden && selection.manual != null) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    stringResource(
                        R.string.ward_enforcement_pin_failed,
                        backendLabel(selection.manual),
                        selection.chosen?.let { backendLabel(it) }
                            ?: stringResource(R.string.ward_enforcement_none),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
            SecureOutlinedButton(onClick = { refresh++ }) {
                Text(stringResource(R.string.enf_refresh))
            }
        }

        SuiteSectionHeader(stringResource(R.string.enf_operating_modes))
        Text(
            stringResource(R.string.enf_operating_modes_help),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.lg),
        )

        SuiteListRow(
            headline = stringResource(R.string.enf_auto),
            supporting = stringResource(R.string.enf_auto_help),
            leading = { RadioButton(selected = pinned == null, onClick = null) },
            onClick = {
                Enforcement.setManual(ctx, null)
                manual++
            },
        )

        Enforcement.PREFERENCE_ORDER.forEach { backend ->
            val probe = list.first { it.backend == backend }
            SuiteListRow(
                headline = backendLabel(backend),
                supporting = statusPrefix(backend, probe, selection.chosen, pinned) + probe.detail,
                leading = { RadioButton(selected = pinned == backend, onClick = null) },
                // An unavailable backend cannot be pinned: a pin that is not in force is exactly
                // the "control that looks set and does nothing" this app must not ship.
                onClick = if (probe.available) {
                    {
                        Enforcement.setManual(ctx, backend)
                        manual++
                    }
                } else {
                    null
                },
            )
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
    }
}

@Composable
private fun statusPrefix(
    backend: EnforcementBackend,
    probe: BackendProbe,
    chosen: EnforcementBackend?,
    pinned: EnforcementBackend?,
): String = when {
    !probe.available -> stringResource(R.string.enf_unavailable) + " — "
    backend == chosen -> stringResource(R.string.enf_in_force) + " — "
    backend == pinned -> stringResource(R.string.enf_pinned) + " — "
    else -> ""
}
