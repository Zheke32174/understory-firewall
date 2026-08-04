package com.understory.firewall

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * Settings & defaults surface. Renders the base-app default for every setting
 * (the auditable [FirewallDefaults.CATALOG]) and offers a full restore-to-defaults.
 * Every value shown here is the default the app uses out of the box, and every one
 * is changeable on its own screen — this is the reference + the reset.
 */
@Composable
fun DefaultsScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var confirm by remember { mutableStateOf(false) }
    var done by remember { mutableStateOf<String?>(null) }

    SuiteScaffold(title = "Settings & defaults", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            SuiteCard {
                Text("Base-app defaults", style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    "Every setting below has a working default — the base-app value the app ships " +
                        "with — and every one is changeable on its own screen. Nothing here is " +
                        "required to be touched for the app to work out of the box.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // Group the catalog by store for readability.
            FirewallDefaults.CATALOG.groupBy { it.store }.forEach { (store, entries) ->
                SuiteCard {
                    Text(store, style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                    entries.forEach { d ->
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                            Text(d.setting, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                            Text(d.value, style = MaterialTheme.typography.bodyMedium,
                                color = UnderstoryTheme.semantic.success)
                        }
                        if (d.note.isNotBlank()) {
                            Text(d.note, style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                    }
                }
            }

            SuiteCard {
                Text("Restore defaults", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                BoundaryText(
                    "Resets every setting to the values above. This is a FULL reset: it also clears " +
                        "your flagged-app list, custom block/allow domains, saved DNSCrypt/Tor choices, " +
                        "and the egress chain. It does not touch captures or granted permissions.",
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                SecureButton(onClick = { confirm = true }) { Text("Restore all settings to defaults") }
                done?.let {
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    Text(it, style = MaterialTheme.typography.bodyMedium,
                        color = UnderstoryTheme.semantic.success)
                }
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }

    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text("Restore all defaults?") },
            text = { Text("This resets every setting and clears your flagged apps, custom domains, and egress chain. This can't be undone.") },
            confirmButton = {
                SecureButton(onClick = {
                    FirewallDefaults.restoreDefaults(ctx)
                    confirm = false
                    done = "All settings restored to base-app defaults."
                }) { Text("Restore") }
            },
            dismissButton = { SecureOutlinedButton(onClick = { confirm = false }) { Text("Cancel") } },
        )
    }
}
