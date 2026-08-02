package com.ant.emichaosbg.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.SettingsInputAntenna
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow

/**
 * Every destination this app has. FIVE, and every one of them is a bottom-bar tab,
 * so every feature Chaos Orb ships is reachable in ONE TAP from the first frame.
 *
 * The previous shell had four destinations for roughly fourteen subsystems, and
 * one of those four was a WebView holding seven sub-tabs of its own. ScanEngine,
 * TamperGuard, NativeMic, NativeMasker, WifiScanBudget and the tower log had no
 * native entry AT ALL — that is the reported "menu half non existent". Nothing is
 * added to this enum that does not have a working screen behind it.
 */
enum class OrbRoute(val title: String, val label: String, val icon: ImageVector) {
    SWEEP("Sweep", "Sweep", Icons.Filled.Radar),
    RADIOS("Radios", "Radios", Icons.Filled.SettingsInputAntenna),
    DEVICE("Device", "Device", Icons.Filled.PhoneAndroid),
    MASK("Mask & mic", "Mask", Icons.Filled.GraphicEq),
    VAULT("Vault", "Vault", Icons.AutoMirrored.Filled.ListAlt),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OrbRoot(onMinimise: () -> Unit) {
    var route by rememberSaveable { mutableStateOf(OrbRoute.SWEEP.name) }
    val current = runCatching { OrbRoute.valueOf(route) }.getOrDefault(OrbRoute.SWEEP)

    // ONE back handler, owned here. From a tab other than home, back returns home;
    // from home it minimises rather than finishing, so the sentinel's foreground
    // service is not the only thing left holding the process.
    BackHandler(enabled = true) {
        if (current != OrbRoute.SWEEP) route = OrbRoute.SWEEP.name else onMinimise()
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        current.title,
                        style = MaterialTheme.typography.titleLarge,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                // Five items is the ceiling Material3's NavigationBar can lay out
                // legibly on a phone: past that each item gets under 48dp and the
                // labels truncate to three characters. The nav is designed to that
                // limit rather than overflowing into it.
                OrbRoute.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = current == tab,
                        onClick = { route = tab.name },
                        icon = { Icon(tab.icon, contentDescription = tab.title) },
                        label = { Text(tab.label, maxLines = 1) },
                        alwaysShowLabel = true,
                    )
                }
            }
        },
    ) { pad ->
        when (current) {
            OrbRoute.SWEEP -> SweepScreen(pad) { route = it.name }
            OrbRoute.RADIOS -> RadiosScreen(pad)
            OrbRoute.DEVICE -> DeviceScreen(pad)
            OrbRoute.MASK -> MaskScreen(pad)
            OrbRoute.VAULT -> VaultScreen(pad)
        }
    }
}
