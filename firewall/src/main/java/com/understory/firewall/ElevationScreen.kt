package com.understory.firewall

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.understory.elevation.ui.ElevationCard
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * Optional-elevation settings surface. The suite is rootless by default; this
 * screen exists purely so a user who WANTS more can install Shizuku or Dhizuku
 * and grant this app — then the real per-app enforcement in the Restrict
 * worklist and the one-tap "Apply Private DNS now" button light up.
 *
 * The heavy lifting is the shared [ElevationCard] from :elevation: it shows the
 * current tier, an honest "what this unlocks / rootless fallback" explanation,
 * and a grant button ONLY when a tier is actually grantable — never a dead or
 * disabled button. When nothing is grantable it offers the rootless fallback
 * (here, the system Private DNS settings deep-link) so the user is never left
 * at a dead end.
 *
 * Doctrine unchanged: elevation is a SEPARATE, non-VPN enforcement path. It
 * never touches the VPN slot, never flips the app out of Companion mode, and
 * never claims to fully block all traffic — each control's copy states exactly
 * what its mechanism does.
 */
@Composable
fun ElevationScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    SuiteScaffold(title = "Elevation (optional)", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))

            BoundaryText(
                "Net Audit works fully without this. Elevation is a separate, " +
                    "opt-in path that never uses the VPN slot. Install Shizuku or " +
                    "Dhizuku and grant this app to turn advisory controls into real " +
                    "enforcement."
            )

            ElevationCard(
                unlocks = listOf(
                    "Block an app's background data (real, per-app)",
                    "Suspend an app (real)",
                    "Apply Private DNS in one tap (no ADB grant)",
                ),
                rootlessFallback = "Use Android's own Private DNS and per-app data " +
                    "controls — Net Audit opens them for you.",
                onRootlessFallback = {
                    val primary = Intent("android.settings.PRIVATE_DNS_SETTINGS")
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    runCatching { ctx.startActivity(primary) }.recoverCatching {
                        ctx.startActivity(
                            Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            )

            SuiteCard {
                Text(
                    "What each tier does",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    "• Shizuku: runs privileged shell (netpolicy, pm) at the uid you " +
                        "granted — per-app background-data block, suspend, and Private DNS.\n" +
                        "• Dhizuku: a rootless Device-Owner delegate — suspend and Private " +
                        "DNS work; per-app background-data block is Shizuku-only and is " +
                        "reported honestly as unavailable on Dhizuku.\n" +
                        "• None (rootless): every control falls back to opening Android's " +
                        "own setting; nothing here is required.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}
