package com.understory.firewall

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * Shared firewall-app UI helpers and models used across the v2 screens.
 * Token-native: colors come from [MaterialTheme.colorScheme] /
 * [UnderstoryTheme.semantic], never a hex literal.
 */

/** An installed-app row model, reused by Restrict / Standalone / Traffic. */
data class AppEntry(
    val packageName: String,
    val label: String,
    val isSystemApp: Boolean,
    /** True when synthesized for a restricted package no longer installed. */
    val isStale: Boolean = false,
)

/** Loads the installed, user-facing app list off the caller's IO context. */
object AppListLoader {
    fun load(ctx: Context): List<AppEntry> {
        val pm = ctx.packageManager
        val flags = PackageManager.GET_META_DATA
        return runCatching {
            pm.getInstalledApplications(flags)
                .filter { it.packageName != ctx.packageName }
                .map { ai ->
                    AppEntry(
                        packageName = ai.packageName,
                        label = ai.loadLabel(pm).toString(),
                        isSystemApp = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                    )
                }
                .filter {
                    // Hide most system apps; keep ones with a launcher intent.
                    !it.isSystemApp || pm.getLaunchIntentForPackage(it.packageName) != null
                }
        }.getOrDefault(emptyList())
    }
}

/**
 * A single verdict chip. [tone] selects the Material role: PRIMARY (green,
 * the strong/good state), WARNING (amber, hardening available), NEUTRAL
 * (secondary — a valid non-Tailscale user), or UNKNOWN (dim — an
 * inference gap; never a false green).
 */
enum class ChipTone { PRIMARY, WARNING, NEUTRAL, UNKNOWN }

@Composable
fun VerdictChip(text: String, tone: ChipTone, modifier: Modifier = Modifier) {
    val (bg, fg) = when (tone) {
        ChipTone.PRIMARY -> MaterialTheme.colorScheme.primaryContainer to
            MaterialTheme.colorScheme.onPrimaryContainer
        ChipTone.WARNING -> UnderstoryTheme.semantic.warningContainer to
            UnderstoryTheme.semantic.warning
        ChipTone.NEUTRAL -> MaterialTheme.colorScheme.surfaceVariant to
            MaterialTheme.colorScheme.onSurfaceVariant
        ChipTone.UNKNOWN -> MaterialTheme.colorScheme.surfaceVariant to
            UnderstoryTheme.semantic.dim
    }
    Surface(
        color = bg,
        contentColor = fg,
        shape = MaterialTheme.shapes.small,
        modifier = modifier,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(
                horizontal = UnderstoryTheme.spacing.md,
                vertical = UnderstoryTheme.spacing.sm,
            ),
        )
    }
}

/**
 * A single per-fact row: a label + a [Tri] state glyph, with a TalkBack
 * stateDescription so a screen reader announces "yes/no/unknown."
 */
@Composable
fun TriRow(label: String, tri: Tri, modifier: Modifier = Modifier, subtitle: String? = null) {
    val (glyph, desc, color) = when (tri) {
        Tri.YES -> Triple("✓", "yes", UnderstoryTheme.semantic.success)
        Tri.NO -> Triple("✗", "no", MaterialTheme.colorScheme.error)
        Tri.UNKNOWN -> Triple("?", "unknown", UnderstoryTheme.semantic.dim)
    }
    Row(
        modifier = modifier
            .padding(vertical = UnderstoryTheme.spacing.xs)
            .semantics(mergeDescendants = true) { stateDescription = desc },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = glyph,
            color = color,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier
                .size(24.dp)
                .semantics { contentDescription = desc },
        )
        androidx.compose.foundation.layout.Spacer(Modifier.size(UnderstoryTheme.spacing.md))
        androidx.compose.foundation.layout.Column(Modifier) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** Small dim body caption used as boundary/footer lines. */
@Composable
fun BoundaryText(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodyMedium,
        color = UnderstoryTheme.semantic.dim,
        modifier = modifier,
    )
}
