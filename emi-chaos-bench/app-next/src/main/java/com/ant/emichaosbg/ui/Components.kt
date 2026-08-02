package com.ant.emichaosbg.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/**
 * The app's whole widget vocabulary, in one file.
 *
 * Every string these render is attacker-influenced somewhere in this app — SSIDs,
 * BLE device names, package labels, /proc paths, carrier names. They go through
 * Compose `Text`, which does not parse markup of any kind, so there is no markup
 * sink to abuse. That is a property of the toolkit rather than of a sanitiser, and
 * it is the reason this app renders findings as text and nothing else.
 */

/** Severity, in the vocabulary the detectors already speak (1 = note … 3 = act). */
enum class Level { OK, INFO, WARN, ALERT, UNKNOWN }

@Composable
fun levelColor(level: Level) = when (level) {
    Level.OK -> OrbTheme.semantic.success
    Level.INFO -> MaterialTheme.colorScheme.primary
    Level.WARN -> OrbTheme.semantic.caution
    Level.ALERT -> OrbTheme.semantic.danger
    Level.UNKNOWN -> OrbTheme.semantic.dim
}

fun levelOfSeverity(sev: Int): Level = when {
    sev >= 3 -> Level.ALERT
    sev == 2 -> Level.WARN
    sev == 1 -> Level.INFO
    else -> Level.UNKNOWN
}

@Composable
fun SectionHeader(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.padding(
            start = OrbTheme.spacing.lg,
            end = OrbTheme.spacing.lg,
            top = OrbTheme.spacing.lg,
            bottom = OrbTheme.spacing.sm,
        ),
    )
}

/** The suite card style: surfaceVariant, medium shape, one tonal step. */
@Composable
fun OrbCard(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurface,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp,
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = OrbTheme.spacing.lg, vertical = OrbTheme.spacing.sm),
    ) {
        Column(Modifier.padding(OrbTheme.spacing.lg), content = content)
    }
}

/** Card title plus a coloured verdict pill on the right. */
@Composable
fun CardHeader(title: String, verdict: String, level: Level) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            title,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f, fill = false),
        )
        Pill(verdict, level)
    }
}

@Composable
fun Pill(text: String, level: Level) {
    val c = levelColor(level)
    Surface(
        color = c.copy(alpha = 0.16f),
        contentColor = c,
        shape = MaterialTheme.shapes.small,
    ) {
        Text(
            text.uppercase(),
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            maxLines = 1,
        )
    }
}

/** Body copy inside a card — the honest explanation, not a headline. */
@Composable
fun Note(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.padding(top = OrbTheme.spacing.sm),
    )
}

/**
 * Label / value row. The value is monospace and scrolls horizontally in its own
 * container rather than wrapping, so a 9-digit LTE cell id or a 64-hex cert digest
 * cannot break row alignment or push the page sideways.
 */
@Composable
fun KeyValue(label: String, value: String, level: Level = Level.UNKNOWN) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(132.dp),
        )
        Box(Modifier.weight(1f).horizontalScroll(rememberScrollState())) {
            Text(
                value,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = if (level == Level.UNKNOWN) MaterialTheme.colorScheme.onSurface
                else levelColor(level),
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/** One detector finding: a severity stripe plus the full text, never truncated. */
@Composable
fun Finding(text: String, level: Level, modifier: Modifier = Modifier) {
    val c = levelColor(level)
    Row(
        modifier
            .fillMaxWidth()
            .padding(top = OrbTheme.spacing.sm),
    ) {
        Box(
            Modifier
                .width(3.dp)
                .defaultMinSize(minHeight = 20.dp)
                .background(c, MaterialTheme.shapes.extraSmall),
        )
        Text(
            text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.padding(start = OrbTheme.spacing.md),
        )
    }
}

@Composable
fun RunButton(
    label: String,
    busy: Boolean,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    Button(
        onClick = onClick,
        enabled = enabled && !busy,
        modifier = modifier.defaultMinSize(minHeight = 48.dp),
    ) {
        if (busy) {
            CircularProgressIndicator(
                strokeWidth = 2.dp,
                modifier = Modifier.width(16.dp),
                color = MaterialTheme.colorScheme.onPrimary,
            )
            Text(" ")
        }
        Text(if (busy) "Working…" else label)
    }
}

@Composable
fun SecondaryButton(
    label: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.defaultMinSize(minHeight = 48.dp),
    ) { Text(label) }
}

@Composable
fun ThinDivider() {
    HorizontalDivider(
        Modifier.padding(vertical = OrbTheme.spacing.md),
        color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f),
    )
}
