package com.understory.security.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.Role.Companion.Switch as SwitchRole
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.toggleableState
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.selection.toggleable
import androidx.compose.ui.res.stringResource
import com.understory.security.R
import com.understory.security.secureClickable
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * Shared row / card / section building blocks. All consume tokens from the
 * theme package — no hex literal, no bare design `.sp`. Interactive surfaces
 * carry the tap-jacking-hardened [secureClickable] and a 48dp/56dp minimum
 * touch target (§3 A-1), and Switch/Slider rows bake in the merged TalkBack
 * semantics the audit flagged as missing.
 */

/**
 * Section-header label above a group of rows/cards. [titleMedium], dim, with the
 * suite's standard leading padding.
 */
@Composable
fun SuiteSectionHeader(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.padding(
            start = UnderstoryTheme.spacing.lg,
            top = UnderstoryTheme.spacing.md,
            end = UnderstoryTheme.spacing.lg,
            bottom = UnderstoryTheme.spacing.sm,
        ),
    )
}

/**
 * The suite card style: a `surfaceVariant` [Surface] with the medium shape and
 * tonal elevation. When [onClick] is non-null the whole card is
 * [secureClickable] with `Role.Button` semantics and a 48dp minimum height.
 * Replaces the ad-hoc `Box(background(accent.copy(alpha=.06f), RoundedCornerShape(4.dp)))`
 * pattern and every app's inline card.
 */
@Composable
fun SuiteCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit,
) {
    val clickMod = if (onClick != null) {
        Modifier
            .secureClickable(onClick)
            .semantics { role = Role.Button }
            .defaultMinSize(minHeight = 48.dp)
    } else {
        Modifier
    }
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurface,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp,
        modifier = modifier.fillMaxWidth().then(clickMod),
    ) {
        Column(
            modifier = Modifier.padding(UnderstoryTheme.spacing.lg),
            content = content,
        )
    }
}

/**
 * A consistent list row over Material3 [ListItem]: optional leading/trailing
 * slots, an optional supporting line, whole-row [secureClickable] when
 * [onClick] is set, merged semantics so a screen reader reads the row as one
 * node, and a 56dp minimum height.
 */
@Composable
fun SuiteListRow(
    headline: String,
    modifier: Modifier = Modifier,
    supporting: String? = null,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
    onClick: (() -> Unit)? = null,
) {
    val rowMod = if (onClick != null) {
        modifier
            .fillMaxWidth()
            .secureClickable(onClick)
            .semantics(mergeDescendants = true) { role = Role.Button }
            .defaultMinSize(minHeight = 56.dp)
    } else {
        modifier
            .fillMaxWidth()
            .semantics(mergeDescendants = true) {}
            .defaultMinSize(minHeight = 56.dp)
    }
    ListItem(
        headlineContent = {
            Text(
                headline,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        },
        supportingContent = supporting?.let {
            {
                Text(
                    it,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        leadingContent = leading,
        trailingContent = trailing,
        // Only containerColor is set here; explicit text colors above keep this
        // resilient to the material3 ListItemColors param set across BOM bumps.
        colors = ListItemDefaults.colors(
            containerColor = MaterialTheme.colorScheme.background,
        ),
        modifier = rowMod,
    )
}

/**
 * The ONLY sanctioned way to place a Switch in the suite. Fixes the passgen
 * `ToggleRow` finding: the whole row is [toggleable] with [SwitchRole] and
 * merged semantics, so TalkBack reads "&lt;label&gt;, switch, on" instead of an
 * unlabeled control. The inner [Switch] clears its own semantics so the row is
 * a single a11y node.
 */
@Composable
fun SwitchRow(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    supporting: String? = null,
    enabled: Boolean = true,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .toggleable(
                value = checked,
                enabled = enabled,
                role = SwitchRole,
                onValueChange = onCheckedChange,
            )
            .defaultMinSize(minHeight = 56.dp)
            .padding(
                horizontal = UnderstoryTheme.spacing.lg,
                vertical = UnderstoryTheme.spacing.md,
            ),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyLarge,
                color = if (enabled) MaterialTheme.colorScheme.onSurface
                else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (supporting != null) {
                Text(
                    text = supporting,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Switch(
            checked = checked,
            onCheckedChange = null, // row owns the toggle; keep as one a11y node
            enabled = enabled,
            modifier = Modifier
                .padding(start = UnderstoryTheme.spacing.md)
                .clearAndSetSemantics {},
        )
    }
}

/**
 * The ONLY sanctioned way to place a Slider in the suite. Fixes the passgen
 * "Slider no semantic label" finding: the slider carries a [contentDescription]
 * ("&lt;label&gt;: &lt;valueText&gt;"), a [stateDescription], and a
 * [progressBarRangeInfo] so TalkBack announces the current value and range.
 *
 * @param valueText caller-formatted display of [value] (e.g. "16 characters").
 * @param steps discrete stops between range ends, forwarded to [Slider].
 */
@Composable
fun SliderRow(
    label: String,
    value: Float,
    onValueChange: (Float) -> Unit,
    valueRange: ClosedFloatingPointRange<Float>,
    valueText: String,
    modifier: Modifier = Modifier,
    steps: Int = 0,
    enabled: Boolean = true,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(
                horizontal = UnderstoryTheme.spacing.lg,
                vertical = UnderstoryTheme.spacing.sm,
            ),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = valueText,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Slider(
            value = value,
            onValueChange = onValueChange,
            valueRange = valueRange,
            steps = steps,
            enabled = enabled,
            modifier = Modifier
                .fillMaxWidth()
                .semantics {
                    contentDescription = "$label: $valueText"
                    stateDescription = valueText
                    progressBarRangeInfo = ProgressBarRangeInfo(
                        current = value,
                        range = valueRange,
                        steps = steps,
                    )
                },
        )
    }
}

/**
 * A11y-safe reveal control for a masked secret. Enforces §3 A-2: the hidden
 * state announces "hidden" (never the value), the shown state announces the
 * [label] only (never speaks the secret characters). The caller supplies the
 * visual (icon or text) via [content]; this helper owns only the toggle and its
 * truthful semantics.
 *
 * @param revealed current reveal state (caller-held).
 * @param onToggle flip the reveal state.
 * @param label a non-secret name for what is being revealed (e.g. "Password").
 */
@Composable
fun RevealToggle(
    revealed: Boolean,
    onToggle: () -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    content: @Composable (revealed: Boolean) -> Unit,
) {
    val hiddenDesc = stringResource(R.string.cd_password_hidden)
    val shownDesc = stringResource(R.string.cd_reveal) + ": " + label
    Box(
        modifier = modifier
            .secureClickable(onToggle)
            .defaultMinSize(minWidth = 48.dp, minHeight = 48.dp)
            .semantics {
                role = Role.Button
                // Announce state truthfully; NEVER the secret characters.
                contentDescription = if (revealed) shownDesc else hiddenDesc
                toggleableState =
                    if (revealed) ToggleableState.On else ToggleableState.Off
            },
        contentAlignment = Alignment.Center,
    ) {
        content(revealed)
    }
}
