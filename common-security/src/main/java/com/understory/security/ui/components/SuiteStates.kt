package com.understory.security.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.understory.security.R
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * The four screen-level states every list/detail surface can now render —
 * possible only because §5 moved crypto/IO off the main thread, so a spinner
 * can actually paint. [ErrorState] and [FatalScreen] are the CD-4 "failure
 * honesty" surfaces: silent dead-ends and blind `finish()` calls are replaced
 * by a truthful message.
 */
sealed interface UiState<out T> {
    data object Loading : UiState<Nothing>
    data class Ready<T>(val value: T) : UiState<T>
    data class Empty(val message: String) : UiState<Nothing>
    data class Error(val message: String, val onRetry: (() -> Unit)? = null) : UiState<Nothing>
}

/**
 * Centered spinner + label. Announced to TalkBack as a polite live region so a
 * screen reader is told when a long crypto/IO op begins and the label changes.
 */
@Composable
fun LoadingState(
    label: String = stringResource(R.string.state_loading),
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(UnderstoryTheme.spacing.xl)
            .semantics {
                contentDescription = label
                liveRegion = LiveRegionMode.Polite
            },
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(UnderstoryTheme.spacing.md))
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

/**
 * Empty-list state: optional icon, a title, optional body, optional CTA slot.
 * Directly supplies the passgen "empty state for vault list" finding.
 */
@Composable
fun EmptyState(
    title: String,
    modifier: Modifier = Modifier,
    body: String? = null,
    icon: ImageVector? = null,
    action: (@Composable () -> Unit)? = null,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(UnderstoryTheme.spacing.xl),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        if (icon != null) {
            Icon(
                imageVector = icon,
                contentDescription = null, // decorative; the title carries meaning
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(48.dp),
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
        }
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.Center,
        )
        if (body != null) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                text = body,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        if (action != null) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
            action()
        }
    }
}

/**
 * Error surface — an error-tinted card with the message and an optional Retry.
 * NEVER swallows: this is where swallowed taps and silent hard-fails (CD-4c)
 * surface a truthful message. The Retry button is the tap-jacking-hardened
 * [SecureOutlinedButton].
 */
@Composable
fun ErrorState(
    message: String,
    modifier: Modifier = Modifier,
    onRetry: (() -> Unit)? = null,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(UnderstoryTheme.spacing.xl),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Surface(
            color = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier.padding(UnderstoryTheme.spacing.lg),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
            ) {
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                )
                if (onRetry != null) {
                    SecureOutlinedButton(onClick = onRetry) {
                        Text(stringResource(R.string.action_retry))
                    }
                }
            }
        }
    }
}

/**
 * When-dispatch over the four states so a caller writes one line and renders the
 * right surface. [ready] is invoked only in [UiState.Ready]; the other three map
 * to [LoadingState] / [EmptyState] / [ErrorState].
 */
@Composable
fun <T> UiStateHost(
    state: UiState<T>,
    modifier: Modifier = Modifier,
    ready: @Composable (T) -> Unit,
) {
    when (state) {
        is UiState.Loading -> LoadingState(modifier = modifier)
        is UiState.Empty -> EmptyState(title = state.message, modifier = modifier)
        is UiState.Error -> ErrorState(
            message = state.message,
            onRetry = state.onRetry,
            modifier = modifier,
        )
        is UiState.Ready -> ready(state.value)
    }
}

/**
 * Full-screen fatal surface. Replaces the silent tamper/attestation
 * `finish(); return` (CD-4c honesty): the user is told *why* the app refused to
 * continue. Renders an error-container background, [headlineSmall] title,
 * [bodyMedium] reason, and an optional expandable [details] block in monospace
 * [labelSmall] — a shared home for the per-app `renderDiagnostic` text, so its
 * hex/`sp` literals die too.
 *
 * This is the "warn, don't die" antivirus/tamper surface: the caller decides
 * whether it is terminal, but the user always gets a message.
 */
@Composable
fun FatalScreen(
    title: String,
    reason: String,
    modifier: Modifier = Modifier,
    details: String? = null,
) {
    var showDetails by remember { mutableStateOf(false) }
    Surface(
        modifier = modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.xl),
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.error,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
            Text(
                text = reason,
                style = MaterialTheme.typography.bodyMedium,
            )
            if (details != null) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
                SecureOutlinedButton(onClick = { showDetails = !showDetails }) {
                    Text(
                        stringResource(
                            if (showDetails) R.string.action_hide_details
                            else R.string.action_show_details
                        )
                    )
                }
                if (showDetails) {
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    Surface(
                        color = MaterialTheme.colorScheme.surface,
                        contentColor = MaterialTheme.colorScheme.onSurface,
                        shape = MaterialTheme.shapes.small,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            text = details,
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            modifier = Modifier.padding(UnderstoryTheme.spacing.md),
                        )
                    }
                }
            }
        }
    }
}
