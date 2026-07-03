package com.understory.security.ui.components

import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.understory.security.R
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton

/**
 * The single home for every "delete vault / wipe / reset" confirm across the
 * suite. Uses the tap-jacking-hardened [SecureButton]/[SecureOutlinedButton] so
 * a destructive confirm can't be tap-jacked through an overlay, and tints the
 * confirm as [error].
 *
 * @param requireHold when true (irreversible ops), the confirm is a
 *   press-and-hold: the user must hold the confirm control for ~800ms, which a
 *   stray tap or a tap-jack overlay cannot satisfy. A progress bar shows the
 *   hold advancing; releasing early cancels.
 */
@Composable
fun ConfirmDestructiveDialog(
    visible: Boolean,
    title: String,
    body: String,
    confirmLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
    requireHold: Boolean = false,
) {
    if (!visible) return
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = {
            Icon(
                imageVector = Icons.Filled.Warning,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
            )
        },
        title = { Text(title, style = MaterialTheme.typography.titleLarge) },
        text = {
            Column {
                Text(body, style = MaterialTheme.typography.bodyMedium)
                if (requireHold) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.msg_hold_to_confirm),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        confirmButton = {
            if (requireHold) {
                HoldToConfirmButton(label = confirmLabel, onConfirm = onConfirm)
            } else {
                SecureButton(
                    onClick = onConfirm,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                ) { Text(confirmLabel) }
            }
        },
        dismissButton = {
            SecureOutlinedButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}

/**
 * Press-and-hold confirm affordance for irreversible ops. Fills a progress bar
 * over [holdMillis]; completing the hold fires [onConfirm]. Releasing early
 * resets. A single tap (or a tap-jack) cannot complete the hold.
 */
@Composable
private fun HoldToConfirmButton(
    label: String,
    onConfirm: () -> Unit,
    holdMillis: Long = 800L,
) {
    var holding by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0f) }

    LaunchedEffect(holding) {
        if (holding) {
            val start = System.currentTimeMillis()
            while (holding) {
                val elapsed = System.currentTimeMillis() - start
                progress = (elapsed.toFloat() / holdMillis).coerceIn(0f, 1f)
                if (progress >= 1f) {
                    holding = false
                    onConfirm()
                    break
                }
                // ~60fps poll; cheap and cancels the moment `holding` flips.
                kotlinx.coroutines.delay(16L)
            }
        } else {
            progress = 0f
        }
    }

    Column {
        SecureButton(
            onClick = { /* completion is via hold, not tap */ },
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.error,
                contentColor = MaterialTheme.colorScheme.onError,
            ),
            modifier = Modifier.pointerInput(Unit) {
                detectTapGestures(
                    onPress = {
                        holding = true
                        // Suspends until release/cancel, then resets the hold.
                        tryAwaitRelease()
                        holding = false
                    },
                )
            },
        ) { Text(label) }
        if (progress > 0f) {
            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}
