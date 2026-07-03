package com.understory.security

import android.app.Activity
import android.view.WindowManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.understory.security.ui.Bg
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The one shared reset screen (design §4.1) that replaces the four ad-hoc
 * dead-ends. Reached from (a) the [VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED]
 * unlock branch and (b) a "Reset vault" entry in each app's settings/overflow.
 *
 * Drives a [VaultRecovery.ResetPlan]. Carries no app-specific logic: the app
 * supplies [hooks] ([VaultResetHooks]) and, when the key is usable and it wants
 * the export-first step, an [onExportFirst] callback that navigates to
 * [VaultExportScreen] and calls back when export is done or skipped.
 *
 * @param keyUsable       true for a deliberate reset over an openable vault;
 *                        false when the key was invalidated (export impossible).
 * @param appName         used in the typed confirmation and copy.
 * @param hooks           app glue; [VaultResetHooks.wipe] + [VaultResetHooks.goToSetup].
 * @param onExportFirst   navigate to export; invoke the given `done` lambda when
 *                        the user finishes OR skips. Ignored when !keyUsable.
 */
@Composable
fun VaultRecoveryScreen(
    keyUsable: Boolean,
    appName: String,
    hooks: VaultResetHooks,
    onExportFirst: ((done: () -> Unit) -> Unit)? = null,
) {
    val ctx = LocalContext.current
    val view = LocalView.current
    val scope = rememberCoroutineScope()
    val plan = remember(keyUsable) { VaultRecovery.ResetPlan(keyUsable) }
    // Recompose driver: ResetPlan is a plain class, so mirror its step into
    // Compose state and bump it on every transition.
    var step by remember { mutableStateOf(plan.step) }
    var confirmField by remember { mutableStateOf(TextFieldValue("")) }

    // The reset screen shows unreadable-state context; FLAG_SECURE keeps it out
    // of screenshots/recents like the rest of the vault surfaces.
    DisposableEffect(Unit) {
        val activity = ctx as? Activity
        activity?.window?.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        onDispose { activity?.window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }

    LaunchedEffect(step) {
        if (step == VaultRecovery.ResetStep.DONE) hooks.goToSetup()
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(RecoveryCopy.RESET_TITLE, color = Color(0xFFE0E0E0), fontSize = 22.sp)

        when (step) {
            VaultRecovery.ResetStep.EXPLAIN -> {
                Text(
                    if (keyUsable) RecoveryCopy.RESET_EXPLAIN_KEY_USABLE
                    else RecoveryCopy.RESET_EXPLAIN_KEY_INVALIDATED,
                    color = Color(0xFF9E9E9E), fontSize = 13.sp,
                )
                Spacer(Modifier.height(4.dp))
                SecureButton(
                    onClick = { plan.begin(); step = plan.step },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (keyUsable) "Continue" else RecoveryCopy.RESET_CONFIRM_BUTTON) }
            }

            VaultRecovery.ResetStep.EXPORT_FIRST -> {
                Text(RecoveryCopy.RESET_EXPORT_FIRST, color = Color(0xFF9E9E9E), fontSize = 13.sp)
                Spacer(Modifier.height(4.dp))
                SecureButton(
                    onClick = {
                        // Hand off to the export screen; it calls back when the
                        // user finishes or skips. If no export nav was wired,
                        // treat "Export" as satisfied so the flow can proceed.
                        val cb = onExportFirst
                        if (cb != null) cb { plan.onExportDone(); step = plan.step }
                        else { plan.onExportDone(); step = plan.step }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(RecoveryCopy.EXPORT_TITLE) }
                SecureOutlinedButton(
                    onClick = { plan.onExportSkipped(); step = plan.step },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(RecoveryCopy.RESET_EXPORT_SKIP) }
            }

            VaultRecovery.ResetStep.CONFIRM_WIPE -> {
                Text(
                    RecoveryCopy.resetConfirmPrompt(appName),
                    color = Color(0xFF9E9E9E), fontSize = 13.sp,
                )
                OutlinedTextField(
                    value = confirmField,
                    onValueChange = { confirmField = it },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                val matches = plan.confirmationMatches(confirmField.text, appName)
                Spacer(Modifier.height(4.dp))
                SecureButton(
                    onClick = {
                        if (!plan.confirmationMatches(confirmField.text, appName)) return@SecureButton
                        // Extra tap-jack guard beyond SecureButton's own checks.
                        if (!view.hasWindowFocus()) return@SecureButton
                        plan.onWipeConfirmed(); step = plan.step
                        scope.launch {
                            withContext(Bg.io) { hooks.wipe(ctx) }
                            plan.onWiped(); step = plan.step
                        }
                    },
                    enabled = matches,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                    ),
                ) { Text(RecoveryCopy.RESET_CONFIRM_BUTTON) }
            }

            VaultRecovery.ResetStep.WIPING -> {
                Text(RecoveryCopy.RESET_WIPING, color = Color(0xFF9E9E9E), fontSize = 13.sp)
                Spacer(Modifier.height(4.dp))
                CircularProgressIndicator()
            }

            VaultRecovery.ResetStep.DONE -> {
                // LaunchedEffect(step) routes to Setup; render nothing meaningful.
                CircularProgressIndicator()
            }
        }
    }
}
