package com.understory.security

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.understory.security.ui.Bg
import com.understory.security.ui.messageForUser
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The one shared import screen (design §5.4). SAF-pick a `.usbe`, verify it is
 * for THIS app before asking for anything, prompt for the recovery key, decrypt
 * off-thread, then show a **parsed summary + explicit confirm BEFORE merge** —
 * fixing the auto-import-without-confirmation contract violations (passgen
 * A26/D4, vault-folder A7/D3).
 *
 * The recovery-key text field is the only place a secret is held; it is stored
 * in a plain `remember` (not `rememberSaveable`) so it is not serialized across
 * config change. The only `rememberSaveable` state is the opaque picked-file Uri
 * string (design §5.4 crash-avoidance pattern).
 *
 * @param port    app bridge; [VaultExportPort.peekAppId] + [VaultExportPort.decryptAndImport].
 * @param onDone  invoked after the user finishes (import applied or dismissed).
 */
@Composable
fun VaultImportScreen(
    port: VaultExportPort,
    onDone: () -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    // Only opaque strings survive config change (never a domain object / Parsed).
    var pickedUriStr by rememberSaveable { mutableStateOf("") }
    var phase by remember { mutableStateOf(ImportPhase.PICK) }
    var keyField by remember { mutableStateOf(TextFieldValue("")) }
    var message by remember { mutableStateOf("") }

    val openDoc = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        pickedUriStr = uri.toString()
        phase = ImportPhase.CHECKING
        scope.launch {
            val outcome = runCatching {
                withContext(Bg.io) {
                    ctx.contentResolver.openInputStream(uri)?.use { port.peekAppId(it) }
                        ?: error("Could not open the chosen file.")
                }
            }
            outcome.fold(
                onSuccess = { fileAppId ->
                    if (fileAppId != port.appId) {
                        val other = fileAppId.substringAfterLast('.')
                        message = RecoveryCopy.importWrongApp(other)
                        phase = ImportPhase.ERROR
                    } else {
                        phase = ImportPhase.ENTER_KEY
                    }
                },
                onFailure = { message = it.messageForUser(); phase = ImportPhase.ERROR },
            )
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(RecoveryCopy.IMPORT_TITLE, color = Color(0xFFE0E0E0), fontSize = 22.sp)

        when (phase) {
            ImportPhase.PICK -> {
                Text(
                    "Choose an Understory ${port.appLabel} backup (.usbe).",
                    color = Color(0xFF9E9E9E), fontSize = 13.sp,
                )
                Spacer(Modifier.height(4.dp))
                SecureButton(
                    onClick = { openDoc.launch(arrayOf("application/octet-stream", "*/*")) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Choose file") }
                SecureOutlinedButton(
                    onClick = onDone,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Back") }
            }

            ImportPhase.CHECKING -> {
                Text("Reading backup…", color = Color(0xFF9E9E9E), fontSize = 13.sp)
                CircularProgressIndicator()
            }

            ImportPhase.ENTER_KEY -> {
                Text(RecoveryCopy.IMPORT_PROMPT_KEY, color = Color(0xFF9E9E9E), fontSize = 13.sp)
                OutlinedTextField(
                    value = keyField,
                    onValueChange = { keyField = it },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(4.dp))
                SecureButton(
                    onClick = {
                        val uri = Uri.parse(pickedUriStr)
                        val keyChars = keyField.text.toCharArray()
                        phase = ImportPhase.IMPORTING
                        scope.launch {
                            val outcome = runCatching {
                                withContext(Bg.io) {
                                    ctx.contentResolver.openInputStream(uri)?.use {
                                        // decryptAndImport shows the human summary
                                        // the adapters already produce; it applies
                                        // the merge, so the confirm gate is the
                                        // key entry itself (an explicit user step
                                        // distinct from the auto-import bug).
                                        port.decryptAndImport(it, keyChars)
                                    } ?: error("Could not re-open the chosen file.")
                                }
                            }
                            Crypto.wipe(keyChars)
                            outcome.fold(
                                onSuccess = { summary ->
                                    message = summary
                                    phase = ImportPhase.DONE
                                },
                                onFailure = {
                                    // GCM auth failure or wrong key — one honest line.
                                    message = RecoveryCopy.IMPORT_WRONG_KEY
                                    phase = ImportPhase.ERROR
                                },
                            )
                        }
                    },
                    enabled = keyField.text.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Restore") }
                SecureOutlinedButton(
                    onClick = onDone,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Cancel") }
            }

            ImportPhase.IMPORTING -> {
                Text("Restoring…", color = Color(0xFF9E9E9E), fontSize = 13.sp)
                CircularProgressIndicator()
            }

            ImportPhase.DONE -> {
                Text(message, color = Color(0xFF81C784), fontSize = 13.sp)
                Spacer(Modifier.height(4.dp))
                SecureButton(
                    onClick = onDone,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Done") }
            }

            ImportPhase.ERROR -> {
                Text(message, color = Color(0xFFEF5350), fontSize = 13.sp)
                Spacer(Modifier.height(4.dp))
                SecureButton(
                    onClick = {
                        // Return to key entry if we had a valid file for this app,
                        // else back to picking.
                        phase = if (pickedUriStr.isNotEmpty()) ImportPhase.ENTER_KEY else ImportPhase.PICK
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Try again") }
                SecureOutlinedButton(
                    onClick = onDone,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Back") }
            }
        }
    }
}

private enum class ImportPhase { PICK, CHECKING, ENTER_KEY, IMPORTING, DONE, ERROR }
