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
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.understory.security.ui.Bg
import com.understory.security.ui.messageForUser
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The one shared export screen (design §5.2). Reached from the vault-list
 * overflow, the §3.5 refresh prompt, and the §4 export-first reset step.
 *
 * The default and recommended output is the encrypted [com.understory.backup]
 * envelope written by [port] under the vault's recovery key. A plaintext /
 * incumbent-interop path is offered ONLY behind a second, destructive-styled
 * confirmation ([onExportPlaintext]).
 *
 * Crash-safety (vault-folder A8, design §5.4): this composable holds NO
 * non-Parcelable domain object in `rememberSaveable`. Its only survivable state
 * is the [ExportPhase] enum's `.name` (an opaque String) — never a `Parsed`
 * envelope or a vault entry. Apps that add a per-entry export selection MUST
 * follow the same rule: save the entry **id string** and re-resolve it against
 * the live store on return, exactly as this screen models.
 *
 * @param port           app bridge to the envelope + adapter.
 * @param unlocked       the app's already-unlocked vault handle (passed to
 *                       [VaultExportPort.buildPayload]). May be null when the
 *                       app builds its payload without a handle.
 * @param recoveryKey    the vault recovery key. Ownership stays with the caller;
 *                       this screen does not wipe it (the caller's
 *                       enrollment/reveal scope owns its lifecycle). A private
 *                       copy is passed to [port] and wiped there.
 * @param onDone         invoked after a successful write (or user dismiss).
 * @param onExportPlaintext optional plaintext-interop path; when non-null an
 *                        "Export for another app (unencrypted)" action shows.
 */
@Composable
fun VaultExportScreen(
    port: VaultExportPort,
    unlocked: Any?,
    recoveryKey: CharArray,
    onDone: () -> Unit,
    onExportPlaintext: (() -> Unit)? = null,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    // Survivable state is the phase enum's name only (opaque String), never a
    // domain object — the pattern that prevents the vault-folder A8 crash. The
    // enum is the single source of truth; `phase` is derived from it.
    var phaseName by rememberSaveable { mutableStateOf(ExportPhase.IDLE.name) }
    val phase = ExportPhase.valueOf(phaseName)
    var resultMsg by remember { mutableStateOf("") }
    var confirmPlaintext by remember { mutableStateOf(false) }

    val createDoc = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri: Uri? ->
        if (uri == null) { phaseName = ExportPhase.IDLE.name; return@rememberLauncherForActivityResult }
        phaseName = ExportPhase.WRITING.name
        scope.launch {
            val outcome = runCatching {
                withContext(Bg.io) {
                    // Build payload + write envelope entirely off the main
                    // thread so the WRITING state is actually renderable
                    // (SUITE #8 — the "unreachable loading state" fix).
                    val payload = port.buildPayload(unlocked)
                        ?: error("Export unavailable — vault could not be read.")
                    ctx.contentResolver.openOutputStream(uri)?.use { out ->
                        // port.writeEncrypted wipes payload internally. The
                        // envelope label is left empty here — a whole-vault
                        // export isn't scoped to one entry. savedEntryId exists
                        // only to survive config change per the crash-safe
                        // pattern; the app re-resolves it against the live store.
                        port.writeEncrypted(out, payload, recoveryKey, label = "")
                    } ?: run {
                        Crypto.wipe(payload)
                        error("Could not open the chosen file for writing.")
                    }
                }
            }
            outcome.fold(
                onSuccess = { phaseName = ExportPhase.DONE.name; resultMsg = "Backup saved." },
                onFailure = { phaseName = ExportPhase.ERROR.name; resultMsg = it.messageForUser() },
            )
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(RecoveryCopy.EXPORT_TITLE, color = Color(0xFFE0E0E0), fontSize = 22.sp)

        when (phase) {
            ExportPhase.IDLE -> {
                Text(RecoveryCopy.EXPORT_ENCRYPTED_DEFAULT, color = Color(0xFF9E9E9E), fontSize = 13.sp)
                Spacer(Modifier.height(4.dp))
                SecureButton(
                    onClick = { createDoc.launch(defaultExportFilename(port.appLabel)) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Save encrypted backup") }

                if (onExportPlaintext != null) {
                    if (!confirmPlaintext) {
                        SecureOutlinedButton(
                            onClick = { confirmPlaintext = true },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Export for another app (unencrypted)") }
                    } else {
                        Text(
                            RecoveryCopy.exportPlaintextWarning(port.appLabel),
                            color = Color(0xFFFFB74D), fontSize = 12.sp,
                        )
                        SecureButton(
                            onClick = { confirmPlaintext = false; onExportPlaintext() },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.error,
                            ),
                        ) { Text("Yes, write unencrypted") }
                        SecureOutlinedButton(
                            onClick = { confirmPlaintext = false },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Cancel") }
                    }
                }

                SecureOutlinedButton(
                    onClick = onDone,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Back") }
            }

            ExportPhase.WRITING -> {
                Text("Encrypting and saving…", color = Color(0xFF9E9E9E), fontSize = 13.sp)
                Spacer(Modifier.height(4.dp))
                CircularProgressIndicator()
            }

            ExportPhase.DONE -> {
                Text(resultMsg, color = Color(0xFF81C784), fontSize = 13.sp)
                Spacer(Modifier.height(4.dp))
                SecureButton(
                    onClick = onDone,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Done") }
            }

            ExportPhase.ERROR -> {
                Text(resultMsg, color = Color(0xFFEF5350), fontSize = 13.sp)
                Spacer(Modifier.height(4.dp))
                SecureButton(
                    onClick = { phaseName = ExportPhase.IDLE.name },
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

private enum class ExportPhase { IDLE, WRITING, DONE, ERROR }

private val exportDateFormat = SimpleDateFormat("yyyyMMdd", Locale.US)

/** `understory-<applabel>-YYYYMMDD.usbe`, lower-cased app label. */
internal fun defaultExportFilename(appLabel: String): String {
    val slug = appLabel.lowercase(Locale.US).replace(Regex("[^a-z0-9]+"), "-").trim('-')
    return "understory-$slug-${exportDateFormat.format(Date())}.usbe"
}
