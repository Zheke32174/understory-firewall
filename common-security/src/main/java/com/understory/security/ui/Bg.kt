package com.understory.security.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.produceState
import com.understory.security.ui.components.UiState
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The one place the whole suite names its background dispatchers. Crypto and IO
 * must run here, never on `Dispatchers.Main` — main-thread Argon2id (64 MiB),
 * vault re-encrypt, SAF import parse and QR decode are all ANR-class and make
 * loading states unrenderable (SUITE #8).
 *
 * Convention (normative):
 *  - T-1: any `Crypto.*` / Argon2id / KEK wrap-unwrap / GCM, any SAF/file
 *    read-write-parse, any QR encode/decode runs inside `withContext(Bg.io)` or
 *    `Bg.cpu` — never on the composition thread.
 *  - T-2: UI drives these from `viewModelScope` / `rememberCoroutineScope`
 *    launch or [produceUiState], renders `LoadingState` meanwhile, and shows
 *    `ErrorState` / `FatalScreen` on failure.
 *  - T-3: input size caps happen BEFORE `readText()`; the import path checks
 *    length, then parses on [io].
 */
object Bg {
    /** Disk / SAF / network — anything IO-bound. */
    val io: CoroutineDispatcher = Dispatchers.IO

    /** CPU-bound: Argon2id, QR decode, re-encrypt. */
    val cpu: CoroutineDispatcher = Dispatchers.Default
}

/**
 * Best-effort user-facing message for an exception surfaced by [produceUiState].
 * Never leaks a stack trace or a secret; falls back to the exception's simple
 * class name when it carries no message.
 */
fun Throwable.messageForUser(): String =
    message?.takeIf { it.isNotBlank() } ?: (this::class.simpleName ?: "Unknown error")

/**
 * Run [block] off-main and reflect it as a [UiState]. Callers write one line and
 * get `Loading → Ready/Error` for free; pair with `UiStateHost` (§2.3). The work
 * runs on [Bg.cpu] (safe for crypto/QR); IO-heavy callers can `withContext(Bg.io)`
 * inside [block].
 *
 *   val state by produceUiState(vaultId) { vault.unlock(vaultId, password) }
 *   UiStateHost(state) { entries -> VaultList(entries) }
 */
@Composable
fun <T> produceUiState(
    vararg keys: Any?,
    block: suspend () -> T,
): State<UiState<T>> =
    produceState<UiState<T>>(UiState.Loading, *keys) {
        value = runCatching { withContext(Bg.cpu) { block() } }
            .fold(
                onSuccess = { UiState.Ready(it) },
                onFailure = { UiState.Error(it.messageForUser()) },
            )
    }
