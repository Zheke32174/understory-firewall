package com.ant.emichaosbg.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * THE RULE EVERY SCREEN IN THE OLD BUILD KEPT BREAKING, in one place.
 *
 * Every detector call in this app BLOCKS: Keystore key generation, /proc reads,
 * telephony binder round-trips, an AES-GCM decrypt per vault record. Calling one
 * from a composable body freezes the frame; the old Security tab did exactly that
 * and was reported as "keeps freezing".
 *
 * So: gather on Dispatchers.IO, publish on the composition's own thread, and never
 * start a second run while one is in flight. A screen holds a [Probe], calls
 * [Probe.refresh] from a button, and renders [Probe.json] — there is no other way
 * for a detector result to reach the UI.
 */
@Stable
class Probe internal constructor(
    private val scope: CoroutineScope,
    private val run: () -> String,
) {
    /** Last successful result. Null means "has not produced one yet", never "clean". */
    var json by mutableStateOf<JSONObject?>(null)
        private set

    var busy by mutableStateOf(false)
        private set

    /** Set when the call itself threw, as opposed to returning a negative result. */
    var error by mutableStateOf<String?>(null)
        private set

    /** True once a run has completed, so a screen can tell "never ran" from "found nothing". */
    var ran by mutableStateOf(false)
        private set

    fun refresh() {
        if (busy) return
        busy = true
        scope.launch {
            val r = withContext(Dispatchers.IO) {
                runCatching { JSONObject(run()) }
            }
            r.onSuccess { json = it; error = null }
            r.onFailure { error = it.javaClass.simpleName + ": " + (it.message ?: "no detail") }
            ran = true
            busy = false
        }
    }
}

/**
 * @param autoRun run once when the screen first composes. On for read-only status
 *   reads; deliberately OFF for anything that spins a radio, so a scan is a thing
 *   the user asked for.
 */
@Composable
fun rememberProbe(autoRun: Boolean = true, run: () -> String): Probe {
    val scope = rememberCoroutineScope()
    val probe = remember { Probe(scope, run) }
    LaunchedEffect(probe) { if (autoRun) probe.refresh() }
    return probe
}

/** Fire-and-forget background action (start/stop a scanner, write an export). */
@Composable
fun rememberAction(): Action {
    val scope = rememberCoroutineScope()
    return remember { Action(scope) }
}

@Stable
class Action internal constructor(private val scope: CoroutineScope) {
    var busy by mutableStateOf(false)
        private set
    var result by mutableStateOf<String?>(null)
        private set

    fun go(work: () -> String) {
        if (busy) return
        busy = true
        scope.launch {
            val r = withContext(Dispatchers.IO) { runCatching(work) }
            result = r.getOrElse { it.javaClass.simpleName + ": " + (it.message ?: "") }
            busy = false
        }
    }

    fun clear() { result = null }
}
