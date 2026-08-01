package com.understory.security

import android.app.Activity
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

/**
 * Composable that intercepts back-at-root so back MINIMIZES the app (moveTaskToBack — same as
 * Home) instead of the default Android "back at root finishes the activity" semantic that
 * DESTROYS it.
 *
 * WHY THIS IS NOW UNCONDITIONAL. It used to be gated on [TestingMode.KEEP_ALIVE_ON_LEAVE] and
 * became a no-op in release — so a shipped build fell through to finish() and CLOSED the app on
 * back at root. That was reported directly: the apps "close when exited instead of minimizing",
 * killing the very background service they exist to run (the firewall enforcing policy, the
 * masker running, the detector watching). Being destroyed by a stray back press is the worst
 * default for a service-backed app, so minimize-on-root is the correct PRODUCTION behaviour, not
 * a test convenience — the gate is removed and it is always installed.
 *
 * Use at every entry-level route. Sub-routes navigate up the in-app stack with their own
 * BackHandler; this is for the truly-root case where back would otherwise close the activity.
 */
@Composable
fun KeepAliveBackHandler(tag: String) {
    val activity = LocalContext.current as? Activity ?: return
    BackHandler {
        Diagnostics.log(tag, "back at root: moveTaskToBack")
        activity.moveTaskToBack(true)
    }
}
