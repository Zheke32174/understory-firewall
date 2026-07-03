package com.understory.security

import android.app.Activity
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

/**
 * Composable that installs a `BackHandler` intercepting back-at-root.
 * When [TestingMode.KEEP_ALIVE_ON_LEAVE] is true, back at the call site
 * minimizes the activity to the background via `moveTaskToBack(true)`
 * — same effect as pressing home — instead of the default Android
 * "back at root finishes the activity" semantic.
 *
 * When [TestingMode.KEEP_ALIVE_ON_LEAVE] is false (release), this is
 * a no-op: no BackHandler is registered, system back falls through
 * to the activity's default finish path. So this composable is a
 * test-phase convenience that disappears entirely for production.
 *
 * Use at every entry-level Compose route (Setup, Unlock, List, Main,
 * Generator — whichever screens the user might press back from
 * expecting to leave the app). Sub-routes (Add, Diagnostics, etc.)
 * should have their own BackHandler navigating up the in-app stack
 * — this helper is for the truly-root cases where back would
 * otherwise close the activity.
 */
@Composable
fun KeepAliveBackHandler(tag: String) {
    if (!TestingMode.KEEP_ALIVE_ON_LEAVE) return
    val activity = LocalContext.current as? Activity ?: return
    BackHandler {
        Diagnostics.log(tag, "back at root: moveTaskToBack")
        activity.moveTaskToBack(true)
    }
}
