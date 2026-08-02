package com.understory.security.nav

import android.app.Activity
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.platform.LocalContext
import com.understory.security.Diagnostics

/**
 * The suite's single navigation primitive. Every app in the suite navigates through this and
 * nothing else.
 *
 * ## Why this exists rather than a per-app hand-rolled route enum
 *
 * Three navigation defects were reported across every app in the suite, and all three are the
 * same defect wearing different clothes — *navigation state that does not model the hierarchy
 * the user actually descended*:
 *
 *  1. **"nav bar back minimizes them ... many close when exited instead of minimizing."**
 *     A flat `var dest by rememberSaveable { mutableStateOf(Dest.HOME) }` installs no
 *     [BackHandler] at all, so back falls through to the platform default — which *finishes the
 *     activity*. For apps whose entire job is a long-lived foreground service (the firewall
 *     enforcing policy, the masker running, the privileged server serving other apps), being
 *     destroyed by a stray back press is the worst possible default.
 *  2. **"it returns to its main menu from every menu. even sub sub menus."**
 *     A single route variable cannot express *how the user got here*, so "back" can only mean
 *     "assign Main". Descending Home → Apps → Inspector → Elevation and pressing back lands on
 *     Home, discarding three levels at once.
 *  3. Overlays (an app inspector pushed over a tab) that swallow the screen but not the back
 *     gesture, so back skips past the overlay and closes the app underneath it.
 *
 * The previous fix attempt required *every route arm* to remember to write
 * `BackHandler { backToMain() }` by hand. That is the same bug with extra steps: the defect
 * returns the moment someone adds a screen and forgets a line, and it is invisible in review.
 *
 * **So back is not something a screen opts into here — it is a property of the host.**
 * [SuiteNavHost] installs exactly one [BackHandler] for the whole app, and it is the only one.
 * A screen author cannot forget it, cannot misimplement it, and cannot regress it.
 *
 * ## The back contract
 *
 * One rule, applied in order, and it is the same rule in all five apps:
 *
 *  1. An overlay is showing ⇒ dismiss the overlay, stay where we are.
 *  2. We are deeper than a tab root ⇒ pop **exactly one** level. (Fixes defect 2.)
 *  3. We are at a tab root that is not [home] ⇒ go to the home tab. (Standard Android
 *     bottom-nav behaviour; back never leaves the app from a side tab.)
 *  4. We are at the home root ⇒ **minimize** via `moveTaskToBack`, exactly as the Home button
 *     does. Never `finish()`. (Fixes defect 1 — the service survives.)
 *
 * ## Stack shape
 *
 * `[tabRoot, child, grandchild, ...]`. [selectTab] replaces the whole stack because switching
 * tabs is a lateral move, not a descent — a tab switch that pushed would make back walk
 * backwards through the user's tab history, which is not what a bottom bar means.
 *
 * Routes are held as [String] (typically `MyRoute.name`) so the stack is trivially saveable
 * through process death; the typed accessor is [currentAs].
 */
@Stable
class SuiteNav internal constructor(
    private val stack: SnapshotStateList<String>,
    /** The tab back returns to before minimizing. */
    val home: String,
    private val activity: Activity?,
    private val tag: String,
) {

    /** The route currently on screen. */
    val current: String get() = stack.last()

    /** How deep below the current tab's root we are; 1 == at a tab root. */
    val depth: Int get() = stack.size

    /** True when [back] would pop rather than switch tabs or minimize. */
    val canPop: Boolean get() = stack.size > 1

    /** True when the current route is the home tab's root — i.e. back would minimize. */
    val atHomeRoot: Boolean get() = stack.size == 1 && stack[0] == home

    /** The whole stack, oldest first. Useful for breadcrumbs. */
    val trail: List<String> get() = stack.toList()

    /** Typed read of [current]; returns null if the saved name no longer resolves. */
    inline fun <reified E : Enum<E>> currentAs(): E? =
        runCatching { enumValueOf<E>(current) }.getOrNull()

    /** Descend one level. Re-pushing the current route is a no-op (double-tap safety). */
    fun push(route: String) {
        if (stack.last() == route) return
        Diagnostics.log(tag, "push ${stack.last()} -> $route (depth ${stack.size + 1})")
        stack.add(route)
    }

    fun push(route: Enum<*>) = push(route.name)

    /**
     * Lateral move to a top-level tab: the stack is *replaced*, not extended, so the new tab
     * starts at its own root and back from it goes to [home] rather than retracing tab history.
     */
    fun selectTab(route: String) {
        if (stack.size == 1 && stack[0] == route) return
        Diagnostics.log(tag, "tab ${stack.last()} -> $route")
        stack.clear()
        stack.add(route)
    }

    fun selectTab(route: Enum<*>) = selectTab(route.name)

    /** Pop exactly one level. Returns false at a tab root (nothing to pop). */
    fun pop(): Boolean {
        if (stack.size <= 1) return false
        val from = stack.removeAt(stack.lastIndex)
        Diagnostics.log(tag, "pop $from -> ${stack.last()} (depth ${stack.size})")
        return true
    }

    /**
     * Unwind to an ancestor already on the stack — for a "done, back to the hub" action that
     * should collapse several levels at once. No-op if [route] is not an ancestor, so it can
     * never silently blow the stack away.
     */
    fun popTo(route: String) {
        val idx = stack.indexOfLast { it == route }
        if (idx < 0 || idx == stack.lastIndex) return
        Diagnostics.log(tag, "popTo $route (dropping ${stack.size - 1 - idx})")
        while (stack.lastIndex > idx) stack.removeAt(stack.lastIndex)
    }

    fun popTo(route: Enum<*>) = popTo(route.name)

    /**
     * Send the task to the background exactly as the Home button does. The activity — and every
     * foreground service it owns — stays alive. This is the deliberate opposite of `finish()`.
     */
    fun minimize() {
        Diagnostics.log(tag, "minimize (moveTaskToBack) from ${stack.last()}")
        activity?.moveTaskToBack(true)
    }

    /**
     * The back contract, in order. Called only by [SuiteNavHost]; exposed so an app can wire it
     * to a toolbar up-arrow and get behaviour identical to the system back gesture.
     */
    fun back() {
        when {
            pop() -> Unit
            stack[0] != home -> {
                Diagnostics.log(tag, "back at tab root ${stack[0]} -> home $home")
                stack[0] = home
            }
            else -> minimize()
        }
    }
}

/**
 * Create the app's [SuiteNav], surviving rotation and process death.
 *
 * @param home the route back returns to before minimizing — the app's landing tab.
 * @param tag Diagnostics tag, conventionally `"<app>.nav"`.
 */
@Composable
fun rememberSuiteNav(home: String, tag: String): SuiteNav {
    val activity = LocalContext.current as? Activity
    val stack = rememberSaveable(
        saver = listSaver<SnapshotStateList<String>, String>(
            save = { it.toList() },
            restore = { mutableStateListOf<String>().apply { addAll(it) } },
        ),
    ) { mutableStateListOf(home) }
    // Guard against a restore that saved an empty stack (or a home rename between versions):
    // an empty stack would make `current` throw on the very first frame.
    if (stack.isEmpty()) stack.add(home)
    return remember(stack, home, activity, tag) { SuiteNav(stack, home, activity, tag) }
}

@Composable
fun rememberSuiteNav(home: Enum<*>, tag: String): SuiteNav = rememberSuiteNav(home.name, tag)

/**
 * Hosts an app's content and owns **the app's only** [BackHandler].
 *
 * Wrap the whole app body in this exactly once. Screens inside never declare a `BackHandler` and
 * never need an `onBack` that means "go to main" — they take `nav.pop()` (or nothing at all, and
 * let the system gesture do it).
 *
 * @param overlayShowing true while a modal surface (inspector, sheet, wizard) covers the screen.
 *   Back dismisses it first and goes no further — the reported "back closes the app from behind
 *   an overlay" case.
 * @param onDismissOverlay how to dismiss that overlay.
 */
@Composable
fun SuiteNavHost(
    nav: SuiteNav,
    overlayShowing: Boolean = false,
    onDismissOverlay: () -> Unit = {},
    content: @Composable (route: String) -> Unit,
) {
    // enabled = true unconditionally: this handler must beat the platform default in EVERY
    // state, including at the home root, because the platform default there is finish().
    BackHandler(enabled = true) {
        if (overlayShowing) onDismissOverlay() else nav.back()
    }
    content(nav.current)
}
