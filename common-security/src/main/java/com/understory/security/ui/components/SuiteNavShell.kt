package com.understory.security.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreHoriz
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import com.understory.security.R
import com.understory.security.nav.SuiteNav
import com.understory.security.nav.SuiteNavHost
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * One top-level destination in [SuiteNavShell]'s bottom bar.
 *
 * @param route the route name this tab selects — normally `MyRoute.NAME.name`.
 * @param label the bottom-bar caption. Keep it ONE short word; see [SuiteNavShell] for why.
 * @param title the app-bar title when this tab is showing. Defaults to [label].
 */
data class SuiteTab(
    val route: String,
    val label: String,
    val icon: ImageVector,
    val contentDescription: String = label,
    val title: String = label,
)

/**
 * The suite's shared app chrome for a **multi-destination** app: one app bar, one bottom bar,
 * one snackbar host, and — via [SuiteNavHost] — exactly one back handler.
 *
 * [SuiteScaffold] remains the chrome for a single leaf screen. This is its sibling for the
 * screens that own navigation.
 *
 * ## Why the bottom bar overflows automatically
 *
 * Material3's `NavigationBar` divides its width evenly across its children, with no scrolling
 * and no eliding. Yojimbo shipped **eight** items in one bar: at that count each item gets
 * roughly 45dp on a normal phone, labels truncate to two or three characters, and the 48dp
 * minimum touch target is violated. That is the reported "many menus not proportioned well",
 * and it is not a styling nitpick — it is a bar the user cannot read or reliably hit.
 *
 * The spec's ceiling is five. So this shell **enforces** it rather than trusting each app to
 * remember: past [MAX_PRIMARY_TABS] it renders the first four tabs plus a "More" affordance,
 * and the remainder open from a sheet. An app can hand this component fifteen destinations and
 * still get a legible, correctly-proportioned bar — the failure mode is designed out instead of
 * being left to review.
 *
 * ## Chrome rules
 *
 * - The bottom bar shows only at a tab root. Once the user descends, the bar is replaced by a
 *   back arrow, so a sub-screen can never be silently swapped underneath a highlighted tab.
 * - The up-arrow and the system back gesture do **the same thing** — both call [SuiteNav.back].
 *   Two affordances that disagree is its own bug class.
 *
 * @param overlayShowing true while a modal surface covers the content; back dismisses it first.
 * @param content receives the current route and the scaffold insets.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SuiteNavShell(
    nav: SuiteNav,
    tabs: List<SuiteTab>,
    modifier: Modifier = Modifier,
    /** Overrides the tab-derived title — for pushed sub-screens and overlays. */
    title: String? = null,
    snackbarHost: SnackbarHostState? = null,
    actions: @Composable RowScope.() -> Unit = {},
    overlayShowing: Boolean = false,
    onDismissOverlay: () -> Unit = {},
    content: @Composable (route: String, padding: PaddingValues) -> Unit,
) {
    var showOverflow by remember { mutableStateOf(false) }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    val overflows = tabs.size > MAX_PRIMARY_TABS
    val primary = if (overflows) tabs.take(MAX_PRIMARY_TABS - 1) else tabs
    val overflow = if (overflows) tabs.drop(MAX_PRIMARY_TABS - 1) else emptyList()

    SuiteNavHost(
        nav = nav,
        overlayShowing = overlayShowing,
        onDismissOverlay = onDismissOverlay,
    ) { route ->
        val activeTab = tabs.firstOrNull { it.route == route }
        // At a tab root with no overlay: this is a top-level destination, so the bottom bar is
        // the right affordance and there is nothing to go "up" to.
        val atTabRoot = nav.depth == 1 && !overlayShowing && activeTab != null

        Scaffold(
            modifier = modifier.fillMaxSize(),
            containerColor = MaterialTheme.colorScheme.background,
            snackbarHost = { if (snackbarHost != null) SnackbarHost(snackbarHost) },
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            text = title ?: activeTab?.title ?: route,
                            style = MaterialTheme.typography.titleLarge,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    },
                    navigationIcon = {
                        // Shown exactly when back would go somewhere other than "minimize", so
                        // the arrow and the gesture never disagree.
                        if (!atTabRoot) {
                            IconButton(onClick = {
                                if (overlayShowing) onDismissOverlay() else nav.back()
                            }) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                    contentDescription = stringResource(R.string.cd_back),
                                )
                            }
                        }
                    },
                    actions = actions,
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surface,
                        titleContentColor = MaterialTheme.colorScheme.onSurface,
                        navigationIconContentColor = MaterialTheme.colorScheme.onSurface,
                        actionIconContentColor = MaterialTheme.colorScheme.onSurface,
                    ),
                )
            },
            bottomBar = {
                if (atTabRoot) {
                    NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                        primary.forEach { tab ->
                            NavigationBarItem(
                                selected = route == tab.route,
                                onClick = { nav.selectTab(tab.route) },
                                icon = {
                                    Icon(tab.icon, contentDescription = tab.contentDescription)
                                },
                                label = {
                                    Text(tab.label, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                },
                                alwaysShowLabel = false,
                            )
                        }
                        if (overflows) {
                            NavigationBarItem(
                                // Stays lit while any overflow destination is showing, so the bar
                                // never claims nothing is selected.
                                selected = overflow.any { it.route == route },
                                onClick = { showOverflow = true },
                                icon = {
                                    Icon(
                                        Icons.Filled.MoreHoriz,
                                        contentDescription = stringResource(R.string.cd_more),
                                    )
                                },
                                label = {
                                    Text(
                                        stringResource(R.string.nav_more),
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                },
                                alwaysShowLabel = false,
                            )
                        }
                    }
                }
            },
        ) { pad -> content(route, pad) }

        if (showOverflow) {
            ModalBottomSheet(
                onDismissRequest = { showOverflow = false },
                sheetState = sheetState,
                containerColor = MaterialTheme.colorScheme.surface,
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .navigationBarsPadding()
                        .padding(bottom = UnderstoryTheme.spacing.md),
                ) {
                    SuiteSectionHeader(stringResource(R.string.nav_more_header))
                    overflow.forEach { tab ->
                        SuiteListRow(
                            headline = tab.title,
                            leading = {
                                Icon(
                                    tab.icon,
                                    contentDescription = tab.contentDescription,
                                    tint = if (route == tab.route) {
                                        MaterialTheme.colorScheme.primary
                                    } else {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    },
                                )
                            },
                            onClick = {
                                showOverflow = false
                                nav.selectTab(tab.route)
                            },
                        )
                    }
                }
            }
        }
    }
}

/**
 * Material3's spec ceiling for a bottom navigation bar. Beyond this the bar stops being
 * navigation and starts being a row of unreadable slivers — see the class KDoc.
 */
const val MAX_PRIMARY_TABS = 5
