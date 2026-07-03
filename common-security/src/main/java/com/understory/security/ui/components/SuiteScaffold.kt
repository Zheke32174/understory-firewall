package com.understory.security.ui.components

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.understory.security.R
import com.understory.security.SuiteStatusFooter
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * The one screen chrome for the suite: a Material3 [Scaffold] with a
 * [TopAppBar] and the reused [SuiteStatusFooter] bottom bar. Replaces every raw
 * `Surface`/`Column` root (SUITE #9 "no Scaffold/TopAppBar"). Every app's main
 * screen becomes:
 *
 *   SuiteScaffold(title = stringResource(R.string.app_name)) { pad -> … }
 *
 * @param onBack when non-null, a back arrow is shown in the top bar.
 * @param actions trailing top-bar actions (icons); each should be ≥48dp.
 * @param showSuiteFooter set false on screens that shouldn't carry the suite
 *   status footer (e.g. a full-screen fatal or a modal-style sub-screen).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SuiteScaffold(
    title: String,
    modifier: Modifier = Modifier,
    onBack: (() -> Unit)? = null,
    actions: @Composable RowScope.() -> Unit = {},
    showSuiteFooter: Boolean = true,
    content: @Composable (PaddingValues) -> Unit,
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Text(title, style = MaterialTheme.typography.titleLarge)
                },
                navigationIcon = {
                    if (onBack != null) {
                        IconButton(onClick = onBack) {
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
            if (showSuiteFooter) {
                SuiteStatusFooter(
                    Modifier.padding(
                        horizontal = UnderstoryTheme.spacing.md,
                        vertical = UnderstoryTheme.spacing.sm,
                    )
                )
            }
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { pad -> content(pad) }
}
