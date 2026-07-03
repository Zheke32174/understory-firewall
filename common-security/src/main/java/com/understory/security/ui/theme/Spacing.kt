package com.understory.security.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * 4dp-grid spacing scale, provided through a [staticCompositionLocalOf] so an
 * app reads `UnderstoryTheme.spacing.md` instead of a bare `padding(12.dp)`.
 * Replaces the scattered `padding(6/8/10/16/20.dp)` literals across the suite.
 */
@Immutable
data class Spacing(
    val xs: Dp = 4.dp,
    val sm: Dp = 8.dp,
    val md: Dp = 12.dp,
    val lg: Dp = 16.dp,
    val xl: Dp = 24.dp,
    val xxl: Dp = 32.dp,
)

val LocalSpacing = staticCompositionLocalOf { Spacing() }
