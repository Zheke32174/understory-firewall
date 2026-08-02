package com.ant.emichaosbg.ui

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Chaos Orb's local copy of the suite design system.
 *
 * WHY A COPY. `:common-security` (SuiteScaffold, SuiteCard, UnderstoryTheme) lives
 * in the OUTER Gradle build. Chaos Orb is a separate NESTED build with its own
 * settings.gradle.kts, so that module is not on this classpath — there is nothing
 * to reuse here, only something to match. The values below are the suite's
 * "forest floor" neutrals and the CHAOS_ORB accent seed (ion cyan) copied
 * verbatim from `common-security/.../theme/Color.kt` and `Theme.kt`, so the app
 * reads as a sibling rather than a stranger.
 */

// --- neutrals: green-biased near-black, laddered ---------------------------------
private val Ink900 = Color(0xFF0E1512)   // background — forest floor
private val Ink800 = Color(0xFF151E19)   // surface
private val Ink700 = Color(0xFF1C2721)   // surfaceVariant / card
private val Ink600 = Color(0xFF2A3A32)   // outline
private val Fog500 = Color(0xFF7E9084)   // dim labels
private val Fog300 = Color(0xFF9EB2A7)   // secondary text
private val Fog100 = Color(0xFFE7F0EA)   // primary text

// --- semantic --------------------------------------------------------------------
private val Danger = Color(0xFFEF5350)
private val Caution = Color(0xFFFFB74D)
private val Success = Color(0xFF81C784)

/** The suite's CHAOS_ORB seed: ion cyan — emission, the loudest thing in the suite. */
private val ChaosOrbSeed = Color(0xFF4FE0FF)

@Immutable
data class SemanticColors(
    val danger: Color = Danger,
    val caution: Color = Caution,
    val success: Color = Success,
    val dim: Color = Fog500,
)

@Immutable
data class Spacing(
    val xs: Dp = 4.dp,
    val sm: Dp = 8.dp,
    val md: Dp = 12.dp,
    val lg: Dp = 16.dp,
    val xl: Dp = 24.dp,
)

val LocalSemantic = staticCompositionLocalOf { SemanticColors() }
val LocalSpacing = staticCompositionLocalOf { Spacing() }

private val OrbShapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

private val OrbTypography = Typography().let { base ->
    base.copy(
        titleLarge = base.titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = base.titleMedium.copy(fontWeight = FontWeight.SemiBold),
        labelSmall = base.labelSmall.copy(
            fontFamily = FontFamily.Monospace, letterSpacing = 0.sp,
        ),
        bodySmall = base.bodySmall.copy(lineHeight = 18.sp),
    )
}

private val OrbColors = darkColorScheme(
    primary = ChaosOrbSeed,
    onPrimary = Ink900,
    primaryContainer = ChaosOrbSeed.copy(alpha = 0.16f).compositeOver(Ink800),
    onPrimaryContainer = Fog100,
    secondary = Fog300,
    onSecondary = Ink900,
    background = Ink900,
    onBackground = Fog100,
    surface = Ink800,
    onSurface = Fog100,
    surfaceVariant = Ink700,
    onSurfaceVariant = Fog300,
    outline = Ink600,
    outlineVariant = Ink700,
    error = Danger,
    onError = Ink900,
    errorContainer = Danger.copy(alpha = 0.18f).compositeOver(Ink800),
    onErrorContainer = Fog100,
)

object OrbTheme {
    val semantic: SemanticColors
        @Composable get() = LocalSemantic.current
    val spacing: Spacing
        @Composable get() = LocalSpacing.current
}

@Composable
fun ChaosOrbTheme(content: @Composable () -> Unit) {
    androidx.compose.runtime.CompositionLocalProvider(
        LocalSemantic provides SemanticColors(),
        LocalSpacing provides Spacing(),
    ) {
        MaterialTheme(
            colorScheme = OrbColors,
            shapes = OrbShapes,
            typography = OrbTypography,
            content = content,
        )
    }
}
