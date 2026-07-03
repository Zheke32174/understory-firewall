package com.understory.security.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

/**
 * Semantic-color CompositionLocal. Defaults to the dark holder so a stray read
 * outside [UnderstoryTheme] still yields a usable (dark) value rather than
 * throwing.
 */
val LocalSuiteColors = staticCompositionLocalOf { DarkSemantic }

/**
 * True only inside an [UnderstoryTheme] scope. Lets a shared component that is
 * ALSO callable from a not-yet-migrated app (which still wraps its own
 * `MaterialTheme(darkColorScheme())`) fall back to its exact legacy palette when
 * the design system is not in scope — so token adoption never visually regresses
 * an app before it opts in. Remove the fallback branches once all apps adopt.
 */
val LocalUnderstoryThemeActive = staticCompositionLocalOf { false }

/**
 * One accent seed per app — the suite's ONLY per-app theming freedom, so the
 * seven apps stay visibly a family but each keeps an identity. The hues are
 * dim/desaturated on purpose (the suite's security posture, not a splash of
 * brand color).
 */
enum class UnderstoryAccent(val seed: Color) {
    PASSGEN(Color(0xFF7E9E7E)),
    AEGIS(Color(0xFF8AA3C9)),
    VAULTFOLDER(Color(0xFFB08AC9)),
    BACKUPS(Color(0xFF8AC9B0)),
    BROWSER(Color(0xFFC9B08A)),
    FIREWALL(Color(0xFFC98A8A)),
    ANTIVIRUS(Color(0xFF8AC9C9)),
}

/**
 * The single theme wrapper for every suite app. Replaces the per-Activity
 * inline `MaterialTheme(colorScheme = darkColorScheme())` calls. Wire an app's
 * `setContent` as:
 *
 *   UnderstoryTheme(accent = UnderstoryAccent.PASSGEN) { … }
 *
 * @param dynamicColor OPT-IN, default OFF. Dynamic (wallpaper-derived) color
 *   would let arbitrary hues repaint a "security tool" — a green "safe" chip
 *   could render pink, an honesty smell — so the conservative default keeps the
 *   dim-neutral identity. The plumbing is present for an app that later adds a
 *   user setting. minSdk is 33, so the SDK_INT >= 31 guard is documentation.
 */
@Composable
fun UnderstoryTheme(
    accent: UnderstoryAccent,
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit,
) {
    val ctx = LocalContext.current
    val scheme: ColorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= 31 ->
            if (darkTheme) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        darkTheme -> understoryDarkColors(accent.seed)
        else -> understoryLightColors(accent.seed)
    }
    val semantic = if (darkTheme) DarkSemantic else LightSemantic

    CompositionLocalProvider(
        LocalSuiteColors provides semantic,
        LocalSpacing provides Spacing(),
        LocalUnderstoryThemeActive provides true,
    ) {
        MaterialTheme(
            colorScheme = scheme,
            typography = UnderstoryType,
            shapes = UnderstoryShapes,
            content = content,
        )
    }
}

/**
 * Single accessor an app reads tokens through. Any color you would have written
 * `Color(0xFF…)` for now comes from [colors] (Material role) or [semantic]
 * (warning/success/dim). Spacing/type/shapes likewise route through here so an
 * app never touches a raw `.dp`/`.sp` design literal.
 */
object UnderstoryTheme {
    val colors: ColorScheme
        @Composable @ReadOnlyComposable get() = MaterialTheme.colorScheme
    val semantic: SuiteSemanticColors
        @Composable @ReadOnlyComposable get() = LocalSuiteColors.current
    val spacing: Spacing
        @Composable @ReadOnlyComposable get() = LocalSpacing.current
    val type: Typography
        @Composable @ReadOnlyComposable get() = MaterialTheme.typography
    val shapes: Shapes
        @Composable @ReadOnlyComposable get() = MaterialTheme.shapes
}
