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
 * apps stay visibly a family but each keeps a distinct identity. These are the
 * "Aurora" signature hues: one saturated colour per app, read against the
 * forest-floor dark neutrals (see [understoryDarkColors]). Secret-bearing
 * surfaces still render muted (never a bright value) — the accent is chrome, not
 * the vault. Manager/vault/aegis lean cool (control + lock); firewall/antivirus
 * lean warm (caution + alert), matching each app's semantic weight.
 */
enum class UnderstoryAccent(val seed: Color) {
    PASSGEN(Color(0xFF6FB98A)),      // canopy green
    AEGIS(Color(0xFF8E9BEA)),        // indigo (OTP, cool-lock family)
    VAULTFOLDER(Color(0xFF9A8BEA)),  // locked violet
    BACKUPS(Color(0xFF45C7A6)),      // mint / teal-green
    BROWSER(Color(0xFF5CC8E8)),      // sky cyan
    FIREWALL(Color(0xFFE7B24A)),     // signal amber
    ANTIVIRUS(Color(0xFFEC6B5E)),    // alert coral
    MANAGER(Color(0xFF2FD3C3)),      // electric teal — control-plane authority
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
