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
 * One accent per app — the suite's ONLY per-app theming freedom, so the apps stay visibly a
 * family but each keeps a distinct identity.
 *
 * ## Two seeds, not one
 *
 * [seedDark] is read on the Ink neutrals; [seedLight] on the Paper ones. A single seed cannot
 * serve both, and pretending otherwise was a real defect: [understoryLightColors] used to take
 * the dark seed and pair it with `onPrimary = Paper50`, i.e. **white text on a bright accent**,
 * which measures 1.50–2.85:1. Every filled button in light mode was unreadable. Each
 * [seedLight] below is darkened until white-on-accent clears 5.9:1.
 *
 * ## Hue budget
 *
 * The semantics own the warm arc — Danger ~1°, Caution ~36°, Success ~122°. Brand accents
 * therefore live in 150–330° and stay at least 38° from each other *and* from every semantic
 * hue. 38° is the ceiling once those three are excluded; anything tighter and two apps start
 * reading as the same app under a colour-shifted screen.
 *
 * Two hues were given up to satisfy that, deliberately and against first instinct:
 *
 *  - **Godwall loses amber.** `#E7B24A` sat 3.7° from the semantic Caution hue — a firewall
 *    whose brand colour is its own alarm colour. When every chrome element is the shade that
 *    means "warning", nothing on the screen can mean warning any more.
 *  - **Masamune loses forge orange.** `#FF7A45` sat 15.9° from Danger and 22.6° from Godwall.
 *
 * Colour is also not the only carrier: each app owns a motif (Gate / Course / Slash / Fold /
 * Emission) so identity survives greyscale and colour-vision differences.
 */
enum class UnderstoryAccent(val seedDark: Color, val seedLight: Color) {
    PASSGEN(Color(0xFF6FB98A), Color(0xFF2F6B4A)),      // canopy green
    AEGIS(Color(0xFF8E9BEA), Color(0xFF3A46A8)),        // indigo (OTP, cool-lock family)
    VAULTFOLDER(Color(0xFF9A8BEA), Color(0xFF4A3AA8)),  // locked violet
    BACKUPS(Color(0xFF45C7A6), Color(0xFF0A6B55)),      // mint / teal-green
    BROWSER(Color(0xFF5CC8E8), Color(0xFF0B6389)),      // sky cyan
    FIREWALL(Color(0xFFE7B24A), Color(0xFF7A5B0A)),     // signal amber (legacy; see GODWALL)
    ANTIVIRUS(Color(0xFFEC6B5E), Color(0xFFA32C1E)),    // alert coral
    MANAGER(Color(0xFF2FD3C3), Color(0xFF0A6B62)),      // electric teal (legacy; see YOJIMBO)

    // ---- The named five: the Aurora ring. ----
    //
    // Yojimbo and Genji BOTH shipped as MANAGER, so on device they were the same app in two
    // icons — the reported "make menu appearances unique and matching" failure. Matching comes
    // from the shared neutrals, type scale, spacing and chrome (SuiteNavShell); unique comes
    // from the accent and the motif.
    //
    // Contrast figures are white-on-accent for seedLight, accent-on-Ink900 for seedDark.

    /** Gate. *A wall is not a warning* — so it does not wear the warning colour. */
    GODWALL(Color(0xFFA3A0F0), Color(0xFF4A43D6)),      // cobalt steel   7.79:1 / 6.56:1

    /** Course. *The retainer holds the keys* — the foundation the others draw from. */
    YOJIMBO(Color(0xFF1FC48F), Color(0xFF0A6B4E)),      // jade           8.24:1 / 6.24:1

    /** Slash. *A cut, not a crash* — hooks and rewrites. */
    GENJI(Color(0xFFD28CF0), Color(0xFF9226C4)),        // arc violet     7.71:1 / 6.10:1

    /** Fold. *The hottest part of the flame is not orange.* */
    MASAMUNE(Color(0xFFF27ACA), Color(0xFFB22078)),     // quench rose    7.41:1 / 5.97:1

    /** Emission. *Something is always emitting.* */
    CHAOS_ORB(Color(0xFF3FB5F5), Color(0xFF0B639C)),    // ion cyan       8.05:1 / 6.14:1
    ;

    /**
     * Back-compat alias. Call sites that predate the light-mode fix read `accent.seed` and
     * meant the dark one, which was the only one that existed.
     */
    val seed: Color get() = seedDark
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
        darkTheme -> understoryDarkColors(accent.seedDark)
        else -> understoryLightColors(accent.seedLight)
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
