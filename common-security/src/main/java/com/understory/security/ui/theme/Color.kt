package com.understory.security.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.compositeOver

/**
 * Token palette for the whole suite. Every ad-hoc `Color(0xFF…)` that used to
 * live in an app or in a shared component maps to a Material3 color ROLE below,
 * so an app never references a hex again — it reads
 * `MaterialTheme.colorScheme.X` or `UnderstoryTheme.semantic.X` instead.
 *
 * The base constants are `internal`: apps never see raw hues, only roles. This
 * is what lets the §5.3 `HardcodedColor` gate be absolute outside this package.
 *
 * Contrast ratios (WCAG, against the stated background) are noted where a token
 * is used for text, so the design-review gate (§3 A-4) can verify a new token
 * without re-measuring the existing ones.
 */

// --- Neutrals — "forest floor" dark: a green-biased near-black, laddered.
//     The Aurora accents (UnderstoryAccent) read as a constellation against these.
internal val Ink900 = Color(0xFF0E1512)   // background — forest floor
internal val Ink800 = Color(0xFF151E19)   // surface     (SuiteStatusFooter :81/:97)
internal val Ink700 = Color(0xFF1C2721)   // surfaceVariant / card
internal val Ink600 = Color(0xFF2A3A32)   // outline on dark
internal val Fog500 = Color(0xFF7E9084)   // onSurfaceVariant dim (footer :124); labels only
internal val Fog300 = Color(0xFF9EB2A7)   // secondary text (Diag :73); contrast: 7:1 on Ink900
internal val Fog100 = Color(0xFFE7F0EA)   // primary text (Diag :69/:137); contrast: 16:1 on Ink900

// --- Semantic ---
internal val Danger = Color(0xFFEF5350)    // error (footer :145, Diag ERROR :117); contrast: 4.7:1 on Ink900
internal val Caution = Color(0xFFFFB74D)   // warning (Diag WARN :117); contrast: 10:1 on Ink900
internal val Success = Color(0xFF81C784)   // success (footer MARK :116); contrast: 9:1 on Ink900
internal val SuccessDim = Color(0xFF7E9E7E) // verified-peer green (footer :145); contrast: 5.5:1 on Ink900

// --- Light-theme neutrals ---
internal val Paper50 = Color(0xFFFAFAFA)
internal val Paper100 = Color(0xFFF2F2F2)
internal val Slate900 = Color(0xFF1A1A1A)  // primary text on paper; contrast: 15:1 on Paper50
internal val Slate600 = Color(0xFF5A5A5A)  // secondary text on paper; contrast: 5.9:1 on Paper50
internal val LightOutline = Color(0xFFCFCFCF)

// --- Semantic-extras defaults (see SuiteSemanticColors) ---
// Warm-toned "on" surfaces so warning/success text sits on a dim tinted card.
internal val CautionDeep = Color(0xFF3A2E14)
internal val SuccessDeep = Color(0xFF14301C)

/**
 * Dark scheme — the default, matching today's look EXACTLY so no app visually
 * regresses. Neutrals ladder Ink900 → Ink600; text ladders Fog100 → Fog500.
 * The single knob an app varies is [seed] (its accent).
 */
internal fun understoryDarkColors(seed: Color): ColorScheme = darkColorScheme(
    primary = seed,
    onPrimary = Ink900,
    primaryContainer = seed.copy(alpha = 0.16f).compositeOver(Ink800),
    onPrimaryContainer = Fog100,
    secondary = seed,
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
    errorContainer = Danger.copy(alpha = 0.14f).compositeOver(Ink800),
    onErrorContainer = Fog100,
    scrim = Color(0xCC000000),
)

/**
 * Light scheme — new, but COMPLETE (CD-4: don't ship a half-light theme —
 * either full or opt out via §1.5). Paper neutrals + Slate text.
 */
internal fun understoryLightColors(seed: Color): ColorScheme = lightColorScheme(
    primary = seed,
    onPrimary = Paper50,
    primaryContainer = seed.copy(alpha = 0.18f).compositeOver(Paper100),
    onPrimaryContainer = Slate900,
    secondary = seed,
    onSecondary = Paper50,
    background = Paper50,
    onBackground = Slate900,
    surface = Paper100,
    onSurface = Slate900,
    surfaceVariant = Paper100,
    onSurfaceVariant = Slate600,
    outline = LightOutline,
    outlineVariant = Paper100,
    error = Danger,
    onError = Paper50,
    errorContainer = Danger.copy(alpha = 0.14f).compositeOver(Paper100),
    onErrorContainer = Slate900,
    scrim = Color(0x99000000),
)

/**
 * Material3's [ColorScheme] has no `warning`/`success` role, but the audit
 * needs them (WARN=Caution, verified-peer=SuccessDim). This immutable holder is
 * exposed via [LocalSuiteColors] so `MaterialTheme.colorScheme` stays standard
 * and apps still read semantic colors through one accessor
 * ([com.understory.security.ui.theme.UnderstoryTheme.semantic]).
 */
@Immutable
data class SuiteSemanticColors(
    val warning: Color,
    val onWarning: Color,
    val warningContainer: Color,
    val success: Color,
    val onSuccess: Color,
    val successContainer: Color,
    /** Fog500 — the footer's dim "suite"/"no peers" grey. */
    val dim: Color,
)

internal val DarkSemantic = SuiteSemanticColors(
    warning = Caution,
    onWarning = Ink900,
    warningContainer = Caution.copy(alpha = 0.16f).compositeOver(Ink800),
    success = Success,
    onSuccess = Ink900,
    successContainer = Success.copy(alpha = 0.16f).compositeOver(Ink800),
    dim = Fog500,
)

internal val LightSemantic = SuiteSemanticColors(
    warning = Color(0xFF9A6B00),
    onWarning = Paper50,
    warningContainer = Caution.copy(alpha = 0.22f).compositeOver(Paper100),
    success = Color(0xFF2E7D46),
    onSuccess = Paper50,
    successContainer = Success.copy(alpha = 0.22f).compositeOver(Paper100),
    dim = Slate600,
)
