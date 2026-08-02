package com.understory.security.ui.theme

import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow

/**
 * The palette's promises, as arithmetic.
 *
 * Every rule here was written *after* being broken, which is the only reason to spend a test on
 * colour:
 *
 *  - Yojimbo and Genji shipped as the same accent, so the two apps were indistinguishable on
 *    device. Then `masamune-next` independently declared a seed byte-identical to Yojimbo's, in
 *    a different repo, in a hand-written theme mirror. Twice is a pattern, and a pattern needs a
 *    gate rather than another round of care.
 *  - Godwall's amber sat 3.7° from the semantic Caution hue: a firewall whose brand colour was
 *    its own alarm colour, so nothing on its screens could mean "warning" any more.
 *  - Light mode paired the DARK seed with white text and measured as low as 1.50:1, which makes
 *    every filled button in the light theme unreadable.
 *
 * None of those are visible in review. All three are one arithmetic check away.
 */
class AccentPaletteTest {

    /** The five apps this campaign is about. Legacy accents keep their historical hues. */
    private val brand = listOf(
        UnderstoryAccent.GODWALL,
        UnderstoryAccent.YOJIMBO,
        UnderstoryAccent.GENJI,
        UnderstoryAccent.MASAMUNE,
        UnderstoryAccent.CHAOS_ORB,
    )

    // The semantic hues brand accents must stay clear of, so "this means danger" keeps meaning it.
    private val semantics = mapOf(
        "Danger" to Danger,
        "Caution" to Caution,
        "Success" to Success,
    )

    private companion object {
        /** Achievable ceiling once the three semantic hues are excluded from the wheel. */
        const val MIN_HUE_SEPARATION_DEG = 38.0

        /**
         * Genji↔Masamune is the tightest pair and lands on EXACTLY 38.000° by design — but
         * Compose's [Color] stores channels as Float, and 0xCA/255 does not round-trip through
         * float32. The measured separation is therefore 37.9999987334013, i.e. 1.27e-6° short,
         * and a bare `<` fails on quantization rather than on colour.
         *
         * 1e-4° of tolerance covers that with headroom. For scale: one degree of hue is already
         * below the threshold most observers can name, so a ten-thousandth of one cannot hide a
         * real collision — an actual duplicate seed measures 0°, and the nearest genuine pair in
         * this palette is 38°. Nothing lives in between.
         */
        const val HUE_EPSILON_DEG = 1e-4

        /** White-on-accent in light mode. */
        const val MIN_LIGHT_CONTRAST = 5.9

        /** Accent-on-Ink900 in dark mode, for the five this campaign owns. */
        const val MIN_DARK_CONTRAST = 7.0

        /**
         * WCAG AA for normal text, and the floor NO accent may drop below.
         *
         * Two legacy accents belonging to other suite apps sit between this and
         * [MIN_DARK_CONTRAST] — VAULTFOLDER at 6.39:1 and ANTIVIRUS at 6.02:1. They are
         * recorded here rather than silently exempted: both clear AA and neither app is in
         * scope for this campaign, so raising them means changing another app's brand colour,
         * which is a product decision and not a drive-by edit. If either app is rebuilt, it
         * gets the same 7:1 bar as the five.
         */
        const val MIN_DARK_CONTRAST_LEGACY = 4.5
    }

    @Test
    fun `no two of the five share a seed`() {
        val darks = brand.map { it.seedDark }
        val lights = brand.map { it.seedLight }
        assertTrue(
            "two apps share a dark seed — they will read as the same app on device",
            darks.toSet().size == darks.size,
        )
        assertTrue(
            "two apps share a light seed",
            lights.toSet().size == lights.size,
        )
    }

    @Test
    fun `the five are at least 38 degrees apart in hue`() {
        val failures = mutableListOf<String>()
        for (i in brand.indices) {
            for (j in i + 1 until brand.size) {
                val a = brand[i]
                val b = brand[j]
                val d = hueDistance(hue(a.seedDark), hue(b.seedDark))
                if (d < MIN_HUE_SEPARATION_DEG - HUE_EPSILON_DEG) {
                    failures += "${a.name} vs ${b.name}: ${"%.1f".format(d)}°"
                }
            }
        }
        assertTrue("accents too close in hue — $failures", failures.isEmpty())
    }

    @Test
    fun `no brand accent sits on a semantic hue`() {
        val failures = mutableListOf<String>()
        brand.forEach { accent ->
            semantics.forEach { (name, color) ->
                val d = hueDistance(hue(accent.seedDark), hue(color))
                if (d < MIN_HUE_SEPARATION_DEG - HUE_EPSILON_DEG) {
                    failures += "${accent.name} is ${"%.1f".format(d)}° from $name"
                }
            }
        }
        // A brand colour that reads as an alarm colour destroys the alarm, not the brand.
        assertTrue("brand accent collides with a semantic meaning — $failures", failures.isEmpty())
    }

    @Test
    fun `light seeds are readable with white text`() {
        val failures = mutableListOf<String>()
        UnderstoryAccent.entries.forEach { accent ->
            val ratio = contrast(Color.White, accent.seedLight)
            if (ratio < MIN_LIGHT_CONTRAST) {
                failures += "${accent.name}: ${"%.2f".format(ratio)}:1"
            }
        }
        assertTrue(
            "white-on-accent below ${MIN_LIGHT_CONTRAST}:1 in light mode — $failures",
            failures.isEmpty(),
        )
    }

    @Test
    fun `the five clear 7 to 1 on the Ink background`() {
        val failures = brand.mapNotNull { accent ->
            val ratio = contrast(accent.seedDark, Ink900)
            if (ratio < MIN_DARK_CONTRAST) "${accent.name}: ${"%.2f".format(ratio)}:1" else null
        }
        assertTrue(
            "accent-on-Ink900 below ${MIN_DARK_CONTRAST}:1 — $failures",
            failures.isEmpty(),
        )
    }

    @Test
    fun `every accent including the legacy ones clears WCAG AA on Ink`() {
        val failures = UnderstoryAccent.entries.mapNotNull { accent ->
            val ratio = contrast(accent.seedDark, Ink900)
            if (ratio < MIN_DARK_CONTRAST_LEGACY) {
                "${accent.name}: ${"%.2f".format(ratio)}:1"
            } else {
                null
            }
        }
        assertTrue("accent-on-Ink900 below AA — $failures", failures.isEmpty())
    }

    @Test
    fun `the back-compat seed alias still resolves to the dark seed`() {
        // Call sites written before light mode was split read `accent.seed` and meant the dark
        // one. If that alias ever pointed at seedLight, every dark-mode screen would dim at once.
        UnderstoryAccent.entries.forEach {
            assertTrue("${it.name}.seed drifted from seedDark", it.seed == it.seedDark)
        }
    }

    // ---- colour maths (sRGB → relative luminance, and HSL hue) ----

    /** WCAG 2.x relative luminance. */
    private fun luminance(c: Color): Double {
        fun lin(v: Float): Double {
            val d = v.toDouble()
            return if (d <= 0.03928) d / 12.92 else ((d + 0.055) / 1.055).pow(2.4)
        }
        return 0.2126 * lin(c.red) + 0.7152 * lin(c.green) + 0.0722 * lin(c.blue)
    }

    /** WCAG contrast ratio; order-independent. */
    private fun contrast(a: Color, b: Color): Double {
        val la = luminance(a)
        val lb = luminance(b)
        return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
    }

    /** Hue in degrees, 0–360. Grey returns 0, which no accent here is. */
    private fun hue(c: Color): Double {
        val r = c.red.toDouble()
        val g = c.green.toDouble()
        val b = c.blue.toDouble()
        val mx = maxOf(r, g, b)
        val mn = minOf(r, g, b)
        val d = mx - mn
        if (d == 0.0) return 0.0
        val h = when (mx) {
            r -> 60 * (((g - b) / d) % 6)
            g -> 60 * (((b - r) / d) + 2)
            else -> 60 * (((r - g) / d) + 4)
        }
        return (h + 360) % 360
    }

    /** Shortest arc between two hues, so 350° and 10° are 20° apart rather than 340°. */
    private fun hueDistance(a: Double, b: Double): Double {
        val raw = abs(a - b)
        return min(raw, 360 - raw)
    }
}
