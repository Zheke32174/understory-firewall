package com.ant.emichaosbg

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * THE STANDING RULES OF THIS REBUILD, ENFORCED BY A TEST RATHER THAN BY MEMORY.
 *
 * Each of these was violated by the module this one replaces, and each was caught
 * by a human rather than by anything automatic. A rule that lives only in a comment
 * gets refactored away by someone who did not read the comment.
 */
class InvariantsTest {

    private fun sourceRoot(): File =
        listOf(File("src/main/java"), File("app-next/src/main/java"))
            .firstOrNull { it.isDirectory }
            ?: error("could not locate the module source root from ${File(".").absolutePath}")

    private fun kotlinSources(): List<File> =
        sourceRoot().walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    /** Comments legitimately NAME the things this module refuses to use. Strip them. */
    private fun code(f: File): String = f.readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .replace(Regex("(?m)//.*$"), "")

    // ------------------------------------------------------------------ the invariant

    /**
     * NO DEPENDENCE ON ANY APP THIS SUITE REPLACES.
     *
     * Yojimbo IS Shizuku and Dhizuku; an app in this suite that imports their client
     * libraries, ships their provider, or tells the user to "install X first" has not
     * replaced them. The previous Chaos Orb module compiled against BOTH client
     * libraries and shipped `rikka.shizuku.ShizukuProvider` inside its own APK.
     */
    @Test
    fun `no source references Shizuku or Dhizuku`() {
        val banned = listOf("rikka.shizuku", "dev.rikka", "Shizuku", "Dhizuku", "dhizuku")
        val offenders = kotlinSources().mapNotNull { f ->
            val body = code(f)
            val hits = banned.filter { body.contains(it) }
            if (hits.isEmpty()) null else "${f.name}: $hits"
        }
        assertTrue(
            "Chaos Orb must not reference the apps this suite replaces — found: $offenders",
            offenders.isEmpty(),
        )
    }

    /**
     * FULLY NATIVE. No WebView, no JS bridge, no page. The half-finished web->native
     * migration is the diagnosed root cause of "menu half non existent, security
     * scanners not working".
     */
    @Test
    fun `no source touches WebView or a JavaScript bridge`() {
        val banned = listOf(
            "android.webkit", "WebView", "JavascriptInterface",
            "addJavascriptInterface", "evaluateJavascript", "loadUrl",
        )
        val offenders = kotlinSources().mapNotNull { f ->
            val body = code(f)
            val hits = banned.filter { body.contains(it) }
            if (hits.isEmpty()) null else "${f.name}: $hits"
        }
        assertTrue("this module must be fully native — found: $offenders", offenders.isEmpty())
    }

    /** And no page to load even if something tried. */
    @Test
    fun `the module ships no HTML asset`() {
        val assets = listOf(File("src/main/assets"), File("app-next/src/main/assets"))
            .firstOrNull { it.isDirectory }
        val html = assets?.walkTopDown()?.filter { it.extension.lowercase() in setOf("html", "htm") }
            ?.toList() ?: emptyList()
        assertTrue("no HTML may ship in this module — found: ${html.map { it.name }}", html.isEmpty())
    }

    // ------------------------------------------------------------------ the vault

    /**
     * THE VAULT CANNOT BE EMPTIED. Not by a "guarded" helper, not by an internal
     * convenience method someone adds later for testing. Rotation is the single
     * exception and it KEEPS the rotated segment.
     */
    @Test
    fun `SecureLog exposes no way to delete, clear or truncate the log`() {
        val banned = listOf(
            "delete", "clear", "wipe", "erase", "purge", "reset", "truncate", "drop",
        )
        val offenders = SecureLog::class.java.methods
            .map { it.name }
            .filter { name -> banned.any { name.lowercase().contains(it) } }
        assertTrue(
            "SecureLog must expose no destructive method — found: $offenders. A log the app " +
                "can empty is not evidence.",
            offenders.isEmpty(),
        )
    }

    // ------------------------------------------------------------------ overlay watch

    /**
     * THE OVERLAY DETECTOR NEVER READS SCREEN CONTENT. The platform requires
     * canRetrieveWindowContent="true" for getWindows() to return anything, so the
     * restraint cannot be enforced by the manifest — it is enforced by the code never
     * calling a content API. That makes it exactly the kind of promise that decays
     * silently.
     */
    @Test
    fun `OverlayWatch never calls a screen-content API`() {
        val src = kotlinSources().firstOrNull { it.name == "OverlayWatch.kt" }
            ?: error("OverlayWatch.kt not found")
        val body = code(src)
        val forbidden = listOf(
            "getRootInActiveWindow", "rootInActiveWindow", ".getText(", "getChild(",
            "findAccessibilityNodeInfosByText", "findAccessibilityNodeInfosByViewId",
            "performAction(",
        )
        val used = forbidden.filter { body.contains(it) }
        assertTrue(
            "OverlayWatch must read window METADATA only. Found content API usage: $used.",
            used.isEmpty(),
        )
    }

    // ------------------------------------------------------------------ the cert pin

    /**
     * THE SIGNATURE CHECK IS NOT A PLACEHOLDER. The old build shipped
     * `expectedSignatureHash = ""` against `ok = expected.isBlank() || …`, so the
     * integrity headline said "clean" unconditionally on every build.
     */
    @Test
    fun `the certificate pins are real 64-hex digests`() {
        listOf(SuiteCertPins.DEBUG, SuiteCertPins.RELEASE).forEach {
            assertTrue(
                "a cert pin must be a 64-char lowercase hex digest, not a placeholder — got '$it'",
                Regex("^[a-f0-9]{64}$").matches(it),
            )
        }
    }
}
