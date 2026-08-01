package com.ant.emichaosbg

import org.junit.Assert.*
import org.junit.Test

/**
 * THE STANDING RULES, ENFORCED BY A TEST RATHER THAN BY MEMORY.
 *
 * Several properties of this app are not features that can be traded off later — they are
 * commitments, and every one of them was violated at least once during development and caught
 * by a human rather than by anything automatic. A rule that lives only in a comment gets
 * refactored away by someone who did not read the comment. These assert the rules directly.
 *
 * They use reflection rather than behaviour because most of these classes need an Android
 * Context and cannot be constructed on the JVM. That is fine: the property being asserted is
 * about the SHAPE of the API — what it is possible to call — which reflection answers exactly.
 */
class InvariantsTest {

    /**
     * THE VAULT CANNOT BE EMPTIED. Not by the page, not by a "guarded" native helper, not by
     * an internal convenience method someone adds later for testing.
     *
     * A log the compromised compartment can erase is not evidence. The WebView is the largest
     * attack surface this app has, and the first thing worth doing after getting a foothold
     * there is deleting the record of how you arrived. Rotation is the single exception and it
     * is native-side, size-driven, and KEEPS the rotated segment.
     */
    @Test
    fun `SecureLog exposes no way to delete, clear or truncate the log`() {
        val banned = listOf("delete", "clear", "wipe", "erase", "purge", "reset", "truncate", "drop")
        val offenders = SecureLog::class.java.methods
            .map { it.name }
            .filter { name -> banned.any { name.lowercase().contains(it) } }
        assertTrue(
            "SecureLog must expose no destructive method — found: $offenders. " +
            "A log the app can empty is not evidence. If you are adding rotation, it must " +
            "keep the rotated segment, as rotateIfNeeded() does.",
            offenders.isEmpty()
        )
    }

    /** The page-facing bridge is the compartment that must never be able to erase anything. */
    @Test
    fun `VaultBridge exposes no destructive method to the WebView`() {
        val banned = listOf("delete", "clear", "wipe", "erase", "purge", "reset", "truncate", "drop")
        val offenders = VaultBridge::class.java.methods
            .map { it.name }
            .filter { name -> banned.any { name.lowercase().contains(it) } }
        assertTrue(
            "VaultBridge is reachable from the WebView compartment and must be append/read " +
            "only — found: $offenders",
            offenders.isEmpty()
        )
    }

    /**
     * Everything the bridge DOES expose is reachable by anything running in the page. Pinning
     * the exact set means adding a new one is a deliberate act that shows up in a diff, rather
     * than something that slips in because a class gained a public method.
     */
    @Test
    fun `VaultBridge exposes exactly the intended methods to the page`() {
        val declared = VaultBridge::class.java.declaredMethods
            .filter { java.lang.reflect.Modifier.isPublic(it.modifiers) }
            .map { it.name }.toSortedSet()
        assertEquals(
            "the page-facing vault API changed — this set is deliberate, widen it only on purpose",
            sortedSetOf("append", "count", "exportCsv", "exportJson", "read", "verify"),
            declared
        )
    }

    /**
     * THE OVERLAY DETECTOR NEVER READS SCREEN CONTENT.
     *
     * This is the entire basis on which an accessibility service was added to a
     * counter-surveillance app. The platform requires canRetrieveWindowContent="true" for
     * getWindows() to return anything, so the restraint cannot be enforced by the manifest —
     * it is enforced by the code never calling a content API. That makes it exactly the kind
     * of promise that decays silently, so it is asserted here against the compiled class.
     */
    @Test
    fun `OverlayWatch never calls a screen-content API`() {
        val src = java.io.File(
            "src/main/java/com/ant/emichaosbg/OverlayWatch.kt"
        ).takeIf { it.exists() }
            ?: java.io.File("app/src/main/java/com/ant/emichaosbg/OverlayWatch.kt")
        assertTrue("OverlayWatch.kt not found for inspection at ${src.absolutePath}", src.exists())

        val body = src.readText()
            // Ignore the KDoc/comments, which legitimately NAME these APIs to say it avoids them.
            .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
            .replace(Regex("(?m)//.*$"), "")

        val forbidden = listOf(
            "getRootInActiveWindow", "rootInActiveWindow",
            ".getText(", "getChild(", "findAccessibilityNodeInfosByText",
            "findAccessibilityNodeInfosByViewId", "performAction("
        )
        val used = forbidden.filter { body.contains(it) }
        assertTrue(
            "OverlayWatch must read window METADATA only. Found content API usage: $used. " +
            "The whole justification for this service is that it cannot read your screen; " +
            "if it needs to, that decision belongs to the user, not to a refactor.",
            used.isEmpty()
        )
    }

    /**
     * THE DOM HAMMER'S LOCAL CHANNEL IS CAPPED. This is the promise that the disruptor can be
     * driven to capacity globally without crippling the touchscreen locally. The ceiling lives
     * in the page, so it is asserted against the page source.
     *
     * 40% leaves the main thread the clear majority of its time at every severity and overdrive
     * setting. Earlier values of 52% and 70% made the app unusable and had to be reported by a
     * human, twice.
     */
    @Test
    fun `the DOM hammer's LOCAL main-thread ceiling stays bounded`() {
        val page = java.io.File("src/main/assets/index.html").takeIf { it.exists() }
            ?: java.io.File("app/src/main/assets/index.html")
        assertTrue("index.html not found at ${page.absolutePath}", page.exists())
        val text = page.readText()

        val m = Regex("""LOCAL_MAX_DUTY\s*=\s*([0-9.]+)""").find(text)
        assertNotNull("LOCAL_MAX_DUTY must exist — it is the local-usability guarantee", m)
        val ceiling = m!!.groupValues[1].toDouble()
        assertTrue(
            "LOCAL_MAX_DUTY is $ceiling — above 0.45 the UI stops being reliably touchable, " +
            "which is the exact failure that had to be reported from a device twice",
            ceiling <= 0.45
        )
        assertTrue("LOCAL_MAX_DUTY is $ceiling — below 0.15 the local effect is imperceptible",
            ceiling >= 0.15)

        // The global channel must NOT be governed by that ceiling: it runs on the audio thread
        // and is where the chaos actually lives.
        //
        // Comments are stripped before this check. The first version of it matched the DESIGN
        // COMMENT that legitimately names both audioTick and LOCAL_MAX_DUTY while explaining
        // that they are separate — a test that fails on its own documentation is testing prose,
        // not behaviour, which is precisely the defect class this file exists to prevent.
        val code = text
            .replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
            .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
            .replace(Regex("(?m)^\\s*//.*$"), "")
        val tick = Regex("""audioTick\s*:\s*function[\s\S]*?\n\s{4}\},""").find(code)
        assertNotNull("audioTick must exist — it IS the global channel", tick)
        assertFalse(
            "audioTick (the GLOBAL channel) must not consult the LOCAL ceiling: it runs on the " +
            "audio thread, cannot stall the UI, and is where the chaos is meant to live",
            tick!!.value.contains("LOCAL_MAX_DUTY")
        )
        assertFalse(
            "audioTick must not yield to touch — only the LOCAL/DOM half does",
            tick.value.contains("interactUntil")
        )
    }

    /**
     * The interaction yield is what makes a finger drag win against the hammer. Without it the
     * page measured perfectly and could not be scrolled.
     */
    @Test
    fun `the DOM hammer yields the main thread to touch`() {
        val page = java.io.File("src/main/assets/index.html").takeIf { it.exists() }
            ?: java.io.File("app/src/main/assets/index.html")
        val text = page.readText()
        assertTrue("the hammer must track interaction to yield to it",
            text.contains("interactUntil"))
        assertTrue("touch listeners must be passive so registering them cannot delay a gesture",
            Regex("""passive\s*:\s*true""").containsMatchIn(text))
        assertTrue("the burst loop must skip work while the user is interacting",
            Regex("""interacting\s*=\s*perfNow\(\)\s*<\s*interactUntil""").containsMatchIn(text))
    }
}
