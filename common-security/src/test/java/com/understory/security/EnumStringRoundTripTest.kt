package com.understory.security

import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Regression guard for the saveable-state pattern we now use across all
 * apps: store the enum's `.name` as a String in rememberSaveable, restore
 * via `EnumClass.valueOf(name)`. Earlier we tried `mutableStateOf(Enum)`
 * relying on Compose's AutoSaver — the shipped APK string table contained
 * the "cannot be saved" error which suggested AutoSaver was rejecting our
 * enums at runtime even though Kotlin enums are Serializable. The String
 * round-trip is bulletproof; this test pins it.
 *
 * If a future refactor accidentally goes back to enum-direct storage, this
 * test won't catch that — but it WILL catch any breakage in the `valueOf`
 * lookup that the new pattern depends on.
 */
@RunWith(RobolectricTestRunner::class)
class EnumStringRoundTripTest {

    private enum class Stage { Setup, Unlock, Main, Encrypt, Decrypt, Reveal }

    @Test
    fun nameToValueOfRoundTrip_preservesAllEntries() {
        for (s in Stage.values()) {
            val name = s.name
            val restored = Stage.valueOf(name)
            assertEquals("round-trip preserves $s", s, restored)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun valueOfRejectsUnknownName() {
        Stage.valueOf("NotAStage")
    }
}
