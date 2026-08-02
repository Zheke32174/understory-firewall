package com.ant.emichaosbg

/**
 * The suite's signing-certificate pins — SHA-256 of the signing certificate,
 * lowercase hex, no colons.
 *
 * These are the SAME two digests as
 * `common-security/src/main/java/com/understory/security/SuitePins.kt`. They are
 * duplicated rather than imported because Chaos Orb lives in its own nested
 * Gradle build and cannot depend on that module; the values are pinned literals
 * either way, and the build's debug signingConfig points at the same committed
 * `keystore/debug.keystore` the rest of the suite signs with, so a debug APK
 * built here produces [DEBUG] exactly.
 *
 * THIS REPLACES `BuildConfigLike.expectedSignatureHash = ""`, which made the old
 * app's signature check `ok = expected.isBlank() || …` — i.e. unconditionally
 * true on every build that shipped. An integrity headline that always says
 * "clean" is worse than none.
 */
object SuiteCertPins {

    const val DEBUG =
        "aba68a81a0d63b5549794e586875a4f04e6dba3a6fe25d363e04eb75f46df69e"

    const val RELEASE =
        "59a3dee7feb8262170e4dcabb3dbe7bc323abe8715ab49f5bed5133046a45c4a"

    /** The pin that gates THIS build. Variant selection rides BuildConfig.DEBUG. */
    fun expected(isDebugBuild: Boolean): String = if (isDebugBuild) DEBUG else RELEASE
}
