package com.understory.security

/**
 * Single source of truth for the suite's signing-cert pins (SHA-256 of the
 * signing certificate, lowercase hex, no colons). Every runtime pin check
 * ([Tamper], [SuiteAttestation], [SuiteCapabilityRegistry]) reads
 * [EXPECTED_CERT_SHA256] from here — the digest pair is written once.
 *
 * Two keystores exist:
 *   - DEBUG:   the committed suite debug keystore (`keystore/debug.keystore`).
 *   - RELEASE: the offline release keystore — never in any repo. Location,
 *     rotation, and build wiring: `docs/SIGNING.md`.
 *
 * Variant selection rides this library's `BuildConfig.DEBUG`: app debug
 * builds consume the library's debug variant and release builds its release
 * variant, so the active pin always matches the keystore that signs the
 * surrounding APK.
 *
 * The build-time `verifyCertPin` task greps this file for both named digests
 * and asserts every assembled APK is actually signed by the matching
 * keystore. Keep each digest as a quoted 64-char lowercase-hex literal
 * following its constant name, or that grep breaks.
 */
object SuitePins {

    const val DEBUG_CERT_SHA256 =
        "aba68a81a0d63b5549794e586875a4f04e6dba3a6fe25d363e04eb75f46df69e"

    const val RELEASE_CERT_SHA256 =
        "59a3dee7feb8262170e4dcabb3dbe7bc323abe8715ab49f5bed5133046a45c4a"

    /** The pin gating this build's own cert and every suite sibling's. */
    val EXPECTED_CERT_SHA256: String =
        if (BuildConfig.DEBUG) DEBUG_CERT_SHA256 else RELEASE_CERT_SHA256
}
