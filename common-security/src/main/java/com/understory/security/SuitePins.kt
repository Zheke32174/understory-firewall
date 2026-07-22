package com.understory.security

/**
 * Public certificate pins for authenticated Understory distributions.
 *
 * The former shared debug key became public and cannot establish identity.
 * Debug builds remain usable for local development but have no suite trust pin.
 *
 * The release private key remains external to source and ordinary CI. Only its
 * certificate digest is public.
 */
object SuitePins {
    const val RELEASE_CERT_SHA256 =
        "59a3dee7feb8262170e4dcabb3dbe7bc323abe8715ab49f5bed5133046a45c4a"

    const val DEBUG_IDENTITY_TRUSTED = false

    /** Certificate accepted for authenticated release variants only. */
    const val EXPECTED_RELEASE_CERT_SHA256 = RELEASE_CERT_SHA256
}
