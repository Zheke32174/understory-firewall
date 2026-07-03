package com.understory.security

import android.content.Context
import android.content.pm.PackageManager
import java.security.MessageDigest

/**
 * Cross-app attestation for the suite.
 *
 * Each app already pins its own signing cert via [Tamper.signatureMatches].
 * SuiteAttestation extends this to siblings: if a sibling app from the same
 * suite is installed, we verify ITS cert too. If a sibling exists but its
 * cert doesn't match the suite pin, the app refuses to function — the
 * sibling has been repackaged and we don't trust the suite anymore.
 *
 * This is genuinely additive: each app works fine standalone (no sibling
 * required). When siblings ARE installed they form a mutual-verification
 * mesh, and a single compromised sibling drags down every other suite app
 * on the device.
 *
 * Properties:
 *   - Rootless. Uses public PackageManager APIs.
 *   - In-bounds. Each app declares siblings in its <queries> block (no
 *     QUERY_ALL_PACKAGES needed).
 *   - Optional. Missing siblings are not a defense failure — they just
 *     aren't checked.
 *   - Suite-symmetric. Every app verifies every other app it knows about.
 */
object SuiteAttestation {

    /**
     * The suite's signing cert digest. Same value as [Tamper.EXPECTED_CERT_SHA256]
     * (intentional duplication — keeping these in sync is what `verifyCertPin`
     * checks at build time across every app).
     */
    private const val EXPECTED_SUITE_CERT_SHA256 =
        "aba68a81a0d63b5549794e586875a4f04e6dba3a6fe25d363e04eb75f46df69e"

    /**
     * Known suite member package names. Add new apps here as they ship.
     * Each app calling [verify] checks every OTHER app in this list — its
     * own package is excluded automatically (no point self-checking; that's
     * Tamper's job).
     */
    private val SUITE_PACKAGES = listOf(
        "com.understory.passgen",
        "com.understory.aegis",
        "com.understory.firewall",
        "com.understory.backups",
        "com.understory.browser",
        "com.understory.antivirus",
        "com.understory.vaultfolder",
    )

    data class Verdict(
        val installedSiblings: List<String>,
        val tamperedSiblings: List<String>,
    ) {
        /** Refuse to run when any sibling is installed but its cert is wrong. */
        val hardFail: Boolean
            get() = tamperedSiblings.isNotEmpty()
    }

    /**
     * Inspect every sibling package. Returns a verdict — caller checks
     * [Verdict.hardFail] and aborts if true.
     */
    fun verify(ctx: Context): Verdict {
        val pm = ctx.packageManager
        val ourPackage = ctx.packageName
        val installed = mutableListOf<String>()
        val tampered = mutableListOf<String>()

        for (sibling in SUITE_PACKAGES) {
            if (sibling == ourPackage) continue
            val info = try {
                pm.getPackageInfo(sibling, PackageManager.GET_SIGNING_CERTIFICATES)
            } catch (_: PackageManager.NameNotFoundException) {
                continue  // Not installed — not a defense failure.
            } catch (_: Throwable) {
                continue  // Visibility/policy error — not our problem to fix here.
            }

            installed += sibling

            val signingInfo = info.signingInfo
            if (signingInfo == null) {
                tampered += sibling
                continue
            }
            // Use apkContentsSigners only — same logic as Tamper.kt.
            // signingCertificateHistory would accept rotated-out certs.
            val sigs = signingInfo.apkContentsSigners
            if (sigs == null) {
                tampered += sibling
                continue
            }
            val matches = sigs.any { sig ->
                val digest = MessageDigest.getInstance("SHA-256")
                    .digest(sig.toByteArray())
                    .joinToString("") { "%02x".format(it) }
                digest.equals(EXPECTED_SUITE_CERT_SHA256, ignoreCase = true)
            }
            if (!matches) tampered += sibling
        }

        return Verdict(installed, tampered)
    }
}
