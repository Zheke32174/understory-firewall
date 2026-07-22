package com.understory.security

import android.content.Context
import android.content.pm.PackageManager
import java.security.MessageDigest

/** Release-only sibling certificate attestation. */
object SuiteAttestation {
    private val EXPECTED_SUITE_CERT_SHA256 = SuitePins.EXPECTED_RELEASE_CERT_SHA256

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
        val hardFail: Boolean get() = tamperedSiblings.isNotEmpty()
    }

    fun verify(ctx: Context): Verdict {
        if (BuildConfig.DEBUG) return Verdict(emptyList(), emptyList())
        val installed = mutableListOf<String>()
        val tampered = mutableListOf<String>()
        for (sibling in SUITE_PACKAGES) {
            if (sibling == ctx.packageName) continue
            val info = try {
                ctx.packageManager.getPackageInfo(sibling, PackageManager.GET_SIGNING_CERTIFICATES)
            } catch (_: PackageManager.NameNotFoundException) {
                continue
            } catch (_: Throwable) {
                continue
            }
            installed += sibling
            val signers = info.signingInfo?.apkContentsSigners
            if (signers == null) {
                tampered += sibling
                continue
            }
            val matches = signers.any { signer ->
                val digest = MessageDigest.getInstance("SHA-256")
                    .digest(signer.toByteArray())
                    .joinToString("") { "%02x".format(it) }
                digest.equals(EXPECTED_SUITE_CERT_SHA256, ignoreCase = true)
            }
            if (!matches) tampered += sibling
        }
        return Verdict(installed.sorted(), tampered.sorted())
    }
}
