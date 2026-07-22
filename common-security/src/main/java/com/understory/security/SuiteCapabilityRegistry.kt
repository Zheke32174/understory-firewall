package com.understory.security

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import java.security.MessageDigest

/** Release-only discovery of cert-verified suite capabilities. */
object SuiteCapabilityRegistry {
    private val EXPECTED_SUITE_CERT_SHA256 = SuitePins.EXPECTED_RELEASE_CERT_SHA256

    private val KNOWN_PEERS: Map<String, Map<Int, Set<SuiteCapability>>> = mapOf(
        "com.understory.passgen" to mapOf(1 to setOf(SuiteCapability.IDENTITY_VAULT)),
        "com.understory.aegis" to mapOf(1 to setOf(SuiteCapability.OTP_STORE)),
        "com.understory.firewall" to mapOf(1 to setOf(SuiteCapability.NET_POSTURE_AUDIT)),
        "com.understory.backups" to mapOf(1 to setOf(SuiteCapability.BACKUP_ENVELOPE)),
        "com.understory.browser" to mapOf(1 to emptySet()),
        "com.understory.antivirus" to mapOf(1 to setOf(SuiteCapability.APK_AUDITOR)),
        "com.understory.vaultfolder" to mapOf(1 to setOf(SuiteCapability.FILE_VAULT)),
    )

    fun providerAuthorityFor(packageName: String): String = "$packageName.suitecaps"

    object Cols {
        const val VERSION = "version"
        const val CERT_SHA256 = "cert_sha256"
    }

    data class Snapshot(
        val ownPackage: String,
        val peers: List<PeerInfo>,
    ) {
        val capabilities: Set<SuiteCapability> by lazy {
            peers.filter(PeerInfo::certVerified).flatMap(PeerInfo::capabilities).toSet()
        }

        fun has(capability: SuiteCapability): Boolean = capability in capabilities

        fun peersWith(capability: SuiteCapability): List<String> = peers
            .filter { it.certVerified && capability in it.capabilities }
            .map(PeerInfo::packageName)
            .sorted()

        val tier: SuiteTier by lazy {
            when (peers.count(PeerInfo::certVerified) + 1) {
                in 5..Int.MAX_VALUE -> SuiteTier.MESH
                in 3..4 -> SuiteTier.TRIPLE
                2 -> SuiteTier.PAIR
                else -> SuiteTier.STANDALONE
            }
        }

        val unknownVersionPeers: List<String>
            get() = peers.filter { it.certVerified && it.capabilities.isEmpty() }
                .map(PeerInfo::packageName)
    }

    fun snapshot(ctx: Context): Snapshot {
        val ownPackage = ctx.packageName
        if (BuildConfig.DEBUG) return Snapshot(ownPackage, emptyList())

        val peers = mutableListOf<PeerInfo>()
        for ((peerPackage, versions) in KNOWN_PEERS) {
            if (peerPackage == ownPackage) continue
            val packageInfo = try {
                ctx.packageManager.getPackageInfo(peerPackage, PackageManager.GET_SIGNING_CERTIFICATES)
            } catch (_: PackageManager.NameNotFoundException) {
                continue
            } catch (_: Throwable) {
                continue
            }
            val verified = signingCertMatches(packageInfo.signingInfo)
            val version = runCatching { queryPeerVersion(ctx, peerPackage) }.getOrDefault(-1)
            val capabilities = if (verified && version >= 0) versions[version] ?: emptySet() else emptySet()
            peers += PeerInfo(peerPackage, version, capabilities, verified)
        }
        return Snapshot(ownPackage, peers.sortedBy(PeerInfo::packageName))
    }

    private fun signingCertMatches(signingInfo: android.content.pm.SigningInfo?): Boolean {
        val signers = signingInfo?.apkContentsSigners ?: return false
        return signers.any { signer ->
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(signer.toByteArray())
                .joinToString("") { "%02x".format(it) }
            digest.equals(EXPECTED_SUITE_CERT_SHA256, ignoreCase = true)
        }
    }

    private fun queryPeerVersion(ctx: Context, peerPackage: String): Int {
        val uri = Uri.parse("content://${providerAuthorityFor(peerPackage)}/version")
        val cursor = ctx.contentResolver.query(uri, arrayOf(Cols.VERSION), null, null, null)
            ?: return -1
        return cursor.use {
            if (!it.moveToFirst()) return -1
            val index = it.getColumnIndex(Cols.VERSION)
            if (index < 0) -1 else it.getInt(index)
        }
    }
}
