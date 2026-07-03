package com.understory.security

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import java.security.MessageDigest

/**
 * Discovers installed suite peers, validates each via cert-pin, and
 * returns the union of capabilities they offer.
 *
 * Usage from any suite app:
 *
 *     val snap = SuiteCapabilityRegistry.snapshot(context)
 *     if (snap.has(SuiteCapability.OTP_VAULT)) {
 *         // show "require OTP step-up" toggle in our settings
 *     }
 *     when (snap.tier) {
 *         SuiteTier.MESH -> enableQuorumAttestation()
 *         else -> { /* base behaviour */ }
 *     }
 *
 * Registration of new peers: edit [KNOWN_PEERS] only. Each entry maps a
 * package name to a *version → capability set* table — the consumer's
 * authoritative belief about what the peer at that version provides. A
 * peer that returns a version not listed here contributes zero
 * capabilities, even if cert-verified. This is the bedrock defense
 * against capability-spoofing: no peer can self-declare a power its
 * KNOWN_PEERS entry doesn't grant.
 *
 * Refresh model: callers re-invoke [snapshot] from a `PACKAGE_ADDED` /
 * `PACKAGE_REMOVED` BroadcastReceiver to live-update their UI when peers
 * come and go. The query is cheap (~1 PackageManager call + 1
 * ContentResolver query per known peer) so re-running it is fine.
 */
object SuiteCapabilityRegistry {

    /**
     * Same digest as [Tamper.EXPECTED_CERT_SHA256] /
     * [SuiteAttestation.EXPECTED_SUITE_CERT_SHA256]. Build-time
     * `verifyCertPin` keeps these in sync across all three sites.
     */
    private const val EXPECTED_SUITE_CERT_SHA256 =
        "aba68a81a0d63b5549794e586875a4f04e6dba3a6fe25d363e04eb75f46df69e"

    /**
     * The consumer's authoritative belief about each peer:
     *   peer package -> (peer-attested version -> capability set at that version).
     *
     * When a peer ships a new version with new capabilities, ALL consumer
     * apps must update this table to "see" the new powers. That's
     * intentional — a peer cannot grow its own privileges.
     *
     * Unlisted versions (peer is too new, or too old) contribute zero
     * capabilities. The consumer keeps running, just without the peer's
     * uplift.
     */
    private val KNOWN_PEERS: Map<String, Map<Int, Set<SuiteCapability>>> = mapOf(
        "com.understory.passgen" to mapOf(
            1 to setOf(SuiteCapability.IDENTITY_VAULT),
        ),
        "com.understory.aegis" to mapOf(
            1 to setOf(SuiteCapability.OTP_VAULT),
        ),
        "com.understory.firewall" to mapOf(
            1 to setOf(SuiteCapability.NETWORK_FILTER),
        ),
        "com.understory.backups" to mapOf(
            1 to setOf(SuiteCapability.BACKUP_ORCHESTRATOR),
        ),
        "com.understory.browser" to mapOf(
            1 to setOf(SuiteCapability.HARDENED_BROWSER),
        ),
        "com.understory.antivirus" to mapOf(
            1 to setOf(SuiteCapability.REALTIME_SCANNER),
        ),
        "com.understory.vaultfolder" to mapOf(
            1 to setOf(SuiteCapability.FILE_VAULT),
        ),
        // Future apps slot in here. Each new entry needs a same-named
        // ContentProvider in the peer app and a documented tier-unlock
        // entry in SUITE_DESIGN.md.
        // "com.understory.sandbox"     to mapOf(1 to setOf(LOCAL_POLICY)),
    )

    /**
     * The ContentProvider authority pattern every suite app exposes.
     * Authority = `{packageName}.suitecaps`. Single row. Two columns:
     * `version` (int) and `cert_sha256` (string, lowercase hex). The
     * cert_sha256 column is informational — the consumer recomputes from
     * `PackageManager` for the actual security check. It's just there to
     * help diagnose mismatches.
     */
    fun providerAuthorityFor(packageName: String): String =
        "$packageName.suitecaps"

    /** Column names returned by every BaseCapabilityProvider. */
    object Cols {
        const val VERSION = "version"
        const val CERT_SHA256 = "cert_sha256"
    }

    data class Snapshot(
        val ownPackage: String,
        val peers: List<PeerInfo>,
    ) {
        /** All capabilities the union of cert-verified peers contributes. */
        val capabilities: Set<SuiteCapability> by lazy {
            peers.filter { it.certVerified }
                .flatMap { it.capabilities }
                .toSet()
        }

        /** Convenience: does ANY verified peer offer this capability? */
        fun has(c: SuiteCapability): Boolean = c in capabilities

        /** Verified peers offering [c], ordered by package name. */
        fun peersWith(c: SuiteCapability): List<String> =
            peers.filter { it.certVerified && c in it.capabilities }
                .map { it.packageName }
                .sorted()

        /** Cumulative tier including the local app itself. */
        val tier: SuiteTier by lazy {
            val verifiedPeers = peers.count { it.certVerified }
            val total = verifiedPeers + 1  // +1 for the local app
            when {
                total >= 5 -> SuiteTier.MESH
                total >= 3 -> SuiteTier.TRIPLE
                total == 2 -> SuiteTier.PAIR
                else -> SuiteTier.STANDALONE
            }
        }

        /**
         * Peers that returned a version we don't recognize (peer is newer
         * or older than this consumer's KNOWN_PEERS entry). Useful for
         * surfacing "update available" prompts.
         */
        val unknownVersionPeers: List<String> get() =
            peers.filter { it.certVerified && it.capabilities.isEmpty() }
                .map { it.packageName }
    }

    /**
     * Discover and validate every known peer. Excludes the calling app
     * itself.
     *
     * This call is cheap (~milliseconds) so it can run on the main thread
     * during cold start. Cache it in your Activity / ViewModel for the
     * lifetime of the screen, then re-query on `PACKAGE_ADDED` /
     * `PACKAGE_REMOVED` broadcasts.
     */
    fun snapshot(ctx: Context): Snapshot {
        val ourPackage = ctx.packageName
        val pm = ctx.packageManager
        val peerInfos = mutableListOf<PeerInfo>()

        for ((peerPkg, versionTable) in KNOWN_PEERS) {
            if (peerPkg == ourPackage) continue

            // Step 1: peer installed?
            val pkgInfo = try {
                pm.getPackageInfo(peerPkg, PackageManager.GET_SIGNING_CERTIFICATES)
            } catch (_: PackageManager.NameNotFoundException) {
                continue  // Not installed — skip silently, not a defense fail.
            } catch (_: Throwable) {
                continue  // Visibility / policy denied — out of our hands.
            }

            // Step 2: cert pin check. Untrusted peer contributes 0 caps.
            val certVerified = signingCertMatches(pkgInfo.signingInfo)

            // Step 3: ask the peer's provider for its attested version.
            //         Defensively wrapped — a faulty provider must not
            //         take down the registry query.
            val attestedVersion = runCatching {
                queryPeerVersion(ctx, peerPkg)
            }.getOrDefault(-1)

            // Step 4: translate (peer, version) into local capability set.
            //         An unknown version yields the empty set, which is
            //         the safe default — peer is "seen but inert".
            val caps = if (certVerified && attestedVersion >= 0) {
                versionTable[attestedVersion] ?: emptySet()
            } else {
                emptySet()
            }

            peerInfos += PeerInfo(
                packageName = peerPkg,
                attestedVersion = attestedVersion,
                capabilities = caps,
                certVerified = certVerified,
            )
        }

        return Snapshot(ownPackage = ourPackage, peers = peerInfos)
    }

    private fun signingCertMatches(signingInfo: android.content.pm.SigningInfo?): Boolean {
        if (signingInfo == null) return false
        val sigs = signingInfo.apkContentsSigners ?: return false
        return sigs.any { sig ->
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(sig.toByteArray())
                .joinToString("") { "%02x".format(it) }
            digest.equals(EXPECTED_SUITE_CERT_SHA256, ignoreCase = true)
        }
    }

    private fun queryPeerVersion(ctx: Context, peerPkg: String): Int {
        val authority = providerAuthorityFor(peerPkg)
        val uri = Uri.parse("content://$authority/version")
        // Explicit projection: even though every peer is cert-pinned (a
        // hostile cursor here implies the suite cert is already
        // compromised), passing only the column we read bounds a buggy
        // peer's blast radius — we never allocate space for extra cols.
        val projection = arrayOf(Cols.VERSION)
        val cursor = ctx.contentResolver.query(uri, projection, null, null, null)
            ?: return -1
        return cursor.use { c ->
            if (!c.moveToFirst()) return -1
            val idx = c.getColumnIndex(Cols.VERSION)
            if (idx < 0) -1 else c.getInt(idx)
        }
    }
}
