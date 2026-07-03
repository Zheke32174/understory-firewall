package com.understory.security

/**
 * The capability vocabulary for the Understory suite.
 *
 * Capabilities are the *features other apps offer* — never feature flags
 * for the local app. A capability is added when a suite app gains a new
 * power that other apps can usefully compose against. Removing a value
 * is a breaking change to every consumer; adding one is forward-compatible
 * (consumers that don't know it just ignore it).
 *
 * Adding a capability is a deliberate act:
 *   1. Add the enum entry below.
 *   2. Update [SuiteCapabilityRegistry.KNOWN_PEERS] for every peer that
 *      now provides it, gated on the peer's [providedVersion] field.
 *   3. Update the consumer's UI to react when [has] returns true for it.
 *   4. Document the tier unlock in `android/SUITE_DESIGN.md`.
 *
 * Capability *meaning* is local knowledge: a consumer trusts only its own
 * compiled-in [KNOWN_PEERS] map for the mapping between (peer package,
 * peer version) and capabilities. The peer's content provider only
 * attests "I am package P at version V". A repackaged or impostor peer
 * cannot claim a capability it wasn't shipped with — even if it returns
 * a higher version, the consumer's local map is what's authoritative.
 */
enum class SuiteCapability {
    /**
     * Stores the user's master vault and acts as the suite keychain.
     * Provided by passgen. Other apps can request key-derivation services
     * (e.g. derive a per-app key from the master vault under a context).
     */
    IDENTITY_VAULT,

    /**
     * Stores TOTP/HOTP entries; can issue current codes on request.
     * Provided by aegis. Other apps gate sensitive actions on a
     * just-issued code.
     */
    OTP_VAULT,

    /**
     * System-wide network interception via the VpnService slot. Other
     * apps register filter rules (block/allow per-host, per-app) via
     * a signed Intent. Provided by firewall.
     */
    NETWORK_FILTER,

    /**
     * Encrypted file vault for arbitrary user files. Provided by the
     * future vault-folder app.
     */
    FILE_VAULT,

    /**
     * Cross-app backup orchestration (calls each peer's BackupAdapter,
     * writes the unified [BackupEnvelope]). Provided by the future
     * backups app.
     */
    BACKUP_ORCHESTRATOR,

    /**
     * Real-time scanner for downloaded / opened files. Provided by the
     * future antivirus app.
     */
    REALTIME_SCANNER,

    /**
     * Hardened browser; offers a "open in trusted browser" Intent target
     * other apps prefer over the system default when present. Provided
     * by the future browser app.
     */
    HARDENED_BROWSER,

    /**
     * E2E messenger; offers cross-app message-vault keys for apps that
     * want to securely deliver short notes (e.g. backups → "your backup
     * passphrase, sent to a self-message"). Provided by the future
     * messenger app.
     */
    SECURE_MESSENGER,

    /**
     * Local MDM-style policy enforcement (idle-locks all suite vaults,
     * step-up on untrusted networks). Provided by the future mdm-local
     * app — "policy" without device-admin escalation.
     */
    LOCAL_POLICY,
}

/**
 * Snapshot of an installed peer at a moment in time. The
 * [SuiteCapabilityRegistry] returns one of these per detected peer.
 */
data class PeerInfo(
    val packageName: String,
    /** Version the peer's provider attested to (raw, untranslated). */
    val attestedVersion: Int,
    /**
     * Capabilities the consumer's local KNOWN_PEERS map associates with
     * this (package, version) pair. Empty if the version is unknown
     * (peer is newer than this consumer).
     */
    val capabilities: Set<SuiteCapability>,
    /**
     * True if the peer's APK signing cert matched the suite cert pin.
     * False peers contribute zero capabilities regardless of attested
     * version — defense against repackaged siblings.
     */
    val certVerified: Boolean,
)

/**
 * Suite installation tier. Mirrors the cumulative-emergence ladder
 * documented in `android/SUITE_DESIGN.md`. Apps consult this to decide
 * which entire feature *families* to unlock, in addition to fine-grained
 * [SuiteCapability] checks.
 */
enum class SuiteTier {
    /** Just this app installed (or all peers cert-failed). */
    STANDALONE,

    /** This app + 1 verified peer. Pairwise unlocks active. */
    PAIR,

    /** 3 or 4 verified peers. Suite-wide policies become coherent. */
    TRIPLE,

    /** 5+ verified peers. Mesh / quorum attestation viable. */
    MESH,
}
