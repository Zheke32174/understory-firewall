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
 *
 * BEACON RULE (content honesty, on top of the spoofing defense): a
 * capability may be mapped in [SuiteCapabilityRegistry.KNOWN_PEERS] for a
 * (package, version) pair ONLY if a live peer-invocable code path in that
 * app, at that version, actually delivers the power this enum's KDoc
 * describes to a peer — either (a) a peer-invocable IPC surface
 * (signature-gated ContentProvider / Service / signed Intent target) or
 * (b) a documented Intent hand-off the peer can fire. A power that exists
 * only in-process, only as a dead adapter with no IPC, only behind a
 * vetoed slot, or only on a roadmap does NOT qualify — leave the peer's
 * capability set empty until the surface ships. Names describe the
 * delivered power at its true cadence and mechanism, never an aspiration
 * (no "realtime scanner" name for an on-demand scanner; no "filter" or
 * "orchestrator" name for something that only reads or advises).
 */
enum class SuiteCapability {
    /**
     * Stores the user's master vault and acts as the suite keychain.
     * Provided by passgen. Other apps can request key-derivation services
     * (e.g. derive a per-app key from the master vault under a context).
     */
    IDENTITY_VAULT,

    /**
     * Stores TOTP/HOTP seeds at rest — storage only, no peer-invocable
     * issue-code surface. Provided by aegis at v1. A peer may know aegis
     * holds OTP seeds, but cannot ask it for a live code. Distinct from
     * [OTP_VAULT]: this is the honest v1 beacon (no code-issue IPC ships
     * yet). See BEACON-1 — a storage-only role must not advertise the
     * issue-code power it doesn't deliver.
     */
    OTP_STORE,

    /**
     * Holds TOTP/HOTP seeds AND exposes a peer-invocable surface that
     * issues a current code to a requesting peer. Provided by aegis, but
     * only once a code-issue IPC actually ships (deferred at v1 — aegis
     * currently maps [OTP_STORE] instead). Other apps gate sensitive
     * actions on a just-issued code.
     */
    OTP_VAULT,

    /**
     * Audits network posture — remote-admin-class grants, Private-DNS
     * (DoT) state, and VPN-slot health — and advises. It does NOT
     * intercept packets; the VPN slot is permanently ceded to the
     * incumbent tunnel. Rootless, read/advise only. Provided by firewall.
     */
    NET_POSTURE_AUDIT,

    /**
     * Encrypted file vault for arbitrary user files; accepts a file via
     * the deposit (ACTION_VIEW) Intent target. Provided by vault-folder.
     */
    FILE_VAULT,

    /**
     * Encrypts/decrypts a single file to/from the suite [BackupEnvelope]
     * format, and is a hand-off target for "encrypt this and store it".
     * Provided by backups. This is the honest v1 power. Cross-app
     * orchestration (pulling every peer's vault over IPC) is a separate
     * future capability — see BEACON-1 note: re-add a BACKUP_ORCHESTRATOR
     * value only when the cross-app BackupProvider IPC actually ships.
     */
    BACKUP_ENVELOPE,

    /**
     * On-demand static APK / installed-app auditor: accepts a share/VIEW
     * of an APK and returns advisory findings. No real-time watcher,
     * receiver, or worker — rootless real-time is impossible and never
     * claimed. Provided by antivirus.
     */
    APK_AUDITOR,

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
