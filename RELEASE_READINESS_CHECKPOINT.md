# Release-readiness checkpoint

## Identity

- Repository: `Zheke32174/understory-firewall`
- Checkpoint branch: `security/public-signing-containment-v1`
- Reviewed default head: `141c10b191b74031f890c35aa0a5bf17dd6245ec`
- Coordination: `Zheke32174/understory-common#3`

## Last completed scope

Public signing identity, APK publication authority, current-tree key exposure,
install-verification claims, vendored trust primitives, security reporting,
licensing presence, and Android build/test validation.

## Resolved on this draft

- Removed the shared public debug private key from the current tree.
- Removed committed debug-signing configuration and credentials.
- Revoked debug signatures for authorship, sibling identity, and capabilities.
- Replaced automatic mutable latest-release publication with read-only validation.
- Removed tag force-update, release-asset overwrite, and repository-write authority.
- Corrected install-verification, CI-artifact, and public-distribution claims.
- Added deterministic signing and presentation boundary validation.

## Validation receipts

Pending exact-head GitHub Actions validation.

## Open blockers

- The key remains reachable in public history and prior artifacts/releases.
- Existing movable tags and release assets need an explicit steward disposition.
- No independently verified signed release candidate exists.
- No immutable versioned publication workflow is approved.
- The repository has no explicit license; no license was invented.
- Offline release-key custody remains unverified.
- Branch rules, secret scanning, push protection, private vulnerability reporting,
  and immutable-release settings need administrative verification.
- Real-device Companion/Standalone VPN-conflict, rollback, and uninstall receipts
  remain required before release.

## Reconsideration triggers

New commit, changed CI, newly discovered key material, changed release asset,
license decision, signing rotation, changed public claim, new device fixture,
changed repository visibility, or explicit steward request.

## Next action

Obtain exact-head policy/build/test receipts, then decide historical debug-release
and tag disposition before designing any authenticated immutable candidate.
