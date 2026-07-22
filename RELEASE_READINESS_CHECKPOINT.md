# Release-readiness checkpoint

## Identity

- Repository: `Zheke32174/understory-firewall`
- Checkpoint branch: `security/public-signing-containment-v1`
- Reviewed default head: `141c10b191b74031f890c35aa0a5bf17dd6245ec`
- Validated implementation head: `c74c578c773a3a44a02308d63de93d54b889f3ef`
- Coordination: `Zheke32174/understory-common#3`

## Last completed scope

Public signing identity, APK publication authority, current-tree key exposure,
install-verification claims, vendored trust primitives, security reporting,
licensing presence, Android assembly, and complete unit-test validation.

## Resolved on this draft

- Removed the shared public debug private key from the current tree.
- Removed committed debug-signing configuration and credentials.
- Revoked debug signatures for authorship, sibling identity, and capabilities.
- Replaced automatic mutable latest-release publication with read-only validation.
- Removed tag force-update, release-asset overwrite, and repository-write authority.
- Corrected install-verification, CI-artifact, and public-distribution claims.
- Added deterministic signing and presentation boundary validation.
- Verified the repaired tree assembles and its complete unit-test suite passes.

## Validation receipts

GitHub Actions run `29936261110` passed at exact implementation head
`c74c578c773a3a44a02308d63de93d54b889f3ef`:

- immutable read-only checkout;
- signing and public-presentation boundary validation;
- Android SDK provisioning;
- local debug APK assembly without a committed suite signing key;
- complete Gradle unit-test execution;
- durable unit-test receipt upload.

## Changed conclusion

The current source, presentation, build, and test boundary is green. The
repository is not publishable because historical artifacts, release governance,
licensing, signing custody, administrative settings, and real-device lifecycle
receipts remain unresolved.

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

Review the coordinated sibling receipts, select a source license, and decide the
disposition of historical public debug releases before designing any authenticated
immutable candidate. Preserve a separate later gate for disposable-device
Companion/Standalone conflict, rollback, update, and uninstall validation.
