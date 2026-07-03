# understory-firewall

Outbound-network gate via the VPN slot: per-app blocklist, DNS provider control (dnscrypt-proxy bundling), drop stats, overlay routing. Combined firewall+VPN because Android has one VPN slot.

Status: **alpha** (functional; working the release-blockers list in understory-common).

## Build

Requires JDK 17+ and the Android SDK with platform 35 + build-tools 35.0.0.

```bash
# Copy local.properties.example to local.properties, set sdk.dir
gradle :firewall:assembleDebug
# APK: firewall/build/outputs/apk/debug/firewall-debug.apk
```

CI (GitHub Actions) builds the debug APK + runs unit tests on every push; the APK is attached as a workflow artifact. Debug builds are signed with the committed suite debug keystore so the signing-cert digest matches the suite pin (Tamper.EXPECTED_CERT_SHA256) — installs update-in-place over other suite-pin builds.

## Provenance & suite

Split 2026-07-02 from `Zheke32174/underward` `android/` (commit `f867493`) into per-app repos — one repo per suite app.

Part of the **Understory Suite** — rootless, in-bounds, local-first Android security apps (design constraints: no root, no Shizuku, public APIs only, zero network unless explicitly opted in).

Shared modules vendored here for a self-contained build: `common-security/` (+ `common-backup/`, `overlay-*/` where used) and `keystore/` (pinned suite debug keystore — cert digest is the Tamper/SuiteAttestation pin). **Do not edit shared modules in this repo.** Their canonical home is [`understory-common`](https://github.com/Zheke32174/understory-common); propagate changes with its `tools/sync-common.sh`.

Suite-level docs (SUITE_DESIGN, SUITE_ROADMAP, RELEASE_BLOCKERS, SAMSUNG_QUIRKS, BlackArch defense matrix + runbooks) live in `understory-common`.
