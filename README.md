# understory-firewall

**Understory Net Audit** — an offline egress dashboard for a Tailscale user. In the default Companion mode it observes, explains, and one-tap-routes you to the network controls you already have (tunnel posture, Android's per-app data restrictions, system Private DNS, and which apps hold remote-admin power) — **it never takes the VPN slot and blocks nothing**. Real per-app packet blocking exists only in an opt-in, default-off **Standalone mode** that refuses to start whenever any other VPN is present. DNS hardening is DoT via the OS's own Private DNS; egress canaries prove on the wire what your DNS/exit actually is. (No dnscrypt bundling and no overlay routing — both were removed as unshippable; see `docs/design-v2/firewall.md`.)

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

## Verify your install

Before trusting the app, confirm the APK you are about to install (or did install) is signed by the suite key. With Android build-tools on any machine:

```bash
apksigner verify --print-certs the-downloaded.apk | grep -i 'SHA-256'
```

The signer certificate SHA-256 digest must be exactly one of the two suite pins (single source of truth: `common-security/.../SuitePins.kt`):

- **Debug** builds (CI artifacts; committed suite debug keystore): `aba68a81a0d63b5549794e586875a4f04e6dba3a6fe25d363e04eb75f46df69e`
- **Release** builds (offline release keystore): `59a3dee7feb8262170e4dcabb3dbe7bc323abe8715ab49f5bed5133046a45c4a`

Any other digest means the APK was not signed by the suite keys — do not install it. The apps also enforce these pins at runtime (Tamper self-check + SuiteAttestation cross-check of installed siblings), but verifying before install is the stronger position. Signing doctrine: `docs/SIGNING.md` in understory-common.
