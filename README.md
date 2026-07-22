# understory-firewall

> [!CAUTION]
> **PUBLIC DEBUG SIGNING INCIDENT:** the former shared debug private key is
> public. Existing debug APKs and continuous debug releases cannot prove
> authorship and are untrusted development artifacts. Only a future APK signed
> by the externally held release key can be an authenticated Understory
> distribution. Tracking: `Zheke32174/understory-common#3`.

**Understory Net Audit** — an offline egress dashboard for a Tailscale user. In the default Companion mode it observes, explains, and one-tap-routes you to the network controls you already have (tunnel posture, Android's per-app data restrictions, system Private DNS, and which apps hold remote-admin power) — **it never takes the VPN slot and blocks nothing**. Real per-app packet blocking exists only in an opt-in, default-off **Standalone mode** that refuses to start whenever any other VPN is present. DNS hardening is DoT via the OS's own Private DNS; egress canaries prove on the wire what your DNS/exit actually is.

Status: **alpha**.

## Build

Requires JDK 17+ and the Android SDK with platform 35 + build-tools 35.0.0.

```bash
# Copy local.properties.example to local.properties, set sdk.dir
gradle :firewall:assembleDebug
# APK: firewall/build/outputs/apk/debug/firewall-debug.apk
```

CI validates the signing boundary, assembles a local debug APK, and runs unit tests. It does not publish APKs. Debug builds use a developer-local Android debug identity and are not authenticated Understory distributions.

## Provenance & suite

Split 2026-07-02 from `Zheke32174/underward` `android/` (commit `f867493`) into per-app repos.

Part of the **Understory Suite** — rootless, in-bounds, local-first Android security apps. Shared modules are vendored for a self-contained build; their canonical home is [`understory-common`](https://github.com/Zheke32174/understory-common). The `keystore/` directory contains documentation only; signing private keys are forbidden.

## Verify your install

Debug APKs cannot be authenticated as Understory distributions. Their signer is developer-local, and the former shared debug signer is revoked.

For a future authenticated release, verify the APK certificate with `apksigner` and require the release fingerprint recorded in `common-security/.../SuitePins.kt`:

```bash
apksigner verify --print-certs the-downloaded.apk | grep -i 'SHA-256'
```

Expected authenticated release certificate:

`59a3dee7feb8262170e4dcabb3dbe7bc323abe8715ab49f5bed5133046a45c4a`

Certificate verification must be combined with an immutable versioned release, checksum/provenance verification, and the source commit. No such release receipt is claimed by this draft.
