# Project debug keystore

`debug.keystore` here is the suite's pinned debug-signing keystore. Wired into
every app module's `signingConfigs.debug` via `android/build.gradle.kts`, so
running `gradle assembleDebug` on any developer's machine produces APKs whose
signing cert digest matches `Tamper.EXPECTED_CERT_SHA256` /
`SuiteAttestation.EXPECTED_SUITE_CERT_SHA256` / equivalent in
`SuiteCapabilityRegistry`.

Cert digest (SHA-256):

    aba68a81a0d63b5549794e586875a4f04e6dba3a6fe25d363e04eb75f46df69e

Default credentials (Android-debug-keystore standard):

    storePassword: android
    keyAlias:      androiddebugkey
    keyPassword:   android

## Why this is committed

Without a committed keystore, every developer's first `assembleDebug` produces
APKs signed with their personal `~/.android/debug.keystore`, which has a
different cert digest. Tamper.kt would then hard-fail at runtime — bricking
fresh installs after every clean checkout.

This is intentional for the v1-alpha development phase. The understory repo
is private; only operator-authorised contributors have read access. A debug
keystore commitment in a private repo is *not* a credential leak — debug
keystores aren't intended for production signing.

## Rotating the keystore

If we ever need to rotate (e.g. credential leak, switch signing identity):

1. Generate a fresh debug keystore:
   ```bash
   keytool -genkey -v -keystore debug.keystore -storepass android \
     -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 \
     -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
   ```
2. Read the new SHA-256 digest:
   ```bash
   keytool -list -v -keystore debug.keystore -storepass android \
     | grep "SHA256:" | awk '{print $2}' | tr -d ':' | tr '[:upper:]' '[:lower:]'
   ```
3. Update **every** pin reference (one source of truth would be nice; we have
   four right now — listed in `RELEASE_BLOCKERS.md`):
   - `common-security/.../Tamper.kt` → `EXPECTED_CERT_SHA256`
   - `common-security/.../SuiteAttestation.kt` → `EXPECTED_SUITE_CERT_SHA256`
   - `common-security/.../SuiteCapabilityRegistry.kt` → `EXPECTED_SUITE_CERT_SHA256`
   - `passgen/.../MainActivity.kt` (diagnostic UI displays the pin)
4. `gradle :passgen:assembleDebug … :vault-folder:assembleDebug`. The
   `verifyCertPin` task in `android/build.gradle.kts` runs after assemble
   and refuses any APK that doesn't match.
5. Anyone with prior installs needs to uninstall once before sideloading the
   new APKs (Android refuses cert-mismatched updates).

## For a release keystore

Release builds **must** use a different keystore stored outside this repo
(see `RELEASE_BLOCKERS.md`). This file is debug-only.
