# Donor transplant — InviZible Pro

This directory is **grafted donor source**, not our code and not a re-implementation
of it. It is here so Godwall can run the donor's real code paths and real layouts
first, and only afterwards replace them piece by piece.

## Origin

| Field | Value |
|---|---|
| Upstream | https://github.com/Gedsh/InviZible |
| Commit | `9956519e221726c469300853cfe9a286abe04420` |
| Date | 2026-07-11 |
| Release | 7.5.0-stable |
| Donor package | `pan.alexander.tordnscrypt` |
| Upstream module | `tordnscrypt` |

## What was transplanted

| Path | Contents |
|---|---|
| `src/main/java/` | 427 Java/Kotlin files, package structure preserved verbatim |
| `src/main/res/` | Full resource tree including all **47 XML layouts** |
| `src/main/AndroidManifest.xml` | Donor manifest, unmodified |
| `build.gradle.donor` | Donor's original build file, kept for reference — **not** an active build script |
| `android-filepicker/` | The `:filepicker` subproject the donor module depends on |
| `LICENSE` | GPL-3.0, as shipped upstream |

Sources are byte-identical to upstream at the commit above. Nothing has been
renamed, reformatted, or "improved" on the way in. That is the point: a graft that
has been edited during transplant is no longer a reference you can diff against.

## What was NOT transplanted (yet)

- **`src/main/assets/*.mp3` — 5.9 MB.** These are not audio. InviZible ships its
  prebuilt native binaries disguised with an `.mp3` extension so they survive
  packaging: `busyb.mp3` (busybox), `dnscrypt.mp3` (dnscrypt-proxy),
  `itpd.mp3` (i2pd), `tor.mp3` (tor). They are the **runtime engine** — the donor's
  DNS/Tor/I2P features cannot actually run without them.
- **`src/main/jni/` — 1.1 MB** of C sources for the donor's native layer.

Both are required before the grafted screens do anything beyond render. They are
deliberately a separate step so this commit stays reviewable.

## Licensing consequence

InviZible Pro is **GPL-3.0**. Grafting it makes any distributed binary that links
this code GPL-3.0 as well. This was accepted knowingly when the donor was chosen.
It is reversible only *before* release — once shipped, the obligation attaches.

## Build status — honest

This module is **not yet wired into `settings.gradle.kts`**, so the existing build is
unaffected and stays green. Enabling it is a deliberate next step, not an accident
waiting to happen, and it needs real work first:

- the donor is a `com.android.application` module with product flavors and NDK
  ABI filters; it must become a library module to slot into this project;
- it pulls Dagger + KSP, `libsuperuser`, `com.jrummyapps:android-shell`, and the
  `:filepicker` project;
- the host app is Jetpack Compose with **zero** XML layouts, so hosting the donor's
  View/Fragment layouts means running both UI systems side by side.

None of this was compiled locally — there is no Android SDK in the session that
produced this commit. CI is the verifier.
