# Donor assets — the payloads that are not source

> "many of these apps require additional resources that are in their git repos
> like invizible pro. you are not going to quietly ignore that this time, for
> ANY donor app." — user, 2026-08-02

## Why this file exists

Most of the donors are not mostly Kotlin. The behaviour we are absorbing lives in
**prebuilt binaries, `.aar` bundles, blocklist packs, dex payloads and bootstrap
archives** that ship *alongside* the source in the donor's repo or its releases.

Reading a donor's Kotlin and reimplementing the UI produces a screen that looks
right and does nothing, because the thing that did the work was an ELF binary in
`assets/`. That is the exact failure mode this campaign is correcting, and it is
invisible in review: the code compiles, the screen renders, the feature is dead.

So every donor payload is enumerated here with **what it is, where it comes from,
how it is obtained, and which capability dies without it.**

## The rule

**A capability whose payload is absent reports absent.** It does not degrade
silently, it does not draw an enabled control, and it does not claim a state it
cannot reach.

`libtailscale` already proves the pattern end to end and is the reference
implementation for every row below:

- `godwall-next/build.gradle.kts` takes the aar as a build input
  (`-Plibtailscale.aar=`, `LIBTAILSCALE_AAR`, or `godwall-next/libs/`).
- Present ⇒ `src/tailscale/java` joins the source set and the real backend
  compiles; `BuildConfig.HAS_MESH_DATAPLANE` is true.
- Absent ⇒ **the build still succeeds** (CI must stay green on a clean checkout;
  a missing optional payload is not a build error), `Mesh.status()` returns
  `ABSENT`, and the Mesh screen says the data plane is not in this build while
  the Start button sits disabled next to that sentence.

Copy that shape. Never `try { } catch { }` a missing payload into a shrug.

## Status legend

| Mark | Meaning |
|---|---|
| **LINKED** | Obtained, in-tree or fetchable, and compiled against |
| **GATED** | Build gate written; payload not yet obtained. Capability reports absent |
| **OPEN** | Not yet gated. **A capability here can currently lie** — fix before shipping the surface |

---

## Godwall

| Donor | Payload | What it actually is | Obtain | Capability without it |
|---|---|---|---|---|
| Tailscale | `libtailscale.aar` | gomobile-bound Go: DERP, NAT traversal, WireGuard keys, MagicDNS. **Not on Maven** — upstream links it as a local file | `gomobile bind -target android -androidapi 26 ./libtailscale` in `tailscale-android` | **LINKED** — mesh node; `ABSENT` without it |
| RethinkDNS | `firestack.aar` | Go tun2socks data plane (`celzero/firestack`). Same shape as libtailscale — a gomobile aar, not a library | `tools/donor-assets/fetch.sh firestack` (four blockers documented there) | **BUILT** — 28.9 MB, 4 ABIs, 129 classes. See docs/FIRESTACK-LINKING.md. Not yet wired into the build |
| RethinkDNS | blocklist packs | ~195 on-device lists + the stamp format. Fetched at runtime from `download.rethinkdns.com`; a minimal set is bundled | Bundle a base pack; runtime fetch for the rest | **GATED** — only the bundled `base.hosts.gz` is available |
| InviZible Pro | `tor`, `i2pd` ELF | Per-ABI prebuilt binaries in `assets/`, **renamed `.mp3`** so Android's packager will not compress or extract them | Built in Gedsh's *separate* toolchain repos, not in `InviZible` itself | **OPEN** — Tor / I2P routing |
| InviZible Pro | ~~`dnscrypt-proxy` ELF~~ | **No longer needed.** firestack implements DNSCrypt *and* anonymized-DNSCrypt relays in Go (`Intra.addDNSCryptTransport` / `addDNSCryptRelay`), plus ODoH, which InviZible does not offer at all | — | **SUPERSEDED** by firestack |
| InviZible Pro | `app_data/` config trees | `torrc`, `dnscrypt-proxy.toml`, `i2pd.conf`, plus tor's `geoip`/`geoip6` | Ship from the donor tree; they are plain config | **OPEN** — the binaries above cannot start without them |
| InviZible Pro | `busybox` | Used to drive iptables and process control | `tools/donor-assets/fetch.sh busybox-android [abi]` — builds from source, recipe verified (nine blockers documented in the script) | **BUILDABLE** — produced a 527 KB static aarch64 Android ELF here; not committed, not device-tested |
| De1984 | tracker/permission DB | Its classification data, not code | From the donor repo | **OPEN** — tracker attribution |

## Yojimbo

| Donor | Payload | What it actually is | Obtain | Capability without it |
|---|---|---|---|---|
| Shizuku | `starter` + server dex | The binary `app_process` execs to stand up the privileged server | Built from `RikkaApps/Shizuku` server module | **GATED** — Yojimbo runs its **own** server; this is reference only, never a runtime dependency |
| ReSukiSU / KernelSU | `ksud` userspace binary | Manages modules and the su policy against a KSU kernel | KernelSU releases, per-ABI | **OPEN** — KernelSU tab is status-only |
| ReSukiSU / KernelSU | kernel patches | Not shippable in an APK at all — the kernel must already carry KSU | n/a | Documented boundary, not a gap |

## Genji

| Donor | Payload | What it actually is | Obtain | Capability without it |
|---|---|---|---|---|
| LSPosed | `liblspd.so` + `framework.jar` | The zygisk/riru native module and the injected framework dex. **This is the hook engine** | Build from `LSPosed/LSPosed` (NDK) | **GATED** — `ArtCore` is an honest stub; the Modules tab states hooks do not fire |
| NPatch / LSPatch | loader `.so` + `lspatch.dex` | The loader embedded into a target APK for rootless Xposed | `LSPosed/LSPatch` releases | **OPEN** — embedded-loader patching |
| ReVanced | `.rvp` patch bundle + integrations APK | Released artifacts, **not source**. The patches are the product | `revanced/revanced-patches` releases | **OPEN** — Genji ships its own fingerprint/rewrite engine instead; bundle compatibility is separate |
| apktool | per-ABI `aapt2` + framework `1.apk` | Needed to *rebuild* an APK rather than rewrite bytes in place | AOSP build-tools; framework from the device | **GATED** — the rewriter is in-place and same-size only, and says so |
| microG | GmsCore APK | An entire separate app, plus signature spoofing that needs a patched ROM or LSPosed | `microg/GmsCore` releases | **OPEN** |

## Masamune

| Donor | Payload | What it actually is | Obtain | Capability without it |
|---|---|---|---|---|
| Termux | bootstrap zip (per-ABI) | The whole `usr/` prefix — every ELF package. This *is* Termux | `termux/termux-packages` releases | **GATED** — the shell delegates to an installed Termux via `RUN_COMMAND`; absent ⇒ blocked empty state, nothing bundled |
| Operit (upstream donor) | `:terminal` submodule | `AAswordman/OperitTerminalCore`; `:app` cannot resolve without it | `git submodule update --init terminal` (**done**, and it clones) | Blocks the legacy `:app` only; `masamune-next` avoids it by construction |
| Operit | MNN / llama.cpp / ncnn / sherpa | On-device inference natives, each its own submodule | `git submodule update --init --recursive` | **OPEN** — local inference |
| Xed Editor | tree-sitter grammar `.so` | One per language | `RohitKushvaha01/Xed-Editor` | **OPEN** — syntax highlighting |
| Total Commander | — | Closed source. Behaviour was reverse-engineered from the APK; there is nothing to take | n/a | Not a gap — `docs/donors/RE-total-commander.md` is the record |

## Chaos Orb

| Donor | Payload | What it actually is | Obtain | Capability without it |
|---|---|---|---|---|
| Rayhunter | capture format | IMSI-catcher detection output it ingests | Format spec, not a binary | **GATED** — ingestion path only |
| JamesDSP | EEL DSP cores | Ported to Kotlin rather than linked | n/a | Not a gap — ported |

---

## Obtaining them

Payloads are **not committed**. They are large, most are separately licensed, and
several are per-ABI. Each is a build input on the libtailscale pattern.

`tools/donor-assets/fetch.sh` is the single entry point. It is intentionally
explicit — one function per payload, each printing its licence and provenance —
because a script that silently downloads binaries into a security build is its own
supply-chain problem. Nothing is fetched implicitly at build time.

## Licensing

These are other people's work under their own terms — InviZible Pro and LSPosed
are GPL-3.0, Tailscale is BSD-3-Clause, Termux packages vary per package. Any
payload that ships in an artifact we distribute carries its licence and
attribution in `NOTICE`. Reverse-engineering a donor to build a superior native
variant is the method; relabelling a donor's binary as ours is not.
