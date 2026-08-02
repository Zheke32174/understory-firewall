# Godwall's Linux subsystem — an own-userland bootstrap, not a Termux dependency

WP-1 of the Godwall rebuild. This document is the third place the two prefix
constants below are written down (the other two are the shell script and the
Kotlin object) — if they are ever found to disagree, this file is the
tie-breaker.

## The decision, stated once

Masamune's Shell screen delegates to an *installed* Termux over
`com.termux.RUN_COMMAND` and shows a blocked empty state when Termux isn't
present. That is a real, documented boundary for that app — see
`tools/donor-assets/fetch.sh fetch_termux_bootstrap`.

**Godwall does not do that.** Godwall ships its own patched copy of the
Termux prefix as an app asset and runs it itself. Per THE INVARIANT
(`docs/REBUILD-CHARTER.md`): *if it has to ask the thing it replaces, it has
not replaced it.* A security suite whose DNS resolvers, Tor/I2P routing and
proxy backends only work when a third-party terminal emulator happens to be
installed has not replaced InviZible Pro — it has added a dependency on it by
proxy. So this is a second, independent bootstrap: same upstream payload
(Termux's package tree), different consumer, different install location,
never the same running instance, never a required peer app.

## Where it lives, and why it cannot live anywhere else

```
PREFIX       = /data/local/tmp/godwall/usr
INSTALL_ROOT = /data/local/tmp/godwall
```

Not the app's private data directory. Since Android 10 (API 29), an app's own
data directory is mounted such that files the app itself writes there cannot
also be mapped executable by that app — W^X enforced at the filesystem level,
not just SELinux. A binary extracted into
`/data/data/com.understory.firewall/...` is inert: `exec()` on it fails
regardless of what privilege obtained it.

`/data/local/tmp` is the writable-AND-executable path on stock Android, and
it is owned by **uid 2000 (shell)**. That is precisely the identity Yojimbo's
privileged shell already runs as — Yojimbo's entire purpose, per the rebuild
charter, is standing up a process at uid 2000 without depending on Shizuku or
Dhizuku. So the chain is: Yojimbo gives Godwall a uid-2000 shell → that shell
extracts and `chmod`s the bootstrap into `/data/local/tmp/godwall/usr` → uid
2000 execs out of it. WP-2 (`PrefixInstaller.kt`, `Supervisor.kt`) owns that
extraction and process supervision. This document and its two files
(`Bootstrap.kt`, `tools/donor-assets/{bootstrap.sh,elf-repatch.py}`) own
*getting a correct, execute-anywhere bootstrap into the APK in the first
place* — the read side WP-2 depends on, not the privileged side itself.

**Not proot.** Running the interpreter directly as uid 2000 out of an
exec-friendly prefix carries no `ptrace` interposition overhead. This is the
same reasoning that lets `tailscaled` run fully unprivileged in Godwall's
mesh node (`docs/TAILSCALE-LINKING.md`) — **a socket listener or dialer needs
no root.** tor, i2pd, dnscrypt-proxy, dnsmasq, v2ray, sing-box and
shadowsocks are all the same shape: bind loopback, get dialled into. Godwall
already holds the tun fd from `VpnService`, so per-app and per-flow
enforcement happens in userspace over that fd (exactly what firestack does —
`docs/FIRESTACK-LINKING.md`), leaving the subsystem's job as "run daemons
that speak to localhost," which uid 2000 is entirely sufficient for. The
boundary that actually needs more than uid 2000 is rewriting the *kernel's*
netfilter tables or reaching into other apps' processes — that is a
different, higher tier, gated separately (WP-8), and this bootstrap makes no
claim on it.

## Why every binary needs surgery before it can be shipped

A stock Termux bootstrap is compiled and linked against
`/data/data/com.termux/files/usr` (`UPSTREAM_PREFIX` in `Bootstrap.kt`). That
absolute path is baked into two places inside every ELF:

1. **`PT_INTERP`** — the executable's dynamic loader path, when the
   toolchain set one.
2. **`DT_RUNPATH` / `DT_RPATH`** — the library search path consulted for
   every `DT_NEEDED` entry not resolved another way.

Moving the *installed* location of these files changes nothing about the
bytes written inside them. The loader still goes looking in
`/data/data/com.termux/files/usr/lib`, finds either nothing (that path
belongs to a different app or doesn't exist at all under Godwall) or someone
else's files, and the exec or the dynamic link fails. **"Nothing loads" is
not a metaphor here — it's the literal `execve()`/`dlopen()` failure mode.**

So every ELF in the bootstrap is repatched, once, before it is packaged as an
app asset:

```
OLD (upstream, hardcoded):  /data/data/com.termux/files/usr
NEW (Godwall's own):        /data/local/tmp/godwall/usr
```

`tools/donor-assets/elf-repatch.py` does the rewrite. It walks **program
headers only** — the same information the OS loader and dynamic linker
themselves consult — rather than section headers, which are debugger/linker
metadata that a stripped binary can lack entirely while still running fine.
Concretely:

- `PT_INTERP` is patched directly: the segment's own bytes ARE the
  interpreter path string.
- `DT_RUNPATH`/`DT_RPATH` are found by walking the `PT_DYNAMIC` segment's
  entries; the value is an offset into the string table pointed to by
  `DT_STRTAB`, and that table's virtual address is translated to a file
  offset by walking `PT_LOAD` segments — never by trusting a section header
  that might not exist.
- As a practical adjunct (the bootstrap also ships shell scripts, not just
  ELF), `#!`-shebang lines are rewritten too, since a `pip` wrapper script
  with a stale shebang fails to exec for exactly the same reason a binary
  with a stale `RUNPATH` does.

**Why this only ever shrinks or holds steady, never grows:** an ELF string
table entry is a null-terminated run of bytes at a fixed file offset other
structures point to *by that offset* — there is no slack to grow into
without shifting every subsequent file offset, which is a relink, not a
patch. `/data/local/tmp/godwall/usr` (27 bytes) is shorter than
`/data/data/com.termux/files/usr` (31 bytes) by construction, so the
replacement always fits with room to null-pad, and the tool refuses outright
(exit 2, no output written) if ever asked to do the reverse.

**This puts a hard 11-character ceiling on the app name**, and it is the one
number here that will bite a future app rather than this one. The upstream
prefix is 31 bytes; ours is `/data/local/tmp/` (16) + name + `/usr` (4), so
the name may not exceed `31 - 16 - 4 = 11` characters. The five current apps
all clear it — `godwall` 7, `masamune` 8, `yojimbo` 7, `genji` 5,
`chaosorb` 8 — but a twelfth character makes the new prefix *longer* than the
old one and every binary in that bootstrap becomes unpatchable. The failure
is loud (exit 2) rather than silent, which is the right behaviour, but the
constraint belongs in the name-choosing decision, not in the error message
someone hits afterwards.

Verified against real compiled ELFs during this work package (64-bit and
32-bit-format-compatible parsing, `DT_RUNPATH` and the older `DT_RPATH` tag,
a static binary with neither `PT_INTERP` nor `PT_DYNAMIC`, a shebang script,
and a directory tree via the recursive walk) — `readelf -d` / `readelf -x
.interp` on the patched output confirm the rewritten paths and confirm
re-running the patcher on already-patched output is a no-op. Not verified:
executing the resulting binaries on an actual Android device, which needs a
device and is out of this WP's reach — see the honesty ledger below.

## How the pieces fit together

```
tools/donor-assets/bootstrap.sh fetch <abi>
    downloads bootstrap-<arch>.zip from a termux-packages release
    (needs TERMUX_BOOTSTRAP_TAG — see below)
        ↓
tools/donor-assets/bootstrap.sh patch <abi>
    unzip → tools/donor-assets/elf-repatch.py over the whole tree
    → re-zip in Termux's own on-disk layout (SYMLINKS.txt preserved)
    → godwall-next/src/main/assets/subsystem/bootstrap/<abi>.zip
        ↓
Bootstrap.kt (this WP)
    reads that asset back: primaryAbi(), status(), manifest(), explain()
    — probes AssetManager, never assumes presence
        ↓
WP-2: PrefixInstaller.kt / Supervisor.kt (separate work package)
    asks Yojimbo for a uid-2000 shell, extracts the asset to
    /data/local/tmp/godwall/usr, execs daemons out of it
```

Each arrow is a real boundary, not a formality: `bootstrap.sh` is never
invoked by Gradle (same discipline as `fetch.sh` — "nothing here runs
implicitly at build time"; a script that silently pulls binaries into a
security build during `gradle assemble` is its own supply-chain problem).
`Bootstrap.kt` never touches `/data/local/tmp` or asks for privilege — it is
pure `AssetManager` reads. The privileged extraction is a different file
this WP does not own or touch.

## Version pinning — deliberately left undone here

`bootstrap.sh fetch` requires an explicit `TERMUX_BOOTSTRAP_TAG` environment
variable rather than defaulting to one. This sandbox has no network path to
GitHub's release API to confirm what the current `bootstrap-*` tag actually
is, and baking in a guessed version string into a script that downloads
binaries for a security build is exactly the failure mode
`docs/DONOR-ASSETS.md` exists to prevent. Whoever runs this for real checks
<https://github.com/termux/termux-packages/releases> for the current
`bootstrap-*` tag first. This is the same posture `fetch.sh` already takes
with `ANDROID_NDK_HOME`, `FIRESTACK_GOROOT`, and the LSPosed/InviZible manual
steps — an unset required input that fails loudly, not a silent default.

## Status — three states, not conflated

- **Verified working (observed):** `elf-repatch.py`'s ELF/shebang rewrite
  logic, exercised against real `gcc`-produced ELFs in this sandbox with
  `readelf` confirming the before/after bytes, including the full
  fetch→patch→repackage pipeline in `bootstrap.sh` run end-to-end against a
  synthetic bootstrap zip. `Bootstrap.kt` compiles and `assembleDebug`
  passes with it in the tree.
- **Compiles, unproven:** everything past that — an actual Termux bootstrap
  has not been downloaded or patched in this session (no pinned version, and
  downloading a real multi-ABI bootstrap here would still leave "does the
  repatched binary actually exec on a device" unverified, since nothing in
  this WP runs on a device). `Bootstrap.status()` has not been exercised
  against a real bundled asset for the same reason.
- **Known absent, not a gap in this WP:** the actual per-ABI
  `subsystem/bootstrap/<abi>.zip` assets are not in this build. Nothing
  bundles a real Termux bootstrap yet; `Bootstrap.status()` correctly and
  honestly reports `ABSENT` until someone runs `bootstrap.sh fetch` +
  `bootstrap.sh patch` per ABI with a real, verified release tag. Same
  no-payload-committed policy as `libtailscale.aar` and `firestack.aar`:
  large, separately-licensed binaries are a build input, obtained
  explicitly, never vendored silently.

## Licensing

Termux packages are a mix of upstream projects under their own licences
(GPL, MIT, BSD and others, per-package — see termux-packages' own
`LICENSE.md` at the pinned tag). This bootstrap ships those binaries
byte-patched at two ELF fields only — no source is modified, no
attribution-bearing string is touched, nothing here relicenses anything.
Per `docs/DONOR-ASSETS.md`'s rule: any payload actually shipped in a
distributed artifact carries its licence and attribution in `NOTICE`. That
entry is not yet added, because no bootstrap asset is yet bundled — add it
in the same change that first commits a real `subsystem/bootstrap/*.zip`.
