#!/usr/bin/env bash
#
# Obtain the donor payloads that are not source.
#
# See docs/DONOR-ASSETS.md for what each payload IS and which capability dies
# without it. This script only obtains them.
#
# DESIGN NOTE, and the reason this is a long explicit script rather than a tidy
# loop over a manifest: every function below downloads or builds a binary that
# ends up inside a security app. A script that silently pulls binaries during a
# build is itself a supply-chain problem, so nothing here runs implicitly — the
# Gradle builds never invoke it. You run it, for one named payload at a time,
# and it prints the provenance and licence of what it fetched.
#
# Usage:
#   tools/donor-assets/fetch.sh list
#   tools/donor-assets/fetch.sh <payload>
#   tools/donor-assets/fetch.sh verify
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE="${DONOR_ASSET_STAGE:-/tmp/donor-assets}"

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m warn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1${2:+ ($2)}"
}

provenance() {
  # Printed after every successful fetch. If you cannot say where a binary came
  # from and under what licence, it does not belong in the build.
  printf '\n  payload:  %s\n  source:   %s\n  licence:  %s\n  installs: %s\n\n' \
    "$1" "$2" "$3" "$4"
}

# ---------------------------------------------------------------------------
# libtailscale — Godwall's mesh data plane. THE REFERENCE IMPLEMENTATION.
# ---------------------------------------------------------------------------
fetch_libtailscale() {
  need go "https://go.dev/dl/"
  need git
  : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME (NDK r27+) — gomobile needs it}"

  local src="$STAGE/tailscale-android"
  mkdir -p "$STAGE"
  if [ ! -d "$src" ]; then
    log "cloning tailscale-android"
    git clone --depth 1 https://github.com/tailscale/tailscale-android "$src"
  fi

  log "installing gomobile"
  go install golang.org/x/mobile/cmd/gomobile@latest
  go install golang.org/x/mobile/cmd/gobind@latest
  export PATH="$PATH:$(go env GOPATH)/bin"

  log "gomobile bind (this takes a few minutes)"
  ( cd "$src" && gomobile bind \
      -target android \
      -androidapi 26 \
      -o "$REPO_ROOT/godwall-next/libs/libtailscale.aar" \
      ./libtailscale )

  provenance "libtailscale.aar" \
    "github.com/tailscale/tailscale-android (gomobile bind ./libtailscale)" \
    "BSD-3-Clause" \
    "godwall-next/libs/libtailscale.aar"
  log "rebuild with: gradle :godwall-next:assembleDebug   (HAS_MESH_DATAPLANE becomes true)"
}

# ---------------------------------------------------------------------------
# firestack — RethinkDNS's Go tun2socks data plane. Same shape as libtailscale.
# ---------------------------------------------------------------------------
fetch_firestack() {
  need go
  need git
  : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME (NDK r27+)}"

  local src="$STAGE/firestack"
  mkdir -p "$STAGE"
  [ -d "$src" ] || git clone --depth 1 https://github.com/celzero/firestack "$src"

  go install golang.org/x/mobile/cmd/gomobile@latest
  export PATH="$PATH:$(go env GOPATH)/bin"

  # The target is `intra`, NOT `android`. `make android` builds the Outline
  # tun2socks variant; `make intra` builds build/intra/tun2socks.aar, which is
  # what upstream's ./make-aar renames to firestack.aar and what RethinkDNS
  # actually links.
  #
  # Four blockers, all hit and diagnosed in this sandbox. They are load-bearing —
  # skip any one and the build fails with a message that points somewhere else:
  #
  # 1. gomobile needs golang.org/x/mobile in the module graph. Recent gomobile
  #    ALSO requires an explicit tool directive, so `go get` alone is not enough:
  #    without `go get -tool ...gobind` it dies with "missing golang.org/x/mobile
  #    dependency" even though go.mod already requires x/mobile.
  # 2. gobind must exist on PATH. gomobile reports "gobind was not found, please
  #    run gomobile init" — but `gomobile init` does not install it here; it has
  #    to be `go install`ed into the same GOBIN.
  # 3. firestack's go.mod declares `go 1.26`, and the Makefile pins
  #    GOTOOLCHAIN=local inside its build recipe. So the toolchain on PATH must
  #    itself be >= 1.26 or the module graph will not load, and the symptom is
  #    the misleading "not in the module dependency graph" from blocker 1.
  # 4. THE SUBTLE ONE. firestack overlays a patch onto Go's own
  #    runtime/write_err_android.go (for crash logging). Go refuses to apply an
  #    overlay to any file under GOMODCACHE — and a toolchain fetched by
  #    GOTOOLCHAIN=go1.26.0 lands in exactly there. So GOROOT must be a copy of
  #    the toolchain OUTSIDE the module cache, or it fails with "Files beneath
  #    GOMODCACHE must not be replaced".
  need make
  local gobin="$src/bin"
  local goroot="${FIRESTACK_GOROOT:-/opt/go126}"
  [ -x "$goroot/bin/go" ] || die "need a Go >= 1.26 GOROOT outside GOMODCACHE at $goroot (blockers 3+4; set FIRESTACK_GOROOT)"

  log "adding the x/mobile tool directive (blocker 1)"
  ( cd "$src" && GOFLAGS=-mod=mod PATH="$goroot/bin:$PATH" go get -tool golang.org/x/mobile/cmd/gobind )

  log "installing gobind into $gobin (blocker 2)"
  ( cd "$src" && GOFLAGS=-mod=mod GOBIN="$gobin" PATH="$goroot/bin:$PATH" go install golang.org/x/mobile/cmd/gobind )

  log "gomobile bind — this compiles Go for four ABIs and takes several minutes"
  ( cd "$src" && env \
      GOROOT="$goroot" \
      PATH="$goroot/bin:$gobin:$PATH" \
      GOFLAGS=-mod=mod \
      make intra ) \
    || die "firestack build failed — read the log above; the real error is usually 20+ lines before the make failure, since depaware prints a wall of 'unused <pkg>' lines first"

  mkdir -p "$REPO_ROOT/godwall-next/libs"
  local built="$src/build/intra/tun2socks.aar"
  [ -f "$built" ] || die "make intra reported success but produced no $built"
  cp "$built" "$REPO_ROOT/godwall-next/libs/firestack.aar"

  provenance "firestack.aar" \
    "github.com/celzero/firestack" \
    "Apache-2.0" \
    "godwall-next/libs/firestack.aar"
}

# ---------------------------------------------------------------------------
# busybox for Android — VERIFIED RECIPE.
#
# This is the reference for cross-compiling any autotools/kbuild C project to an
# Android ABI, and it is the pattern tor and i2pd will follow. It took nine
# attempts; every blocker below is real and each one fails with a message that
# points somewhere unhelpful, so they are documented at the call site.
#
# THE DIVISION OF LABOUR: the NDK does the cross-compiling. A Gentoo/Portage
# layer (see underhall) is useful for supplying configure-time dependencies for
# bigger targets, but it does NOT produce Android binaries itself — native
# `emerge` builds x86-64 Linux. Do not conflate the two.
#
# BLOCKERS, in the order they appear:
#
# 1. `make defconfig` enables applets Bionic cannot build. Android's libc is not
#    glibc: no <shadow.h>, no <sys/kd.h>, no gethostid(), no mntent (addmntent).
#    Start from `make allnoconfig` and enable ONLY the applets needed — which is
#    also what a purpose-built payload should ship.
# 2. CONFIG_FEATURE_SHADOWPASSWDS=y pulls <shadow.h> even with USE_BB_PWD_GRP
#    off; the include is guarded by SHADOWPASSWDS && !USE_BB_SHADOW.
# 3. NDK r27 REMOVED the `aarch64-linux-android-ar` binutils wrappers. The build
#    dies with "aarch64-linux-android-ar: not found" long after compiling fine.
#    Pass AR/NM/STRIP/RANLIB/OBJCOPY as the llvm-* tools explicitly.
# 4. Bionic has provided strchrnul() since API 24, in libc.a's
#    static_function_dispatch.S, so busybox's own fallback is a DUPLICATE SYMBOL
#    at static-link time. Setting -DHAVE_STRCHRNUL through CONFIG_EXTRA_CFLAGS
#    reaches the link line but NOT libbb/platform.c's translation unit, so the
#    guard in that file has to be widened. Verified by reading the linker's own
#    "defined at ... in archive .../libc.a" output rather than guessing.
#
# Result: a 527 KB statically linked aarch64 Android ELF with no dynamic section.
# NOT executed on a device from here — the artifact is verified, its runtime
# behaviour is not.
# ---------------------------------------------------------------------------
fetch_busybox_android() {
  need make
  local abi="${1:-arm64-v8a}"
  local ver="${BUSYBOX_VERSION:-1.36.1}"
  local ndk="${ANDROID_NDK_HOME:-/root/android-sdk/ndk/27.0.12077973}"
  local tc="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
  local api="${ANDROID_API:-26}"

  local triple
  case "$abi" in
    arm64-v8a)   triple=aarch64-linux-android ;;
    armeabi-v7a) triple=armv7a-linux-androideabi ;;
    x86_64)      triple=x86_64-linux-android ;;
    x86)         triple=i686-linux-android ;;
    *) die "unknown abi: $abi" ;;
  esac
  [ -x "$tc/${triple}${api}-clang" ] || die "no NDK clang at $tc/${triple}${api}-clang"

  local src="$STAGE/busybox-$ver"
  mkdir -p "$STAGE"
  if [ ! -d "$src" ]; then
    log "fetching busybox $ver"
    ( cd "$STAGE" && curl -sSL --retry 4 --retry-all-errors \
        -o busybox.tar.bz2 "https://busybox.net/downloads/busybox-$ver.tar.bz2" \
      && tar xf busybox.tar.bz2 && rm -f busybox.tar.bz2 )
  fi

  ( cd "$src"
    log "configuring a minimal applet set (blocker 1)"
    make allnoconfig >/dev/null
    for s in STATIC SH_IS_ASH ASH ASH_INTERNAL_GLOB FEATURE_SH_STANDALONE \
             PS KILL KILLALL PIDOF SLEEP ID CHMOD CHOWN MKDIR RM MV CP LN LS CAT \
             ECHO TEST TRUE FALSE GREP SED AWK CUT TR HEAD TAIL WC SORT UNIQ \
             XARGS FIND WHICH BASENAME DIRNAME READLINK REALPATH DMESG PRINTF \
             TOUCH STAT DU SYNC SETSID NOHUP TIMEOUT ENV; do
      sed -i "s/^# CONFIG_$s is not set/CONFIG_$s=y/" .config
    done
    # blocker 2, plus the applets Bionic cannot provide headers for.
    for s in FEATURE_SHADOWPASSWDS FEATURE_UTMP FEATURE_WTMP TC MOUNT UMOUNT DF; do
      sed -i "s/^CONFIG_$s=y/# CONFIG_$s is not set/" .config
    done
    yes "" | make oldconfig >/dev/null 2>&1

    # blocker 4 — widen the guard in the file that actually compiles it.
    if ! grep -q '__ANDROID__' libbb/platform.c; then
      log "patching libbb/platform.c for Bionic's strchrnul (blocker 4)"
      perl -0pi -e 's/#ifndef HAVE_STRCHRNUL\nchar\* FAST_FUNC strchrnul/#if !defined(HAVE_STRCHRNUL) \&\& !defined(__ANDROID__)\nchar* FAST_FUNC strchrnul/' libbb/platform.c
    fi

    log "building busybox for $abi (blocker 3: llvm-* binutils, not the removed wrappers)"
    PATH="$tc:$PATH" make -j"$(nproc)" \
      CROSS_COMPILE="${triple}-" CC="${triple}${api}-clang" HOSTCC=cc \
      AR=llvm-ar NM=llvm-nm STRIP=llvm-strip RANLIB=llvm-ranlib OBJCOPY=llvm-objcopy
  ) || die "busybox build failed — see the log above"

  # jniLibs rather than assets: the platform extracts these and marks them
  # executable for us, which is cleaner than InviZible's rename-to-.mp3 trick
  # (that exists only to stop the packager compressing an ELF in assets/).
  local dest="$REPO_ROOT/godwall-next/src/main/jniLibs/$abi"
  mkdir -p "$dest"
  cp "$src/busybox" "$dest/libbusybox.so"

  provenance "busybox $ver ($abi, static)" \
    "busybox.net (built from source with the NDK)" \
    "GPL-2.0" \
    "godwall-next/src/main/jniLibs/$abi/libbusybox.so"
}

# ---------------------------------------------------------------------------
# InviZible Pro payloads — tor / dnscrypt-proxy / i2pd, plus their configs.
#
# These are NOT built inside the InviZible repo. Gedsh maintains separate
# toolchain repos and the app ships the results in assets/ renamed to *.mp3 so
# the Android packager will not compress them. That rename is load-bearing: an
# ELF compressed into the APK cannot be exec'd after extraction.
# ---------------------------------------------------------------------------
fetch_invizible() {
  need git
  local src="$STAGE/InviZible"
  mkdir -p "$STAGE"
  [ -d "$src" ] || git clone --depth 1 https://github.com/Gedsh/InviZible "$src"

  local dest="$REPO_ROOT/godwall-next/src/main/assets/invizible"
  mkdir -p "$dest"

  # The configuration trees ARE in the donor repo and are plain text.
  local cfg
  cfg="$(find "$src" -type d -name 'app_data' -print -quit || true)"
  if [ -n "$cfg" ]; then
    log "copying app_data config trees (torrc, dnscrypt-proxy.toml, i2pd.conf, geoip)"
    cp -r "$cfg/." "$dest/"
  else
    warn "no app_data/ found — upstream layout changed; check the repo before proceeding"
  fi

  # The binaries are the hard part and are deliberately NOT auto-downloaded.
  cat <<'EOF'

  The tor / dnscrypt-proxy / i2pd binaries are NOT fetched automatically.

  They are per-ABI ELF executables built in Gedsh's separate toolchain repos,
  and pulling prebuilt native binaries into a security build without a human
  deciding to is exactly the thing this suite exists to argue against. Either:

    a) build them from the upstream toolchain repos yourself, or
    b) extract them from a release InviZible APK you have verified
       (assets/*.mp3 — they are ELF despite the extension), or
    c) leave them out: Godwall's DNS filter, encrypted upstream, per-app policy,
       egress chain and mesh node all work without them. Only Tor / DNSCrypt /
       I2P routing stays reported-absent.

  Place per-ABI binaries under:
    godwall-next/src/main/jniLibs/<abi>/libtor.so
    godwall-next/src/main/jniLibs/<abi>/libdnscrypt-proxy.so
    godwall-next/src/main/jniLibs/<abi>/libi2pd.so

  (jniLibs rather than assets: the platform extracts and marks those
  executable for us, which is cleaner than the .mp3 trick.)

EOF

  provenance "InviZible app_data config trees" \
    "github.com/Gedsh/InviZible" \
    "GPL-3.0" \
    "godwall-next/src/main/assets/invizible/"
}

# ---------------------------------------------------------------------------
# LSPosed — liblspd.so + framework.jar. Genji's runtime hook engine.
# ---------------------------------------------------------------------------
fetch_lsposed() {
  need git
  need java
  local src="$STAGE/LSPosed"
  mkdir -p "$STAGE"
  [ -d "$src" ] || git clone --recurse-submodules --depth 1 \
    https://github.com/LSPosed/LSPosed "$src"

  cat <<'EOF'

  LSPosed needs its own NDK toolchain and a full Gradle build of the daemon plus
  the injected framework. It is not a one-command fetch.

    cd "$STAGE/LSPosed" && ./gradlew :daemon:assembleRelease

  Until liblspd.so and the framework dex are supplied, Genji's ArtCore stays the
  honest stub and the Modules tab states that hooks DO NOT FIRE. Static APK
  patching is unaffected — it needs no native core and no privilege at all.

EOF

  provenance "LSPosed daemon + framework" \
    "github.com/LSPosed/LSPosed" \
    "GPL-3.0" \
    "genji-next/libs/  (not yet wired — capability reports absent)"
}

# ---------------------------------------------------------------------------
# Termux bootstrap — the entire usr/ prefix, per ABI.
# ---------------------------------------------------------------------------
fetch_termux_bootstrap() {
  cat <<'EOF'

  Masamune deliberately does NOT bundle a Termux bootstrap.

  The bootstrap is the whole Termux prefix — every ELF package — and shipping a
  second copy of someone else's package manager inside our APK is both a large
  licensing surface and a second thing to keep patched. masamune-next instead
  delegates to an INSTALLED Termux over com.termux.RUN_COMMAND and shows a
  blocked empty state when it is absent. That is the honest boundary, and it is
  stated on the Shell screen.

  If you want to revisit that, the artifacts are at:
    https://github.com/termux/termux-packages/releases  (bootstrap-<abi>.zip)

EOF
}

# ---------------------------------------------------------------------------
# Operit submodules — unblocks the legacy :app module.
# ---------------------------------------------------------------------------
fetch_operit_submodules() {
  need git
  local tr="${TRACENDROID_ROOT:-$REPO_ROOT/../tracendroid}"
  [ -d "$tr/.git" ] || die "tracendroid not found at $tr (set TRACENDROID_ROOT)"

  log "initialising :terminal (blocks :app dependency resolution)"
  ( cd "$tr" && git submodule update --init terminal )

  log "the inference natives are large; init them only if you need local inference"
  echo "    cd $tr && git submodule update --init --recursive mnn llama app/src/main/cpp/thirdparty"

  provenance "OperitTerminalCore" \
    "github.com/AAswordman/OperitTerminalCore" \
    "see upstream LICENSE" \
    "tracendroid/terminal/"
}

# ---------------------------------------------------------------------------

verify() {
  local ok=0 missing=0
  check() {
    if [ -e "$2" ]; then
      printf '  \033[32mLINKED\033[0m  %-24s %s\n' "$1" "$2"; ok=$((ok + 1))
    else
      printf '  \033[33mabsent\033[0m  %-24s %s\n' "$1" "$2"; missing=$((missing + 1))
    fi
  }
  log "donor payload status"
  check libtailscale "$REPO_ROOT/godwall-next/libs/libtailscale.aar"
  check firestack    "$REPO_ROOT/godwall-next/libs/firestack.aar"
  check invizible    "$REPO_ROOT/godwall-next/src/main/assets/invizible"
  check terminal     "$REPO_ROOT/../tracendroid/terminal/build.gradle.kts"
  echo
  log "$ok present, $missing absent"
  # Absent payloads are NOT an error. Every one of them has a capability that
  # reports itself absent, so the build stays green and the app stays honest.
  return 0
}

list() {
  cat <<'EOF'
Payloads (see docs/DONOR-ASSETS.md for what each one is):

  libtailscale        Godwall mesh data plane          builds from source
  firestack           RethinkDNS tun2socks             builds from source
  busybox-android     iptables/process driver          builds from source (VERIFIED)
  invizible           tor/dnscrypt/i2pd + configs      configs auto, binaries manual
  lsposed             Genji runtime hook engine        manual build
  termux-bootstrap    (documented boundary, not fetched)
  operit-submodules   unblocks the legacy :app module  git submodule

  verify              show what is currently present
EOF
}

case "${1:-list}" in
  list)               list ;;
  verify)             verify ;;
  libtailscale)       fetch_libtailscale ;;
  busybox-android)    fetch_busybox_android "${2:-arm64-v8a}" ;;
  firestack)          fetch_firestack ;;
  invizible)          fetch_invizible ;;
  lsposed)            fetch_lsposed ;;
  termux-bootstrap)   fetch_termux_bootstrap ;;
  operit-submodules)  fetch_operit_submodules ;;
  *)                  die "unknown payload: $1  (try: $0 list)" ;;
esac
