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

  log "building firestack.aar"
  ( cd "$src" && make android ) \
    || die "firestack build failed — check its README for the current make target"

  mkdir -p "$REPO_ROOT/godwall-next/libs"
  find "$src" -name 'firestack*.aar' -exec cp {} "$REPO_ROOT/godwall-next/libs/firestack.aar" \; \
    || die "no firestack aar produced"

  provenance "firestack.aar" \
    "github.com/celzero/firestack" \
    "Apache-2.0" \
    "godwall-next/libs/firestack.aar"
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
  firestack)          fetch_firestack ;;
  invizible)          fetch_invizible ;;
  lsposed)            fetch_lsposed ;;
  termux-bootstrap)   fetch_termux_bootstrap ;;
  operit-submodules)  fetch_operit_submodules ;;
  *)                  die "unknown payload: $1  (try: $0 list)" ;;
esac
