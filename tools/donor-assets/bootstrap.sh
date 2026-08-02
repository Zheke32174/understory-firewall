#!/usr/bin/env bash
#
# Stage, ELF-repatch, and repackage a Termux bootstrap into a Godwall asset.
#
# See docs/LINUX-SUBSYSTEM.md for the architecture this feeds: Godwall ships
# its OWN Linux userland (not a dependency on an installed Termux) at
# /data/local/tmp/godwall/usr, because since API 29 an app's own data dir is
# effectively noexec for files the app writes (W^X) and /data/local/tmp is
# the writable-AND-executable path, owned by uid 2000 — the uid Yojimbo's
# privileged shell already runs as.
#
# A stock Termux bootstrap hardcodes every binary's PT_INTERP and
# DT_RUNPATH/DT_RPATH at /data/data/com.termux/files/usr. Move the prefix
# without rewriting those and the dynamic loader looks in the wrong place
# and nothing execs. `elf-repatch.py` in this directory does the rewrite;
# this script does everything around it: fetch the upstream zip, extract,
# invoke the patcher over the whole tree, repackage in the SAME on-disk
# layout Termux itself installs (see SYMLINKS.txt handling below), and drop
# the result where Godwall's asset pipeline expects it.
#
# Same discipline as tools/donor-assets/fetch.sh: nothing here runs
# implicitly at build time. A script that silently pulls binaries into a
# security build during `gradle assemble` is its own supply-chain problem.
# You run this by hand, one ABI at a time, and it prints provenance.
#
# Usage:
#   tools/donor-assets/bootstrap.sh list
#   tools/donor-assets/bootstrap.sh fetch   <abi>   # download the raw upstream zip
#   tools/donor-assets/bootstrap.sh patch   <abi>   # extract + repatch + repackage
#   tools/donor-assets/bootstrap.sh all     <abi>   # fetch, then patch
#   tools/donor-assets/bootstrap.sh verify          # show what's staged/patched
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE="${DONOR_ASSET_STAGE:-/tmp/donor-assets}/termux-bootstrap"
ASSET_DIR="${BOOTSTRAP_ASSET_DIR:-$REPO_ROOT/godwall-next/src/main/assets/subsystem/bootstrap}"
REPATCHER="$REPO_ROOT/tools/donor-assets/elf-repatch.py"

# The two prefixes. THESE MUST MATCH com.understory.godwall.subsystem.Bootstrap.kt
# — OLD_PREFIX is what upstream Termux hardcodes, NEW_PREFIX is Godwall's own
# prefix constant (PREFIX in Bootstrap.kt). They are declared in two languages
# because a shell script and a Kotlin object can't share a source constant
# across a build boundary; docs/LINUX-SUBSYSTEM.md is the third place this is
# written down, and is the tie-breaker if these three ever drift.
OLD_PREFIX="/data/data/com.termux/files/usr"
NEW_PREFIX="/data/local/tmp/godwall/usr"

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m warn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1${2:+ ($2)}"
}

provenance() {
  printf '\n  payload:  %s\n  source:   %s\n  licence:  %s\n  installs: %s\n\n' \
    "$1" "$2" "$3" "$4"
}

# Android ABI name -> the arch token Termux's bootstrap release assets use.
termux_arch_for_abi() {
  case "$1" in
    arm64-v8a)   echo "aarch64" ;;
    armeabi-v7a) echo "arm" ;;
    x86_64)      echo "x86_64" ;;
    x86)         echo "i686" ;;
    *) die "unknown ABI: $1 (want one of arm64-v8a, armeabi-v7a, x86_64, x86)" ;;
  esac
}

all_abis() { echo "arm64-v8a armeabi-v7a x86_64 x86"; }

# ---------------------------------------------------------------------------
# fetch — download the raw upstream bootstrap zip for one ABI.
#
# DELIBERATELY NOT PINNED TO A TAG HERE. termux-packages cuts a new
# `bootstrap-<date>-rN` release periodically and this sandbox has no network
# path to GitHub's API to read the current one at the time of writing — so
# rather than bake in a version string I cannot verify, TERMUX_BOOTSTRAP_TAG
# is a required input. Check https://github.com/termux/termux-packages/releases
# for the current bootstrap-* tag before running this.
# ---------------------------------------------------------------------------
fetch() {
  local abi="${1:?usage: bootstrap.sh fetch <abi>}"
  local arch; arch="$(termux_arch_for_abi "$abi")"
  need curl
  : "${TERMUX_BOOTSTRAP_TAG:?set TERMUX_BOOTSTRAP_TAG to a release tag from \
https://github.com/termux/termux-packages/releases (e.g. bootstrap-2025.01.01-r1) \
— not guessed here because this environment cannot reach the GitHub API to confirm \
the current one}"

  mkdir -p "$STAGE/raw"
  local out="$STAGE/raw/bootstrap-${arch}.zip"
  local url="https://github.com/termux/termux-packages/releases/download/${TERMUX_BOOTSTRAP_TAG}/bootstrap-${arch}.zip"

  log "fetching $url"
  curl -sSL --fail --retry 4 --retry-all-errors -o "$out" "$url" \
    || die "download failed — confirm the tag has a bootstrap-${arch}.zip asset"

  provenance "bootstrap-${arch}.zip (raw, unpatched)" \
    "$url" \
    "varies per package — see termux-packages LICENSE.md; attribution owed in NOTICE before this ships" \
    "$out"
}

# ---------------------------------------------------------------------------
# patch — extract a staged (or already-downloaded) zip, repatch every ELF and
# every shebang script in it, and repackage in Termux's own on-disk layout.
#
# LAYOUT NOTE: Termux's bootstrap zip does not store real symlinks — it ships
# a SYMLINKS.txt manifest of "target<TAB>linkpath" pairs (both relative to
# $PREFIX) that TermuxInstaller.java replays with Os.symlink() at install
# time, because symlinks-in-zip has been unreliable across the tooling that
# produces and consumes these archives. Preserved as-is here: entries are
# relative names, never the absolute old prefix, so nothing in that manifest
# needs rewriting — but it's checked defensively rather than assumed, because
# an assumption is exactly the failure mode this whole campaign is correcting.
# ---------------------------------------------------------------------------
patch() {
  local abi="${1:?usage: bootstrap.sh patch <abi>}"
  local arch; arch="$(termux_arch_for_abi "$abi")"
  need python3
  need unzip
  need zip
  [ -f "$REPATCHER" ] || die "missing $REPATCHER"

  local raw="$STAGE/raw/bootstrap-${arch}.zip"
  [ -f "$raw" ] || die "no staged zip at $raw — run 'bootstrap.sh fetch $abi' first"

  local extract="$STAGE/extract/$abi"
  rm -rf "$extract"
  mkdir -p "$extract"
  log "extracting $raw"
  unzip -q "$raw" -d "$extract"

  if [ -f "$extract/SYMLINKS.txt" ]; then
    if grep -q "$OLD_PREFIX" "$extract/SYMLINKS.txt"; then
      warn "SYMLINKS.txt contains an absolute old-prefix reference — rewriting it too"
      sed -i "s#$OLD_PREFIX#$NEW_PREFIX#g" "$extract/SYMLINKS.txt"
    fi
  fi

  log "repatching every ELF + shebang under $extract (this is the load-bearing step)"
  python3 "$REPATCHER" \
    --old-prefix "$OLD_PREFIX" --new-prefix "$NEW_PREFIX" \
    --verbose "$extract" \
    || die "elf-repatch.py reported errors — a bootstrap with even one \
unpatched loader path will fail to exec on device; not shipping it"

  mkdir -p "$ASSET_DIR"
  local out="$ASSET_DIR/${abi}.zip"
  rm -f "$out"
  log "repackaging patched tree as $out"
  ( cd "$extract" && zip -qXr "$out" . )

  provenance "${abi}.zip (PT_INTERP + DT_RUNPATH repatched to $NEW_PREFIX)" \
    "github.com/termux/termux-packages release ${TERMUX_BOOTSTRAP_TAG:-<unset — set when fetch ran>}, \
patched by tools/donor-assets/elf-repatch.py" \
    "varies per package — see termux-packages LICENSE.md; attribution owed in NOTICE before this ships" \
    "$out"
  log "asset ready — Bootstrap.kt reads this via assetPath(\"$abi\") = \"subsystem/bootstrap/${abi}.zip\""
}

all() {
  local abi="${1:?usage: bootstrap.sh all <abi>}"
  fetch "$abi"
  patch "$abi"
}

verify() {
  local ok=0 missing=0
  log "termux bootstrap asset status (per ABI)"
  for abi in $(all_abis); do
    local asset="$ASSET_DIR/${abi}.zip"
    if [ -e "$asset" ]; then
      printf '  \033[32mLINKED\033[0m  %-14s %s\n' "$abi" "$asset"
      ok=$((ok + 1))
    else
      printf '  \033[33mabsent\033[0m  %-14s %s\n' "$abi" "$asset"
      missing=$((missing + 1))
    fi
  done
  echo
  log "$ok present, $missing absent — Bootstrap.status() in Kotlin reports the same thing at runtime"
  return 0
}

list() {
  cat <<EOF
Termux bootstrap staging, per ABI (arm64-v8a, armeabi-v7a, x86_64, x86):

  fetch <abi>   download the raw upstream bootstrap-<arch>.zip
                (needs TERMUX_BOOTSTRAP_TAG — see the comment above fetch())
  patch <abi>   extract + elf-repatch.py + repackage into
                godwall-next/src/main/assets/subsystem/bootstrap/<abi>.zip
  all <abi>     fetch, then patch
  verify        show which per-ABI assets are staged

  old prefix:   $OLD_PREFIX
  new prefix:   $NEW_PREFIX
EOF
}

case "${1:-list}" in
  list)   list ;;
  fetch)  fetch "${2:-}" ;;
  patch)  patch "${2:-}" ;;
  all)    all "${2:-}" ;;
  verify) verify ;;
  *)      die "unknown command: $1 (try: $0 list)" ;;
esac
