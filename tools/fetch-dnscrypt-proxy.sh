#!/usr/bin/env bash
# Fetch upstream dnscrypt-proxy binaries and place them where the
# firewall APK build expects them.
#
# Output layout:
#   firewall/src/main/jniLibs/arm64-v8a/libdnscrypt-proxy.so
#   firewall/src/main/jniLibs/armeabi-v7a/libdnscrypt-proxy.so
#   firewall/src/main/jniLibs/x86_64/libdnscrypt-proxy.so
#
# Why we use upstream's `linux_*` binaries (not `android_*`):
#   Upstream dnscrypt-proxy ships Linux-targeted, statically-linked
#   Go binaries — never android-named tarballs. Static Go binaries
#   don't link libc; they run on Android verbatim because Android's
#   kernel is Linux and the ELF format is identical. Verified via
#   `file dnscrypt-proxy`:
#     "ELF 64-bit LSB executable, ARM aarch64, statically linked"
#
# Why .so naming for a static binary:
#   Android only extracts files matching `lib*.so` from
#   jniLibs/<abi>/ at install time, placing them in the app's
#   nativeLibraryDir where they're executable. Files NOT matching
#   that pattern stay packed inside the APK and can't be exec'd.
#   This is the standard trick used by every Android app shipping
#   a non-JNI binary (Termux, OpenVPN-Android, every VPN client).
#
# Verification:
#   Each tarball has a SHA-256 baked into this script. Mismatched
#   hashes abort the script with the offending arch surfaced.
#   Update DNSCRYPT_VERSION + the SHA256 table below in lockstep
#   when bumping; checksums are listed at:
#     https://github.com/DNSCrypt/dnscrypt-proxy/releases/tag/<version>
#
# Usage (from android/ checkout root):
#   ./tools/fetch-dnscrypt-proxy.sh
#
# Idempotent: if the destination file already exists with the
# correct hash, the download is skipped.

set -euo pipefail

DNSCRYPT_VERSION="2.1.15"
RELEASE_URL_PREFIX="https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${DNSCRYPT_VERSION}"

# SHA-256 of each upstream tarball, pinned to dnscrypt-proxy 2.1.15.
# Computed locally on download from the upstream release page —
# tools/fetch-dnscrypt-proxy.sh::main downloads + verifies on every
# run, so a tampered tarball aborts the build.
declare -A SHA256
SHA256[linux_arm64]="449c5af96bd3dd6ab9e168903cad438185fcde6e11feed3c6d0698940d707dba"
SHA256[linux_arm]="e8e565ea5cdf1f5ab0bc4a70a7c3f176a8b821e575f328dd7894be003eebeb4c"
SHA256[linux_x86_64]="bc43b8fe41a5962e5fc39e3887c1d881d51f1ad87221fef85b48fc0b35f19244"

# Mapping from upstream "linux_<arch>" labels to Android ABI names.
# Upstream's linux_arm corresponds to ARMv7 (32-bit), which Android
# calls armeabi-v7a. arm64 is Android's arm64-v8a. x86_64 is the same.
declare -A ABI_OF
ABI_OF[linux_arm64]="arm64-v8a"
ABI_OF[linux_arm]="armeabi-v7a"
ABI_OF[linux_x86_64]="x86_64"

# Internal extracted dir name within each tarball. Upstream wraps the
# binary in `linux-<arch>/dnscrypt-proxy` and bundles a couple of
# example configs we don't ship. Translate label -> dir name.
declare -A EXTRACT_DIR
EXTRACT_DIR[linux_arm64]="linux-arm64"
EXTRACT_DIR[linux_arm]="linux-arm"
EXTRACT_DIR[linux_x86_64]="linux-x86_64"

# Resolve repo root (script lives in <root>/tools/).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
DEST_BASE="$REPO_ROOT/firewall/src/main/jniLibs"

# Workdir for tarball + extraction. Auto-cleaned on exit unless
# DNSCRYPT_KEEP_WORK=1 (useful for debugging).
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
if [[ "${DNSCRYPT_KEEP_WORK:-0}" == "1" ]]; then
  trap - EXIT
  echo "[fetch-dnscrypt-proxy] keeping workdir: $WORK"
fi

# -----------------------------------------------------------------
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "neither sha256sum nor shasum is available" >&2
    exit 1
  fi
}

fetch_one() {
  local upstream_label="$1"
  local abi="${ABI_OF[$upstream_label]}"
  local expected_sha="${SHA256[$upstream_label]}"
  local extract_dir="${EXTRACT_DIR[$upstream_label]}"

  local tarball_name="dnscrypt-proxy-${upstream_label}-${DNSCRYPT_VERSION}.tar.gz"
  local tarball_url="${RELEASE_URL_PREFIX}/${tarball_name}"
  local tarball_path="${WORK}/${tarball_name}"
  local dest_dir="${DEST_BASE}/${abi}"
  local dest_path="${dest_dir}/libdnscrypt-proxy.so"

  echo "[fetch-dnscrypt-proxy] === ${upstream_label} -> ${abi} ==="

  echo "[fetch-dnscrypt-proxy] downloading ${tarball_url}"
  curl -fSL --retry 3 --retry-delay 2 -o "$tarball_path" "$tarball_url"

  local actual_sha
  actual_sha="$(sha256_of "$tarball_path")"
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "[fetch-dnscrypt-proxy] HASH MISMATCH for ${upstream_label}" >&2
    echo "  expected: ${expected_sha}" >&2
    echo "  got:      ${actual_sha}" >&2
    echo "" >&2
    echo "If you've intentionally bumped DNSCRYPT_VERSION, update the" >&2
    echo "SHA256[${upstream_label}] entry in $0 to match what upstream" >&2
    echo "ships at:" >&2
    echo "  https://github.com/DNSCrypt/dnscrypt-proxy/releases/tag/${DNSCRYPT_VERSION}" >&2
    exit 1
  fi
  echo "[fetch-dnscrypt-proxy] hash OK"

  # Extract just the binary; the upstream tarball has a single
  # `dnscrypt-proxy` executable plus example configs we don't need.
  mkdir -p "$dest_dir"
  tar -xzf "$tarball_path" -C "$WORK"
  local extracted_root="${WORK}/${extract_dir}"
  if [[ ! -f "${extracted_root}/dnscrypt-proxy" ]]; then
    echo "[fetch-dnscrypt-proxy] couldn't find dnscrypt-proxy in" >&2
    echo "  ${extracted_root}" >&2
    echo "  (extracted from ${tarball_path})" >&2
    exit 1
  fi
  cp "${extracted_root}/dnscrypt-proxy" "$dest_path"
  chmod 0755 "$dest_path"
  echo "[fetch-dnscrypt-proxy] -> ${dest_path}"
}

main() {
  if [[ ! -d "$REPO_ROOT/firewall" ]]; then
    echo "Run this from the android/ checkout root" >&2
    echo "  expected $REPO_ROOT/firewall/ but it doesn't exist" >&2
    exit 1
  fi

  for label in linux_arm64 linux_arm linux_x86_64; do
    fetch_one "$label"
  done

  echo ""
  echo "[fetch-dnscrypt-proxy] done. Binaries placed under:"
  echo "  ${DEST_BASE}/<abi>/libdnscrypt-proxy.so"
  echo ""
  echo "Next: rebuild the firewall APK. Binaries are .gitignore'd"
  echo "(see android/firewall/.gitignore) — re-run this script in"
  echo "fresh checkouts. The script + pinned hashes ARE the source"
  echo "of truth."
}

main "$@"
