#!/usr/bin/env bash
# factory-setup.sh — on-create/on-attach provisioning for factory-stamped
# codespaces. Idempotent: safe to re-run on every attach.
#
# Manifest syntax (repos.txt, next to this script):
#   owner/repo                    shallow-clone into $FACTORY_VENDOR_DIR/<repo>
#   https://github.com/owner/repo same (tree/blob suffixes stripped)
#   owner/*                       ALL public repos of a user/org (GitHub API)
#   gist:<id>                     clone gist into _gists/<id>
#   doc <url>                     download into _docs/ (papers, pages, threads)
#
# Clone/download failures are non-fatal — a repo may be private, renamed, or
# gone; results land in $FACTORY_VENDOR_DIR/.factory-report.txt.
#
# Deliberately clone-only: nothing from the vendored repos is executed or
# dependency-installed here — running npm/pip install across ~100 unvetted
# repos would execute their postinstall hooks (supply-chain risk). Install a
# repo's deps yourself, per repo, after looking at it.
#
# Never exits nonzero — a broken vendor repo must not brick codespace creation.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/repos.txt"

# /workspaces persists across codespace stop/start/rebuild; fall back to
# $HOME for plain local devcontainers where /workspaces doesn't exist.
if [ -z "${FACTORY_VENDOR_DIR:-}" ]; then
  if [ -d /workspaces ] && [ -w /workspaces ]; then
    FACTORY_VENDOR_DIR=/workspaces/vendor
  else
    FACTORY_VENDOR_DIR="$HOME/vendor"
  fi
fi

mkdir -p "$FACTORY_VENDOR_DIR"
REPORT="$FACTORY_VENDOR_DIR/.factory-report.txt"
: > "$REPORT.tmp"

if [ ! -f "$MANIFEST" ]; then
  echo "factory-setup: no manifest at $MANIFEST — nothing to clone" | tee "$REPORT"
  exit 0
fi

ok=0 skipped=0 failed=0 docs=0

clone_repo() {  # $1 = owner/repo
  local repo="$1" name owner dest have
  name="${repo##*/}"; owner="${repo%%/*}"
  dest="$FACTORY_VENDOR_DIR/$name"

  # If a dir with this name exists, keep it when it's the same repo,
  # otherwise clone under owner__name to dodge the collision. Match on the
  # trailing owner/repo path, not the host — codespaces and proxied
  # environments rewrite the clone URL's host portion.
  if [ -d "$dest/.git" ]; then
    have="$(git -C "$dest" remote get-url origin 2>/dev/null || true)"
    have="${have%.git}"
    case "$have" in
      */"$repo") echo "present  $repo" >> "$REPORT.tmp"; skipped=$((skipped+1)); return ;;
      *)         dest="$FACTORY_VENDOR_DIR/${owner}__${name}" ;;
    esac
  fi
  if [ -d "$dest/.git" ]; then
    echo "present  $repo" >> "$REPORT.tmp"; skipped=$((skipped+1)); return
  fi

  if git clone --depth 1 "https://github.com/$repo" "$dest" >/dev/null 2>&1; then
    echo "cloned   $repo" >> "$REPORT.tmp"; ok=$((ok+1))
  else
    rm -rf "$dest"
    echo "FAILED   $repo (private, renamed, or nonexistent)" >> "$REPORT.tmp"
    failed=$((failed+1))
  fi
}

expand_owner() {  # $1 = owner — emit all public owner/repo, paged (/users/ works for orgs too)
  local owner="$1" page json
  for page in 1 2 3 4 5; do
    json="$(curl -fsSL -m 30 "https://api.github.com/users/$owner/repos?per_page=100&page=$page" 2>/dev/null)" || break
    echo "$json" | grep -o '"full_name": *"[^"]*"' | cut -d'"' -f4
    # fewer than 100 entries → last page
    [ "$(echo "$json" | grep -c '"full_name"')" -lt 100 ] && break
  done
}

fetch_doc() {  # $1 = url
  local url="$1" slug
  mkdir -p "$FACTORY_VENDOR_DIR/_docs"
  slug="$(echo "$url" | sed -e 's|^https\?://||' -e 's|[^A-Za-z0-9._-]|_|g' | cut -c1-120)"
  if [ -s "$FACTORY_VENDOR_DIR/_docs/$slug" ]; then
    echo "present  doc $url" >> "$REPORT.tmp"; skipped=$((skipped+1)); return
  fi
  if curl -fsSL -m 60 -o "$FACTORY_VENDOR_DIR/_docs/$slug" "$url" 2>/dev/null; then
    echo "doc      $url" >> "$REPORT.tmp"; docs=$((docs+1))
  else
    rm -f "$FACTORY_VENDOR_DIR/_docs/$slug"
    echo "FAILED   doc $url" >> "$REPORT.tmp"; failed=$((failed+1))
  fi
}

clone_gist() {  # $1 = gist id
  local id="$1" dest="$FACTORY_VENDOR_DIR/_gists/$1"
  if [ -d "$dest/.git" ]; then
    echo "present  gist:$id" >> "$REPORT.tmp"; skipped=$((skipped+1)); return
  fi
  mkdir -p "$FACTORY_VENDOR_DIR/_gists"
  if git clone --depth 1 "https://gist.github.com/$id.git" "$dest" >/dev/null 2>&1; then
    echo "cloned   gist:$id" >> "$REPORT.tmp"; ok=$((ok+1))
  else
    rm -rf "$dest"
    echo "FAILED   gist:$id" >> "$REPORT.tmp"; failed=$((failed+1))
  fi
}

while IFS= read -r raw; do
  line="${raw%%#*}"
  # trim leading/trailing whitespace, keep interior space (doc directive)
  line="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [ -z "$line" ] && continue

  case "$line" in
    doc\ *)
      fetch_doc "${line#doc }" ;;
    gist:*)
      clone_gist "${line#gist:}" ;;
    */\*)
      owner="${line%/\*}"
      repos="$(expand_owner "$owner")"
      if [ -z "$repos" ]; then
        echo "FAILED   $line (owner expansion returned nothing)" >> "$REPORT.tmp"
        failed=$((failed+1))
      else
        while IFS= read -r r; do [ -n "$r" ] && clone_repo "$r"; done <<< "$repos"
      fi ;;
    *)
      # normalize URL forms → owner/repo; strip .git and /tree|/blob suffixes
      repo="$(echo "$line" | sed -E -e 's#^https?://github\.com/##' -e 's#\.git$##' \
              -e 's#^([^/]+/[^/]+)/(tree|blob)/.*#\1#' -e 's#/$##' | tr -d '[:space:]')"
      case "$repo" in
        */*) clone_repo "$repo" ;;
        *)   echo "SKIPPED  $line (not owner/repo)" >> "$REPORT.tmp" ;;
      esac ;;
  esac
done < "$MANIFEST"

{
  echo "# factory-setup report — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# cloned=$ok present=$skipped failed=$failed docs=$docs  vendor=$FACTORY_VENDOR_DIR"
  cat "$REPORT.tmp"
} > "$REPORT"
rm -f "$REPORT.tmp"

echo "factory-setup: cloned=$ok present=$skipped failed=$failed docs=$docs → $REPORT"
exit 0
