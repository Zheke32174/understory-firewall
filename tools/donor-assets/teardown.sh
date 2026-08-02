#!/usr/bin/env bash
#
# Tear a donor APK down into a readable description of HOW IT LOOKS.
#
# WHY THIS EXISTS
# ---------------
# Every failed round of this campaign had the same root cause, and the user
# named it directly: "you need to read more and understand better how the apps
# 'look'. that's been almost exclusively the issue every time."
#
# The donor surface specs up to now were written from knowledge of what these
# apps do. That produces plausible menus with the wrong items, in the wrong
# order, under the wrong headings, with the wrong wording — which is precisely
# the "more coherent but missing basically everything" result.
#
# An APK already contains its own appearance, exactly, and it does not need an
# emulator to read (there is no KVM in this sandbox, so running them is not an
# option):
#
#   res/menu/*.xml         every menu item, in order, with its title and icon
#   res/xml/*preference*   every settings row, in order, with category grouping,
#                          keys, summaries and dependency chains
#   res/layout/*.xml       the actual view hierarchy of each screen
#   res/navigation/*.xml   the destination graph
#   values/strings         the exact wording — not a paraphrase
#   values/colors|themes|dimens   the actual visual language
#
# Release APKs are usually resource-obfuscated (res/u1.xml rather than
# res/menu/bottom_navigation_menu.xml), so this maps logical names back to files
# via `aapt2 dump resources` before decoding each one, and resolves every
# @0x7f10xxxx reference to its real string.
#
# Usage:
#   teardown.sh <apk> [outdir]
#
set -euo pipefail

AAPT="${AAPT2:-/root/android-sdk/build-tools/35.0.0/aapt2}"
APK="${1:?usage: teardown.sh <apk> [outdir]}"
OUT="${2:-$(basename "${APK%.apk}")-teardown}"

command -v "$AAPT" >/dev/null 2>&1 || [ -x "$AAPT" ] || {
  echo "aapt2 not found at $AAPT (set AAPT2=)" >&2; exit 1
}

mkdir -p "$OUT"
RES="$OUT/_resources.txt"
"$AAPT" dump resources "$APK" > "$RES" 2>/dev/null

python3 - "$APK" "$RES" "$OUT" "$AAPT" <<'PY'
import re, subprocess, sys, os, collections

apk, resfile, out, aapt = sys.argv[1:5]

# ---- pass 1: id -> string value, and logical name -> packed file ------------
# `aapt2 dump resources` emits, per entry:
#     resource 0x7f1000e3 string/settings_block_contacts
#       () "Block contacts searching"
# or for file-backed resources:
#     resource 0x7f080061 menu/bottom_navigation_menu
#       () (file) res/u1.xml type=XML
strings, files = {}, {}
cur = None
for line in open(resfile, encoding="utf-8", errors="replace"):
    m = re.match(r'\s*resource (0x[0-9a-f]+) (\w+)/(\S+)', line)
    if m:
        cur = (m.group(1), m.group(2), m.group(3))
        continue
    if cur is None:
        continue
    fm = re.search(r'\(file\) (res/\S+)', line)
    if fm:
        files[f"{cur[1]}/{cur[2]}"] = fm.group(1)
        cur = None
        continue
    sm = re.search(r'\(\)\s+"(.*)"\s*$', line)
    if sm and cur[1] in ("string", "plurals"):
        strings[cur[0]] = sm.group(1)
        cur = None

def resolve(tok):
    """Turn @0x7f1000e3 into its real text where we know it."""
    return strings.get(tok.lower(), tok)

# ---- pass 2: decode every menu / preference / navigation / layout ----------
INTERESTING = ("menu", "xml", "navigation", "layout")
groups = collections.defaultdict(list)
for logical, packed in sorted(files.items()):
    kind = logical.split("/", 1)[0]
    if kind in INTERESTING:
        groups[kind].append((logical, packed))

ATTR = re.compile(r'android:(\w+)\([^)]*\)=(.+?)\s*$')
RAW  = re.compile(r'^"?(.*?)"?(?: \(Raw: "(.*)"\))?$')

def decode(packed):
    try:
        return subprocess.run(
            [aapt, "dump", "xmltree", apk, "--file", packed],
            capture_output=True, text=True, timeout=120,
        ).stdout
    except Exception as e:
        return f"(decode failed: {e})"

def render(tree):
    """Flatten aapt2's xmltree into indented element/attribute lines with
    string references already resolved, which is what a human needs to see."""
    lines = []
    for raw in tree.splitlines():
        em = re.match(r'(\s*)E: ([\w.]+) \(line=(\d+)\)', raw)
        if em:
            depth = len(em.group(1)) // 2
            lines.append(f"{'  ' * depth}<{em.group(2)}>")
            continue
        am = re.search(r'(\s*)A: (?:http://schemas.android.com/apk/res(?:-auto|/android)?:)?(\w+)\([^)]*\)=(.*)', raw)
        if am:
            depth = len(am.group(1)) // 2
            name, val = am.group(2), am.group(3).strip()
            ref = re.match(r'@(0x[0-9a-f]+)', val)
            if ref:
                got = resolve(ref.group(1))
                val = f'"{got}"' if got != ref.group(1) else val
            rawm = re.search(r'\(Raw: "(.*)"\)', val)
            if rawm:
                val = f'"{rawm.group(1)}"'
            # Only the attributes that describe APPEARANCE and STRUCTURE.
            if name in ("title", "summary", "key", "id", "label", "text", "hint",
                        "dependency", "entries", "entryValues", "defaultValue",
                        "checkable", "checked", "showAsAction", "icon", "name",
                        "startDestination", "layout", "orientation", "visibility"):
                lines.append(f"{'  ' * depth}    {name} = {val}")
            continue
    return "\n".join(lines)

summary = []
for kind in ("menu", "xml", "navigation", "layout"):
    entries = groups.get(kind, [])
    if not entries:
        continue
    # Layouts are numerous and mostly framework noise; keep the app's own.
    if kind == "layout":
        entries = [e for e in entries if not e[0].split("/")[1].startswith(
            ("abc_", "m3_", "mtrl_", "design_", "notification_", "select_dialog",
             "support_", "preference_", "expand_button"))]
    path = os.path.join(out, f"{kind}.txt")
    with open(path, "w", encoding="utf-8") as fh:
        for logical, packed in entries:
            fh.write(f"\n########## {logical}   ({packed})\n")
            fh.write(render(decode(packed)) + "\n")
    summary.append(f"{kind}: {len(entries)} -> {os.path.basename(path)}")

# ---- the string table, which is the exact wording ------------------------
with open(os.path.join(out, "strings.txt"), "w", encoding="utf-8") as fh:
    named = {}
    cur = None
    for line in open(resfile, encoding="utf-8", errors="replace"):
        m = re.match(r'\s*resource (0x[0-9a-f]+) string/(\S+)', line)
        if m:
            cur = m.group(2); continue
        if cur:
            sm = re.search(r'\(\)\s+"(.*)"\s*$', line)
            if sm:
                named[cur] = sm.group(1)
            cur = None
    for k in sorted(named):
        fh.write(f"{k} = {named[k]}\n")
summary.append(f"strings: {len(strings)} -> strings.txt")

print("\n".join(summary))
PY

echo
echo "teardown written to: $OUT/"
