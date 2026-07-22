#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
errors = []

if (root / "keystore/debug.keystore").exists():
    errors.append("committed debug.keystore is forbidden")

pins = (root / "common-security/src/main/java/com/understory/security/SuitePins.kt").read_text()
if "DEBUG_CERT_SHA256" in pins or "EXPECTED_CERT_SHA256" in pins:
    errors.append("retired debug or ambiguous certificate pin remains")
if "DEBUG_IDENTITY_TRUSTED = false" not in pins:
    errors.append("debug trust revocation marker missing")

gradle = (root / "build.gradle.kts").read_text()
for forbidden in ('rootProject.file("keystore/debug.keystore")', 'storePassword = "android"', 'keyPassword = "android"'):
    if forbidden in gradle:
        errors.append(f"committed debug-signing configuration remains: {forbidden}")

workflow = (root / ".github/workflows/publish-apk.yml").read_text()
for forbidden in ("contents: write", "gh release", "git tag", "git push --force", "--clobber"):
    if forbidden in workflow:
        errors.append(f"publication authority remains: {forbidden}")
if "contents: read" not in workflow:
    errors.append("validation workflow is not read-only")

readme = (root / "README.md").read_text()
for forbidden in ("committed suite debug keystore", "APK is attached as a workflow artifact", "two suite pins"):
    if forbidden in readme:
        errors.append(f"stale public signing claim remains: {forbidden}")

for rel, marker in [
    ("common-security/src/main/java/com/understory/security/Tamper.kt", "if (BuildConfig.DEBUG) return true"),
    ("common-security/src/main/java/com/understory/security/SuiteAttestation.kt", "if (BuildConfig.DEBUG)"),
    ("common-security/src/main/java/com/understory/security/SuiteCapabilityRegistry.kt", "if (BuildConfig.DEBUG)"),
]:
    if marker not in (root / rel).read_text():
        errors.append(f"{rel} missing debug trust boundary")

for pattern in ("*.jks", "*.p12", "*.pfx", "*.keystore"):
    for path in root.rglob(pattern):
        if ".git" not in path.parts:
            errors.append(f"private-key container present: {path.relative_to(root)}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
print("public signing boundary: valid")
