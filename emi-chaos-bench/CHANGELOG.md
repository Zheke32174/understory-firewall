# Changelog

All notable changes to EMI Chaos Bench are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions match `versionName` in
`app/build.gradle.kts`.

## [3.9-audit] — unreleased

### Added — the Audit pillar (fused security posture)
- **`AuditFusion`** — a pure, JVM-testable engine that folds every existing
  detector (cellular, Wi-Fi, LAN/interception, process integrity, follower
  detection, and the evidence vault's own integrity) into one graded posture:
  a 0–100 score, a `clear/watch/elevated/critical` grade, prioritised findings
  worst-first, and — kept strictly separate — a list of **coverage gaps** for
  checks that could not run, so "nothing found" is never conflated with "did not
  look". No new detector, no radio use; it is a lens over observations the app
  already makes.
- **`AuditEngine`** — the service-owned wrapper that gathers each detector's
  cached JSON, runs the fusion on the background timer (last, after the sweep),
  and writes a coalesced posture-transition line to the encrypted vault, so a
  change in exposure is recorded even with the app backgrounded.
- **Audit screen** — a new native destination surfacing the graded posture, the
  prioritised findings and gaps, and evidence/masking status at a glance.
- **`EMIAudit`** — a read-only page bridge (pinned by `InvariantsTest` to be
  read + append-only, like every other bridge).

### Added — the Forensic pillar (case report + chain of custody)
- **`CaseReport`** — a self-contained evidence bundle in two formats: an HTML
  report to hand to a person and a JSON bundle for machines. Both embed the
  vault's own `verify()` output verbatim (chain-of-custody proof) rather than
  re-deriving an integrity claim, follow the existing `format`-versioning +
  embedded-verification convention, and HTML-escape all attacker-influenceable
  finding text. The report is location-free and identity-free by construction.
- **Chain-of-custody logging** — exporting evidence (case report or raw vault)
  now appends a custody record to the append-only vault: what left the device,
  when, how large, and how many records were attested.

### Changed
- `ShellView` gains the `Audit` destination (nav is now five tabs; the fixed tab
  text size drops from 9.5sp to 9sp so the longest label still fits a fifth-width
  tab on a narrow phone).
- `MaskerService` gains `ensureAuditEngine(ctx)` and drives it last on the 5-min
  background sweep.
- `versionCode` 13 → 14, `versionName` `3.8-persist` → `3.9-audit`.

### Packaging (toward a standalone repository)
- Committed the Gradle **wrapper** (`gradlew`, `gradlew.bat`, wrapper jar) pinned
  to Gradle 8.9.
- Added **Android CI** (`.github/workflows/android-ci.yml`): unit tests, lint,
  debug APK — active when this directory is a repository root.
- Added `SECURITY.md`, `CONTRIBUTING.md`, and this changelog.

### Unchanged, deliberately
- The masking/disruption core (Web Audio graph, DOM hammer, DSP rack) is
  untouched — the audit layer only *reports* whether masking is active. No
  transmit/jam/spoof path was added; the invariants in `ETHICS.md` hold.
