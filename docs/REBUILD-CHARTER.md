# Rebuild charter — the current apps are SCRAP PARTS, not a foundation

> "you are rebuilding all of those apps from scratch essentially and using the
> current versions as scrap parts." — user, 2026-08-02

That is the operating frame. Write it down because forgetting it is exactly how
the drift below happened.

## The relationship

The suite absorbs **donors** (Shizuku, Dhizuku, Tailscale, InviZible, RethinkDNS,
LSPosed, ReVanced, Termux, Total Commander…) by reverse-engineering them and
building superior native variants.

**The current versions of our own apps are donors too.** They are salvage: keep
the parts that are genuinely good, discard the parts that diverge from intent.
They are not authoritative, and they are not finished.

Corollary, and this is the trap that has cost the most: **the confident comments
and honest-sounding docs already in the tree were written by a previous session.
They are marketing, not specification.** Treating them as evidence of
correctness is circular reasoning. Verify against intent and behaviour, never
against the code's own prose.

## THE INVARIANT

> **If it has to ask the thing it replaces, it has not replaced it.**

This is testable, so it is the one rule that does not require re-deriving intent.
Apply it mechanically:

- Yojimbo replaces Shizuku + Dhizuku ⇒ Yojimbo must never require the Shizuku app
  or the Dhizuku app.
- Godwall **is** the Tailscale node ⇒ Godwall must never launch, require, or defer
  to the Tailscale app.
- Godwall draws privilege from **Yojimbo** ⇒ Godwall must never reach for Shizuku
  or Dhizuku directly.
- Genji replaces LSPosed/ReVanced ⇒ Genji must never require LSPosed installed.

A grep that finds these violations:

```bash
grep -rn "getLaunchIntentForPackage" --include="*.kt" .        # deferring to another app
grep -A12 "<queries>" **/AndroidManifest.xml                    # declared dependence
```

"Coexist with", "works alongside", "install X first" and "open X" are all the
smell. An app that replaces something does not coexist with it — at most it
*detects a conflict* and tells the user to remove the thing it supersedes.

## Known violations (measured 2026-08-02, all in Godwall)

| # | Violation | Location | Correct behaviour |
|---|---|---|---|
| 1 | Launches the Tailscale app | `firewall/.../TunnelPostureScreen.kt:151` `openTailscale()` | Godwall runs the tailnet itself (`TailscaleController` + `libtailscale`). The external app is a **slot conflict** to resolve, not a peer to open. |
| 2 | Declares a dep on the Shizuku app | `firewall/src/main/AndroidManifest.xml` `<queries> moe.shizuku.privileged.api` | Privilege comes from **Yojimbo**. |
| 3 | Declares a dep on the Dhizuku app | `firewall/src/main/AndroidManifest.xml` `<queries> com.rosan.dhizuku` | Privilege comes from **Yojimbo**. |

Violations 2–3 were called out by the user at the start of this campaign
("so it's not dependent on shizuku. make it dependent on yojimbo") and are still
present. The whole `TunnelPosture` / `TierOverview` "Tailscale coexistence"
framing is downstream of violation 1 and is scrap along with it.

Yojimbo's own equivalent — `Elevation.canRunShell()` reducing to
`isShizukuGranted()` — is being fixed separately.

## Method going forward

1. **Intent first.** The code cannot tell us what was wanted; it *is* the
   divergence. Where intent is unknown, ask — do not infer from the tree.
2. **Three states, never conflated.** Every claim is one of:
   - **Verified working** — observed doing the thing
   - **Compiles, unproven** — builds; no evidence it functions
   - **Known broken / not as intended**
   "Compiles + unit tests pass" is the *second* state. Reporting it as the first
   is what put a 80%-broken Chaos Orb in the user's hands.
3. **Salvage explicitly.** When reusing an existing file, say why it survived.
   Silence means it was assumed good, and assumption is the failure mode.

## Per-app intent — CONFIRMED vs UNKNOWN

Confirmed by direct user statement:

- **Yojimbo** — *is* Shizuku and Dhizuku. Other apps (including Godwall) draw
  privilege from it. It must run its own privileged server.
- **Godwall** — *is* a Tailscale node, plus firewall + DNS, in one VPN slot. Also
  an egress-chain orchestrator (node **and** chain). Donors: InviZible, RethinkDNS,
  De1984, Fyrypt, Tailscale.
- **Genji** — hook/patch framework; absorbs LSPosed, ReVanced, apktool, NPatch,
  microG. Lucky Patcher: **engineering tooling only**, no billing/licence/fake-Google.
- **Masamune** — AI harness + ryznix second OS; a local container treated as
  external to Android. Not a fork of Operit — Operit is a donor.
- **Chaos Orb** — EMI/counter-surveillance. Currently ~80% broken on device.

**UNKNOWN — needs the user, do not guess:** the intended design for the pieces
that diverged before this session. The tree cannot answer it and inferring from
the tree is what produced the divergence.
