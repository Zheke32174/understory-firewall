# Open observations — unresolved, for re-examination

This file records things observed on a real device that are **not settled**. Nothing here is a
conclusion. Each entry states what was seen, what would distinguish the competing explanations,
and what evidence is still missing.

The reason it exists: during the 2026-08-01 session several observations arrived together, and
the tempting move was to pick the explanation that fit the code I had just been reading. That is
how a real signal gets written off as a bug, and how a bug gets written up as an attack. Both are
expensive. So the discipline is: record the observation, name the discriminating test, wait for
the evidence.

---

## 1. Vault became unreadable partway through (UNRESOLVED)

**Observed.** Successive exports from one device, same session:

| Local time | Records readable | Head count | verify |
|---|---|---|---|
| 15:29 | 70 | 70 | `ok: true`, chain intact |
| 16:19 | 279 | 463 | `AEADBadTagException` |
| 16:47–16:56 | **279** (frozen) | 724 → 830 (climbing) | `AEADBadTagException` |

Readable records froze at 279 while the head kept climbing. ~550 records are on disk and cannot
be authenticated.

**What is established.**
- Records 0–278 are **byte-identical across three exports** taken 30+ minutes apart (compared on
  `seq`, `t`, `prev`, `msg`). No sign of editing in the readable portion.
- Record 0's `prev` equals `sha256("EMI-VAULT-v1")` — the chain starts correctly.
- Sequences 0–278 are contiguous, no duplicates, no backward timestamps.
- The failure is an **authentication** failure at position 279, not a clean truncation. The data
  after it still exists.

**Competing explanations, neither ruled out.**
1. *Sequence slip in this app.* Two of the app's own writers appended concurrently under a
   per-instance lock (fixed: `SecureLog.lock` is now process-wide). Record at position N sealed
   as `seq N-1` → every later record's position disagrees with its sealed sequence.
   - Supporting: break at position 279 is exactly the off-by-one signature; the log had two
     independent writer sources (`webview`, `native`) active; append kept succeeding afterwards,
     which matches head-climbing-while-unreadable.
   - Against: across the 279 readable records there were **zero** cross-writer appends within
     200 ms, so tight interleaving was not otherwise observed.
2. *Something else wrote to the file.* A process running as this app's UID can append or
   overwrite. It cannot forge — the key is non-exportable and StrongBox-backed.
   - Supporting: see observation 2 below, and the timing in observation 3.

**The discriminating test, now implemented.** `walk()` resynchronises: on an authentication
failure it retries neighbouring sequence numbers within `RESYNC_WINDOW`.
- If record 279 authenticates under a **nearby** sequence → explanation 1, and the whole tail
  recovers.
- If it authenticates under **no** sequence in the window → the bytes are not something this app
  wrote, which points at explanation 2.

`verify()` now reports `likelyCause` as `app-defect-sequence-slip` or `truncation`, and lists
`resyncs`. **Run VERIFY on a build ≥ this one and record the result here.**

**Still missing.** The result of that verify. The raw `alerts.log` (app-private; needs adb/root).

---

## 2. `frida-server` present on the device (UNRESOLVED — ownership unknown)

**Observed.** TamperGuard flagged, three times (records #0, #235, #236):

```
possible Frida/injection: binary present: /data/local/tmp/frida-server
```

**Why it matters.** Frida is a dynamic instrumentation framework — it hooks running processes,
intercepts calls, reads and rewrites memory. If attached to this app it could plausibly produce
observation 1 by interfering with the `Cipher` calls or the file writes.

**Why it is not a conclusion.** The device owner runs extensive instrumentation tooling
(Shizuku, Dhizuku, privileged helpers) and confirmed some of the tooling on the device is theirs
and some is not, without resolving which this is. `/data/local/tmp/frida-server` is the ordinary
adb-push location for a *deliberately installed* frida-server.

**Discriminating evidence needed.** Whether the owner placed it; its mtime versus the session;
whether a frida-server process was actually *running* (the check finds the binary on disk, not a
live process); whether anything was attached to this app's PID.

**Improvement worth making.** The check reports a file's existence. Presence on disk and
attachment to this process are very different claims, and the alert should distinguish them —
`EscalationGuard` already reads `TracerPid`, and correlating the two would turn "a tool exists on
this device" into "something is attached to this app".

---

## 3. Timing correlation (NOTED ONLY — not evidence of causation)

Sequence on 2026-08-01 (UTC):

```
19:50:15  sonic-demod  (ultrasonic, heuristic)
19:50:28  sonic-demod  (NULL-PROBE CONFIRMED — external, 94% of level held through mute)
19:50:37  escalation   (overlay/tmpfs — see note below)
19:50:56  sonic-demod  (NULL-PROBE CONFIRMED — 124%)
19:53:09  tamper       (frida-server)
19:54:07  tamper       (frida-server)
19:55:29  cell-band    (ARFCN 66536 → 5230, band 13, same carrier — device stationary)
19:56:38  LAST READABLE RECORD
```

341 s from the last null-probe-confirmed ultrasonic detection to the end of the readable log.

**This is a correlation in a ~30 minute window containing many events.** It is recorded because
it is the kind of pattern that is only assessable in hindsight and across sessions — not because
this ordering demonstrates anything on its own.

The `/apex` escalation flags are a **known false positive** of an older build: `/apex` is tmpfs on
every modern Android device by design. `BENIGN_MOUNTS` excludes it in current code. Those three
records should not be read as signal.

---

## 4. Ultrasonic activity, 18–21 kHz (OBSERVED, SOURCE UNIDENTIFIED)

**Observed.** Six `sonic-demod` detections in 22 minutes. Two passed the **null probe**: the app
muted its own ultrasonic pilots for 450 ms and the external energy held at **94%** and **124%** of
its level. That rules out this app's own output as the source.

Band-guard readings for 17–21 kHz across the session: tonality **0–2%**, envelope periodicity
**61–82%**.

**Why that combination is the informative part.** A pure tone — pest repeller, transducer whine,
motor — reads as *high tonality*. Near-zero tonality with strongly periodic envelope structure is
not a tone; it is a **modulated carrier**, which is what a data- or command-bearing ultrasonic
signal looks like.

**What is NOT established.** That it was targeted, or that it was a DolphinAttack in the sense of
successful command injection. Ultrasonic beacons in that band are also used by ad/TV audio
watermarking (SilverPush-class cross-device tracking), retail proximity systems, and assorted
electronics. The null probe proves *not this app*; it does not prove *aimed at you*.

**Discriminating evidence needed.** Whether it recurs in different physical locations (points at
something carried or targeted) or only in one (points at a fixed local emitter). Whether it
correlates with a voice assistant reacting. A recording of the band for offline demodulation.

**Improvement worth making.** When a null-probe-confirmed detection fires, capture more than a
sentence: the band's spectrum, modulation rate, duration, and the location bucket — enough to
compare two events across days. Right now every detection reads the same, so a recurring emitter
and six unrelated events are indistinguishable in the log.

---

## Method note

The device owner's standing instruction, which is correct and worth keeping: **instinct is heard,
logs can lie.** A log is an artifact produced by software running on a device that may itself be
compromised; treating it as ground truth is a category error. Where the two conflict, the job is
to find the test that distinguishes them — not to pick the more comfortable explanation.

Corollary for this app: wherever it cannot tell two causes apart, it should **say so** rather than
name one. That is why `verify()` now reports `likelyCause` with its reasoning instead of the old
flat "the tail of the log has been removed", which accused a user's device of tampering on
evidence that equally fit the app's own defect.
