# EMI Chaos Bench — Detect Edition

A local, on-device **audio voice-masker with a passive counter-surveillance
detection layer**. It synthesises a dense field of interference-styled sound
sources (30+), driven by chaos attractors and the phone's own motion, to
defeat the *intelligibility* of speech picked up by a nearby microphone —
and it listens back: mic-based voice/ultrasonic-injection detection,
Wi-Fi/BLE anomaly scanning, thermal and cellular (IMSI-catcher) heuristics,
fused into one anomaly score, plus an optional link out to EFF's Rayhunter
and a Shizuku-gated read-only diagnostics panel.

> **Baseband audio model — it does not radiate, and nothing here jams, spoofs,
> or advertises a fabricated identity.** Every "RF", "radar", "TDMA", "spur"
> or "magnetron" *source* is an *audio* model of what that interference
> sounds like — nothing is transmitted over the air. Every *detector* (mic,
> sensors, cell heuristics, Shizuku diagnostics) is receive-only. The one
> exception, and it's a narrow one: **active BLE scanning** (Link tab) uses
> the phone's own radio to send standard scan-request packets — the exact
> same standard-protocol chatter any Bluetooth app does for discovery, at
> the phone's already-certified power limits, via Android's own scan API.
> An optional "chaotic cadence" mode (3.3) randomizes its on/off timing.
> That's it — no beacon advertising, no fabricated device identities, no
> jamming, no GNSS spoofing, and that won't change no matter how the next
> feature request is framed. See [ETHICS.md](ETHICS.md).

This edition expands the original single-source noise maker first into a
sensor-aware, accessory-connected instrument (2.0), then into a passive
detection instrument (3.0). It grew out of studying the feature surface of
BLE/Wi-Fi field tools (accessory pairing, sensor telemetry, profiles,
geofencing, anomaly detection) and porting those *interaction and detection*
ideas — never any transmit capability — onto an audio masker.

## 3.7 — Pulse

**Mic: diagnosed from the diagnostic dump, and it was never a permission problem.**
`NotReadableError` / "Could not start audio source" with `recordAudioGranted: true` on
Android 16 (SDK 36) is Android's **foreground-service type** rule: from Android 11 the mic is
gated on the FGS *type*, not only on `RECORD_AUDIO`. `MaskerService` declared
`mediaPlayback` only, so with the masker running the OS refused capture — and WebView
surfaces that refusal as a bare NotReadableError with no hint. Now declares
`mediaPlayback|microphone` with `FOREGROUND_SERVICE_MICROPHONE`, claimed defensively (a type
you lack the permission for throws on 14+). A new native `probeMic()` opens an `AudioRecord`
directly and reports the real cause — who else is recording, whether the mic is
system-muted, whether the OS can capture at all — so the toast now names the actual problem
instead of guessing.

**Screen chaos did nothing — real bug.** `ScreenChaos.tick()` was driven from `schedule()`,
which only runs inside the audio callback, so it never fired unless the masker was already
playing. Moved to the display loop (along with the governor). Verified animating with the
masker stopped.

**Dhizuku could never have worked.** The tier used `Class.forName("com.rosan.dhizuku.api.Dhizuku")`
— but that class lives in the **client library a consuming app bundles**, not inside the
Dhizuku app, so the lookup always failed in our process and the tier reported "absent" no
matter what was installed. Now a real dependency (`Dhizuku-API:2.5.3`, pinned: 2.6.0 needs
compileSdk 37, 2.5.4+ ship Java 21 bytecode).

**Force-stop protection no longer wants this app to be device owner.** It now routes through
Dhizuku's own device-owner identity — wrapping the `device_policy` binder through Dhizuku and
using *its* admin component — so the protection works without the invasive self-provisioning
path. Self device-owner is listed for completeness and is not what any button does; it needs a
device with no accounts and a factory reset to undo, which is disproportionate for a masking
app.

**Chaos pulse — built from your observation that the BLE cadence behaves better with
Bluetooth OFF.** Identified: with Bluetooth off, `getBluetoothLeScanner()` returns null, so
the native scan returns instantly having touched nothing, and the cadence runs **completely
unthrottled**. With Bluetooth on, Android's BLE scan limiter (~5 starts per 30s) silently
clamps it — the same invisible-throttle failure as the Wi-Fi budget. So the good part was
never the Bluetooth activity; it was the **pure timing chaos**, which the radio was only
getting in the way of.

That is now a standalone engine with no radio dependency, running **simultaneously** with
real BLE scanning rather than instead of it. Measured **568 pulses/sec** at full magnitude
against the BLE limiter's 0.167/s — roughly **3400×**. Each pulse reseeds chaos cores,
perturbs mash dials and drives the sensor bus.

**Wardriving diagnostics.** Since the failure mode is silence, there's now a Diagnostics
button that names the cause: location services off (Android returns *zero* Wi-Fi results when
device location is disabled, regardless of app permissions — the most likely remaining cause),
missing precise-location, Wi-Fi off, no GPS fix, scan budget spent, or healthy.

**Frida detection expanded, and each hit now names what matched** — listening ports
(27042/27043/27047), Frida thread names in *this* process (`gum-js`, `gmain`, `gdbus`),
writable+executable mappings, and specific binary paths. A bare "possible Frida" is
unactionable; an unrelated process on 27042 is the common false positive, while a named
`gum-js` thread inside our own process is much harder to explain away. The panel now says
what to do if it's genuine — and the app deliberately still does **not** retaliate, self-kill
or crash on detection, because those are trivially bypassed by the tooling they target and
turn a false positive into a bricked app.

## 3.6.1 — fixes found by adversarial review and a user bug report

**Wardriving stopped logging (reported).** Traced to a resource conflict I introduced across
3.4–3.6, not to the wardriving code. Android throttles `WifiManager.startScan` to **4 requests
per 2 minutes** and does *not* error when you exceed it — it silently returns the previous
cached results. 3.4 gave wardriving a 15s auto-scan (8 per 2 min, over budget on its own),
then 3.5/3.6 added the chaotic Wi-Fi cadence, the combined scanner and the sensor blaster as
further consumers of the same four slots. The one feature that genuinely needs *fresh* results
got starved, and the silence made it look like a bug in wardriving.

Now every Wi-Fi scan goes through a shared budget: wardriving is `critical` and always gets
slots, the chaos scanners are `chaos` and only consume spare capacity, wardrive's own interval
moved to 32s (just under the cap instead of double it), and the panel shows scans-used plus a
plain-language reason — because an invisible throttle was the actual defect.

**DDC loader was completely dead (critical, found by review).** The biquad stability check had
an inverted sign: for `y = b0x + b1x₁ + b2x₂ + a1y₁ + a2y₂` the Jury condition is
`|a1| < 1 − a2`, and it said `1 + a2`. For a normal high-Q audio section (a2 ≈ −0.98) that
demanded `|a1| < 0.02` where the true bound is 1.98 — so it rejected **5 of the 6 sections** in
the bundled file and the loader could never succeed. Verified against actual pole magnitudes;
the corrected test still rejects a deliberately divergent section at |z| = 1.18.

**Bundled DDC and IR were unreadable on-device.** The page loads from `file:///android_asset/`,
and WebView's `allowFileAccessFromFileURLs` defaults to false, so `fetch()` to a sibling asset
is blocked by same-origin — silently, with only a console error. Fixed by reading assets
natively across the bridge (restricted to `dsp/`) rather than the two worse options: enabling
that flag re-opens a known local-file exfiltration hole, and moving to `WebViewAssetLoader`
would change the page's *origin* and orphan every saved profile in localStorage.

**Audio feedback loop through the rack.** The capture ring was being filled *after* BadJack,
but the granular and glitch modules re-read that ring as a source — putting the rack's gain
stages inside their own feedback path. The ring is now filled pre-rack, which also makes the
guards watch the stage they can actually steer (they correct by rerolling chaos dials; no
chaos reroll can undo a rack setting).

**Infrasound guard was mis-calibrated.** Its decimated ring was fed once per audio buffer with
a hard-coded assumption about buffer size, so its real sample rate — and therefore every
lag→frequency mapping derived from it — drifted with whatever buffer the device chose.
Decimation now counts real samples, giving exactly sr/256 = 187.5Hz over a 5.5s span, and lags
are computed *from* that rate: 0.70–18.75Hz.

**Avocado reset now clears its audio buffers**, so power-cycling the rack no longer replays the
previous session's samples.

**ADB is a real tier now, not an instructions screen** — and this corrects something 3.6 got
wrong. `android.permission.DUMP` is declared `signature|privileged|**development**`, and that
development flag means `adb shell pm grant <pkg> android.permission.DUMP` works for an ordinary
app. Once granted it **persists across reboot and needs no helper process**, which makes
in-process self-dump the strongest *durable* diagnostics tier — stronger than Shizuku, which
dies on reboot when started over adb. Same fixed read-only allowlist discipline.

## What's new in 3.6 — BadJack

**Three independent scanners, staggered.** BLE-only, Wi-Fi-only, and a new **combined**
cadence that re-rolls per burst whether it drives BLE, Wi-Fi, or both. Three independent
random processes on three independent clocks beat one process; **Arm all three** staggers
the starts by random offsets, because cadences kicked off in the same millisecond share a
phase and their combined activity would come out as a regular comb instead of chaos.

**Chaos governor — self-regulating without ever reducing the chaos.** It never touches the
audio engine, randomizer, modulation matrix or any demod guard. It only reshapes the *radio
duty cycle*, and only on measured evidence: battery temperature, charge level, the rate at
which Android is silently dropping our scan requests (an over-eager scanner doesn't scan
more, it just gets ignored while still costing power), and audio-callback overrun.

> Verified, not asserted: at maximum de-rating the `marathon` mode drops from 12.9% to 1.9%
> and `lurk` rises from 13.1% to 33.4% — the duty cycle genuinely eases — while Shannon
> entropy of the mode distribution only falls from 2.248 to 2.019 bits and **all five modes
> stay reachable at every level.** Reshape, not collapse.

**Nine independent spectrum band guards, infrasound → ultrasound.** The global guard asks
"is the whole output predictable?"; these ask it per band, because a band-limited listener
filters to the slice they care about first, so one tidy band is all they need. Per band:
**tonality** (has this band collapsed to a steady tone?) and **envelope periodicity** (is its
loudness pulsing on a schedule?), with band-targeted correction that rerolls only the dials
shaping that band.

Getting this right took four rounds of unit-testing against synthetic signals, and each round
caught a real defect that would have shipped as *a guard confidently naming the wrong band*:

| Defect found by testing | Why it was wrong | Fix |
|---|---|---|
| Waveform autocorrelation per band | A bandpass output oscillates near its own centre frequency no matter what you feed it — it was measuring the **filter's ringing**, not the content. Chaotic output scored a bogus 87% "periodic". | Replaced with envelope coefficient-of-variation, normalised against the Rayleigh value (0.5227) that narrowband *noise* produces. |
| Envelope lags fixed across all bands | Testing a 60Hz-wide band at lags corresponding to 146Hz+ — frequencies its envelope physically cannot contain. | Lags scaled to each band's bandwidth; too-narrow bands report `n/a` instead of a wrong number. |
| Single 2-pole bandpass | Only 12dB/octave, so a loud pure tone leaked into *every* band strongly enough to trip them all. | Cascaded to 4-pole (24dB/oct); f0 clamped below 0.40·sr where the RBJ equations degrade. |
| Filter startup transient | From zero state a narrow low-frequency section spends most of a 21ms window settling; a pure 150Hz tone read **0%** tonal when it should read ~100%. | Warm-up pass over preceding samples; envelope follower seeded at steady state. |
| 43ms window for 20–300Hz | To reject a 150Hz carrier's ripple the follower must sit below ~40Hz, but the noise envelope fluctuates faster than that — so it removed the very fluctuation that distinguishes noise from tone, and **broadband chaos falsely tripped sub-bass and bass.** | Dedicated 4:1-decimated ring, 4096 samples ≈ 341ms, for bands below 1.5kHz. |

Final state: silent on the masker's own broadband chaos, and correctly localising pure tones
at 50Hz, 150Hz, 2kHz and 19kHz, plus a tone buried in noise.

**BadJack DSP rack (new DSP tab)** — a stage-for-stage port of the supplied
`BadJack_HiFi_Avocado_DynBass_DRX.eel` LiveProg script: HiFi rescue (bad-jack channel blend,
mono bass, one-pole bass/vocal/air/harshness shelves) → Avocado glitch/repeat/reverse/duck →
Dynamic bass → DRX 3-band transient dynamics → trim + soft limiter. Plus a **DDC/VDC biquad
loader** and the bundled **48kHz stereo impulse response** via a ConvolverNode.

> **The rootless-JamesDSP exposure is deliberately not reproduced.** Rootless JamesDSP reaches
> system-wide audio by attaching an AudioEffect to the global output mix, which needs a
> signature-level permission (DUMP, via Shizuku/adb). That's what lets it EQ other apps — and
> it's also the exposure: a permission that broad, held persistently, means anything that
> compromises that app inherits a tap on every sound the device makes, calls included. This
> rack is an in-process pass over our own generated buffer. No AudioEffect, no global session,
> no DUMP, no Shizuku, no access to other apps' audio, nothing to inherit. The trade is stated
> plainly rather than hidden: these effects shape the masker's output and nothing else.

DDC files are **pole-stability-checked before they touch the audio path** — a file in the
opposite sign convention, or a malformed one, would otherwise be an instant runaway.

**35 preset modulation matrices, auto-swapped per profile.** With auto-swap on, loading a
builtin draws a fresh routing, so the modulation *topology* changes with the profile rather
than only the dial values. Profiles you saved keep their own matrix. A preset naming a dial
this build lacks drops that route instead of failing.

**Side-channel guard.** MEMS gyros/accelerometers have mechanical resonances — sound near
19–20kHz can couple in and appear as motion that never happened (Son et al., *Rocking Drones
with Intentional Sound Noise*; Trippel et al., *WALNUT*). Three signatures are fused, never
used alone: stream going **narrowband**, gyro and accelerometer **disagreeing** about whether
the phone is moving, and **repeated identical samples**. Plus **runtime hijack** detection —
the primitives the engine depends on and the bridge methods themselves are snapshotted at load
and re-checked for still being native code. Everything reports; nothing blocks.

**Screen chaos.** Brightness, colour temperature, saturation and slight hue drift driven off
the same chaos cores as the audio, every axis clamped (brightness only ever dims to 72% of
your own setting, never brightens past it) and slew-limited. The slew limit is a **safety
bound, not a taste setting**: fast luminance oscillation in the ~3–30Hz range is a
photosensitive-seizure risk, so the rate of change is held far below it. This app's window
only — never the system brightness setting.

**Privileged-access tiers: Shizuku → Dhizuku → Device Owner → ADB.** These are **not
interchangeable**, and the UI says so rather than implying a clean fallback:

- **Shizuku** runs as the adb-shell UID and is the *only* tier that can serve the read-only
  `dumpsys` diagnostics.
- **Dhizuku** is backed by device owner, and its process API spawns inside a normal app UID —
  so shell output through it comes back **no more privileged than ours**. It genuinely cannot
  replace the diagnostics if Shizuku goes away. Nothing can; that capability leaves with it.
- What Dhizuku and **device owner** give instead is what Shizuku can't:
  `setUserControlDisabledPackages` (API 30+), the one supported mechanism on stock Android
  that makes an app resistant to being **silently force-stopped**. That's the real answer to
  "can't be tampered with without appops".
- **Device admin** alone is weaker — it greys out the Settings buttons, but adb can still stop
  the app.

The declared device-admin policy set is deliberately minimal: no wipe, no password control, no
login monitoring. Dhizuku is reached by reflection rather than a compile-time dependency, so a
device without it degrades to "not available" instead of crashing at startup.

## What's new in 3.5 — Blackout

**Chaotic cadence is now a shared engine, and much more aggressive.** The BLE
timing-randomizer from 3.3 became `makeChaosCadence`, and every cycle now independently
redraws a *mode* instead of sampling one fixed range: **sprint** (sub-second rapid-fire),
**normal**, **long** (multi-second), **marathon** (up to a full minute continuous), or
**lurk** (a glance, then up to 30s of silence). Weighted, not uniform, so the duty cycle
stays lumpy instead of averaging out into something predictable.

- **Wi-Fi chaotic cadence** (Detect tab) — the same treatment for Wi-Fi. Same standard
  `WifiManager` scan every Wi-Fi picker runs, just at randomized times and durations.
  Android hard-throttles scan requests, so a "marathon" is a long *window* during which
  requests are issued, not a way to scan faster than the OS permits — excess requests are
  silently dropped by the platform, never escalated.
- **BLE cadence** now uses the same engine, so sessions range from ~150ms to 60s.
- **Sensor blasts** (Sensors tab) — the idea applied to everything else the app can read.
  Each burst hits a randomized subset of the native reads (GNSS status, cell info, thermals,
  raw sensor snapshot, LAN ARP table, cell guard), a randomized number of times, in
  randomized order. **Unlike BLE/Wi-Fi, nothing here goes on the air at all** — these are
  pure receive-only reads of state the OS already holds. Two payoffs: a denser, less
  predictable entropy stream into the audio engine, and much tighter time resolution for
  the detectors.

**Demod guard now runs two independent views.** The existing check is waveform
autocorrelation — what a coherent/FM-style recovery sees. The new one is the **AM /
envelope** view: rectify, low-pass, and read whatever rhythm is left, exactly like a plain
envelope detector. Those fail *differently* — a masker whose waveform is perfectly chaotic
can still be trivially AM-stripped if its **loudness** breathes on a schedule. An AM trip
fires a different burst that rerolls the level/drift dials shaping the envelope, not just
the carrier. Also reported: the **AM modulation index** (depth), since deep *and* periodic
is the genuinely demodulable combination — shallow or chaotic is fine.

> Verified by extracting the shipped `envelopeScore` and running it against synthetic cases:
> chaotic-carrier/periodic-envelope trips at 88%, while flat (9%), shallow-periodic (6%),
> chaotic-envelope (15%) and silence (0%) all correctly stay below threshold. Testing also
> caught a real blind spot — a sparse lag set missed envelope periods falling between its
> values — which is why the lag set is now dense.

**Cell guard (Detect tab) — emergency/push-channel attack detection.** Watches the cell the
phone is actually camped on, from the modem's own passive measurement report. Flags:

- serving cell reporting a **different carrier** than your own SIM,
- the **radio channel (ARFCN) jumping** while the carrier stays the same — being *pushed*
  onto a different channel,
- **generation downgrade** (5G/4G → 3G/2G — the classic step before interception, since 2G
  has no mutual authentication),
- **limited/emergency-only service** while the SIM is ready — a cell that accepted the phone
  but won't carry normal traffic,
- **rapid serving-cell churn**, expected while moving, suspicious while sitting still.

Silent-SMS (Type-0) checking is Shizuku-gated and reported honestly as a *hint*: Type-0 SMS
are consumed below the app layer and never reach any public Android API, so no app can see
one directly. All the check can do is report whether the SMS stack shows dispatch activity
you never saw a message for.

**Background resilience (Detect tab).** Foreground media-playback service now holds a partial
wake lock (without it, aggressive OEM dozing can stall the Web Audio callback with the screen
off — the masker goes quiet exactly when the room does), tracks its own running state, and
reports it. New panel shows foreground-service state, battery-optimisation exemption, app
standby bucket, background-restriction, notification permission and backup state, calling out
weak spots by name. `allowBackup` is now **off** with explicit `dataExtractionRules`: saved
profiles carry geofences and the Wi-Fi list carries which networks you trust — a map of where
you are and what you consider safe — so it never rides out in a cloud backup or restores onto
another device. The app can't grant itself any of the protections; **Request exemption** fires
the standard system consent dialog, which is the point — undoing them takes a deliberate
appops/settings change by a human at the device.

**Not built, and why (band switching):** the request included changing the cellular band
within a carrier's channel range. The app reads the band; it does not set it. See
[ETHICS.md](ETHICS.md) — programmatic band/network-mode selection needs privileged access this
app deliberately doesn't take, and a masker silently reconfiguring your modem is precisely the
wrong thing to have happened the moment you need to dial emergency services. The panel deep-links
to the OS's own network settings with the channel/band readout as context, so the change is
yours to make.

## What's new in 3.4 — Foxhunt

A follow-up round expanding what already shipped rather than adding new categories,
per explicit request: "do another round, see where you can improve what's already
there, expand on these BLE functions, on the other already existing ones."

**BLE (Link tab), expanded around the existing scan/GATT-inspect feature — no new
transmit capability, same standard active scan as before:**
- **Bonded devices panel** — lists Bluetooth devices already paired to the phone at the
  OS level (`BluetoothManager.adapter.bondedDevices`, read-only) with an "Add to list"
  button that folds one into the scan list without needing it back in discovery range.
- **RSSI history + sparkline** — every device's last ~24 RSSI readings, shown inline as
  a compact bar sparkline. Previously a re-seen device's RSSI silently never updated.
- **Foxhunt mode** — a per-device "Foxhunt" toggle that repeatedly re-runs the same scan
  and shows a live warmer/colder trend from the last two readings, for walking toward
  or away from a specific accessory. No new transmission — it's the existing scan on a
  tighter, single-device-focused cadence.
- **BLE scan log CSV export** — every sighting this session (time, name, address, RSSI,
  classification tag), exportable as a file you control, mirroring the wardriving export.

**Wi-Fi (Detect tab), expanded around the existing rogue-AP heuristics:**
- **Trusted-network allowlist** — a "Trust" button per scanned network, keyed by BSSID
  and persisted locally. Trusting a network silences the impersonation-style heuristics
  for it (Karma/multi-SSID, SSID-changed) since a network you've vouched for by its
  BSSID can't be spoofing itself; it does **not** silence WPS/open/WEP warnings, since
  those describe the network's own security posture, not whether it's the real one.
- **Wi-Fi scan log CSV export** — every scan-result sighting this session, same pattern
  as the BLE export above.

**Profiles (Profiles tab): geofenced auto-activation actually works now.** The UI copy
has claimed since 3.x that "geo-fenced auto-activation triggers when GPS enters a
profile's saved location radius," but `Scene.geoCheck()` was a no-op stub — the geo
data was saved on profile save, never read back. Implemented for real: gated by the
same Scene-scheduler switch as time-based cycling, computes haversine distance from
each GPS fix to every saved profile's stored point, auto-loads the nearest match on
entry, and won't re-trigger every GPS tick while sitting still inside one fence (only
on entry, or re-entry after leaving).

**App integrity: manual recheck.** The integrity check (signature/debugger/Frida/root)
previously only ran on a slow automatic cadence. A **Recheck now** button forces an
immediate check — useful right after attaching or detaching a debugger/hooking tool —
and re-arms the one-shot alert guard so a finding that clears and later reappears
alerts again instead of staying silenced by the first sighting.

**Still not built, same reasons as every prior round:** BLE beacon advertising, GNSS
spoofing/transmission, any real RF jam/transmit path. See [ETHICS.md](ETHICS.md).

## What's new in 3.3 — Ghost

**Found while reading code for this round, not requested — fixed anyway:** `builtinSnap()`
(profile loading) unconditionally forced every toggleable module on for every profile,
silently reintroducing the exact "everything on at once" CPU-load problem 3.2 had just
fixed — just triggered by loading any profile instead of Randomize-All. Now respects each
module's boot-time default, same as `build()`.

**More chaos, more vectors:**
- **Waveform swarm** — six independently-picked voices (sine/saw/triangle/square/pulse),
  each randomizable — a 5⁶ = 15,625-way combination before frequency/detune even enters it.
- **Partial sweep chaos** — sweep stubs with new random start/end/length on every attempt,
  often cut short mid-sweep, distinct from the existing continuous Sweep gen.
- **Two FM-demodulation "ghost voice" effects**, audio-domain models of the real technique
  (same category as radar-chirp/TDMA-buzz elsewhere here — nothing RF, pure Web Audio):
  a **frequency discriminator** (differentiator + envelope detector recovering a warbly
  "ghost" from an internally-synthesized FM carrier) and a **phase discriminator**
  (VCO + multiplier + LPF, quadrature-style).
- **Duophonic desync** — the classic 1970s mono-to-fake-stereo trick: delay one channel by
  fractions of a second, low-pass the other's treble, high-pass the delayed channel's bass.
- **Disruptor** — a shared, randomly-updating rate multiplier the three effects above read
  as an extra factor on their own rates: mostly near-normal, occasionally reversed
  (negative) or heavily over-accelerated, on its own unpredictable schedule.
- **10 more profiles** (16 total): Ghost station, Waveform lab, Storm front, Chaos vector
  overdrive, Insect hive, Submarine, Radio silence, Shepard spiral, Feedback chamber, and
  Total chaos (everything on — the same correctness-verified worst case as Randomize's
  100% setting).
- **Randomize intensity is a spectrum now** (10–100% slider, Conservative/Balanced/Total
  quick-picks) — 3.2 accidentally shipped a flat 70%-only default that dropped the "always
  literally everything" option; restored and widened.

**Passive analysis, in the spirit of Praat/Melodyne:** a **vocal spectral analysis** panel
— coarse pitch estimate plus the loudest spectral peak in each of three formant bands
(F1 ≈300–900Hz, F2 ≈900–2500Hz, F3 ≈2–4kHz, the "singer's formant") — reading the same mic
analyser the existing Broadband analyzer already used. Rough peak-picking, not lab-grade
LPC formant tracking, and said so in the UI copy.

**App integrity (anti-tampering, detect-and-report only):** a new `TamperGuard` checks this
APK's own signing-certificate hash, and looks for the common traces of a debugger, Frida
instrumentation, or root — the same category of check banking/DRM apps ship. Nothing here
blocks the app, alters behavior, or touches data; it only feeds a status readout.

**RF environment classifier:** a synthesis panel — Wi-Fi by band, BLE by classification,
active cellular generation, satellites in view — sorted from data every other panel is
already collecting. No new radio activity.

**On BLE/RF "activity" and "satellite shenanigans" (round 3.2→3.3 follow-up):** both were
requested again this round, more insistently, with the (correct) observation that active
BLE scanning already transmits. That's true, and it's why the "chaotic cadence" toggle
above exists — cycling the *existing, standard* scan on/off at randomized timing, using the
same protocol chatter any Bluetooth app already sends. What's still not built, and won't
be: fabricating BLE advertisements/decoy device identities (new information broadcast into
shared spectrum for other people's scanners to treat as real — categorically different from
discovery-protocol chatter), and anything that transmits toward or spoofs GNSS/GPS (a
federal offense and a genuine aviation/navigation safety hazard, "shenanigans" framing
notwithstanding). Full reasoning in [ETHICS.md](ETHICS.md).

## What's new in 3.2 — Churn (tune-up round)

**Two real bug fixes, reported after 3.1:**
- **Some sliders weren't auto-sliding.** The Boost/baseband and Output-DSP sections were
  deliberately excluded from the auto-masher/drift pool. They're back in — every dial in
  the app now participates in chaos churn.
- **Mic error still occurring.** Found a second, independent bug in the native permission
  handler: `onPermissionRequest` could call both `grant()` and `deny()` on the same
  request, which is invalid Android API usage. Fixed to be strictly one-or-the-other.
  `Mic.enable()` also now retries with plain `{audio:true}` if the stricter constraint set
  is rejected, and gives a clearer, scenario-specific error message (blocked / no device /
  busy / insecure context) instead of a generic "denied."

**More vectors to pull, more chaos categories, creative additions:**
- **Four more chaos vectors (C–F)**, on top of the original A/B — six live cores total,
  each an independently-picked attractor + rate, each routable into one of nine named
  modulation buses (amp, freq, filter, Doppler, glitch, formant, chorus, tilt, granular
  smear) at its own weight. New "Chaos vectors C–F" section.
- **16 new source modules**, each a genuinely different DSP technique, not a parameter
  clone: **Doppler pass** (a moving-source pitch-bend event), wow & flutter, comb flutter,
  granular smear, FM bell clangor, a Shepard-tone riser, a PLL lock/unlock simulator, a
  3-formant vowel morph, chorus swarm, a self-oscillating (internally limited) feedback
  howl, bit-reversal buffer glitch, spectral tilt sweep, wind gusts, metallic-strike modal
  resonance, insect-swarm chirps, and static crackle rain.
- **Demod guard**: watches the masker's own recent output for a strong, sustained
  autocorrelation peak — a sign it's settling into a too-regular, more easily filtered-out
  pattern — and responds with an unprompted, aggressive remodulation burst (reseeds every
  chaos core, hard-rerolls half the dials, spikes the mash rate) to keep it from ever
  sitting still long enough to be learned. Runs on the main thread off the existing
  capture buffer, not in the audio callback.
- **Randomize intensity — a spectrum, not a cap.** "Randomize everything" first shipped this
  round as flat 70%-odds-per-module, which quietly took away the old "always literally
  everything" behavior. Restored, and widened into a slider (10–100%) with
  Conservative/Balanced/Total quick-picks — 100% is exactly the original behavior. Default
  stays at 70% for the CPU-load reason below, but full control, nothing removed.

**Performance note (read if you're editing defaults):** with every module from every round
active at once, measured per-buffer audio cost hit ~78% of the real-time budget on average
and over 300% at peaks — real glitches on real phones. Fix: the 16 new modules plus the
chaos vector bank default to **off** at boot (the original ~22 keep their existing
default-on behavior unchanged); "Randomize everything" defaults to 70% odds per module but
the full 10–100% range — including "always everything," unconditionally — is one slider
away. Fresh-install performance is back to a healthy ~30% average / ~100% peak of budget.

**Satellite view (real GNSS telemetry, receive-only).** Satellite count, which
constellations (GPS/GLONASS/Galileo/BeiDou/QZSS/...), and per-satellite signal strength
(CN0) read straight from the phone's own `GnssStatus` — data the Web Geolocation API
doesn't expose but the OS already has. A GNSS receiver has no transmit path by design: it
only ever listens to satellites. **GNSS/GPS spoofing or jamming was explicitly requested
this round and declined** — beyond being federally illegal, it's genuinely dangerous to
aviation and marine navigation; framing it as "shenanigans" doesn't change either fact. See
[ETHICS.md](ETHICS.md).

**Wardriving actually works now.** Found three real bugs chasing a "doesn't work" report:
(1) the toggle didn't do anything to actually enable GPS or trigger scans, so it silently
logged nothing with zero feedback; (2) it then called a `Sensors.enable()` method that
wasn't exposed on the module's public API; (3) a network seen *before* the first GPS fix
landed got marked "already seen" and was permanently skipped, even after GPS became
available. All three fixed — flipping the Wardriving toggle now turns on Sensors/GPS and
Auto-scan itself, shows "waiting for GPS" vs. "logging," and retries anything seen too
early once a fix lands.

**Declined this round, and why:** "randomized BLE activity" and "randomized RF activity...
to increase surface area" were both requests to have the app *transmit* — BLE advertising
and any RF emission use the radio to broadcast, not just listen, regardless of power level
or how "minimal" the radius. That's the same line this project has held since the first
"radiate" request: read-only, no exceptions, no matter how the ask is framed. See
[ETHICS.md](ETHICS.md).

## What's new in 3.1

- **Fixed a real mic-permission bug**: `MainActivity` used to load the WebView before the
  async permission round-trip finished, so a mic-toggle tap that raced the OS dialog could
  get denied once and stay denied for the rest of that page's life (WebView caches the
  per-origin decision). Now the page doesn't load until permissions are settled, and the
  app reloads the WebView if mic permission is granted late (e.g. via Settings) to give it
  a clean shot. `Mic.enable()` also surfaces the real `DOMException` name instead of a
  generic "denied" toast.
- **Camera visual scan** — `getUserMedia(video)`, analysed frame-by-frame in-process (never
  recorded/saved): looks for bright point-source "hotspots" in an otherwise dark frame, a
  known DIY technique for spotting hidden-camera/mic IR LEDs (many phone sensors have weak
  IR-cut filtering).
- **LAN device inventory** — reads `/proc/net/arp` (the kernel's own table, no root, no
  spoofing) to list who's on your currently-connected network.
- **Wardriving** — GPS-tagged local log of Wi-Fi/BLE sightings, GPX/CSV export. Local-only;
  nothing uploads automatically.
- **BLE GATT inspection** — briefly connects to a picked device and reads its GATT service
  UUIDs for device-type fingerprinting (recognises a handful of SIG-assigned UUIDs,
  including Tile's).
- **Deeper Wi-Fi heuristics** — WPS-enabled and open/WEP network flags, plus Karma/rogue-AP
  detection (same BSSID advertising multiple different SSIDs).
- **On-device indicators** — accessibility-service count, count of other apps holding
  mic/camera/location permission, and battery drain rate: a different class of signal than
  RF (something already on this phone, not nearby).
- Barometer and ambient-light sensors added to the modulation matrix and anomaly fusion.
- See [ETHICS.md](ETHICS.md) for what was explicitly requested and declined this round
  (MITM/ARP-poisoning/packet-sniffing/exploit-module capability referencing Intercepter-NG
  and cSploit) and why.

## What's new in 3.0 — Detect

| Area | What it does |
|------|--------------|
| **Mic voice detection** | `getUserMedia` → in-process speech-band VAD (never recorded/stored/sent). Drives reactive masking (auto-arm / duck / boost on detected speech) and feeds the modulation matrix as sensor `mic`. |
| **Ultrasonic-injection detector** | Watches the mic's ≥18kHz band for sustained, speech-rate-modulated energy — the signature of DolphinAttack/SurfingAttack-style inaudible-command injection (an ultrasonic carrier demodulating in the mic's own nonlinearities). Heuristic, flags for you to verify. |
| **Broadband analyzer** | Full-range spectrum view of the mic input, or of a `spectrum_report` streamed in from a passive RF companion (e.g. an RTL-SDR node on the mesh). |
| **RF passive scan** | Wi-Fi scan heuristics (duplicate-SSID/different-vendor, sudden strong new AP, hidden-network count) plus BLE tracker fingerprinting (AirTag/Find-My, SmartTag-style manufacturer data, MAC-rotation correlation) and BLE spam-flood detection — all off scans Android already exposes. |
| **Sensor-fusion anomaly score** | Fuses thermal delta, cellular generation downgrade/isolation (IMSI-catcher heuristic), magnetometer deviation from its own rolling baseline, motion variance, and the trackers/ultrasonic flags above into one 0–100 score with haptic alerting. A hint to look closer, not a certified detector. |
| **Cross-device sensor mesh** | The Wi-Fi companion link now speaks a small JSON protocol (`sensor_report` / `anomaly` / `rayhunter_alert` / `spectrum_report`) so other phones, an OpenWRT router, or a laptop with a passive accessory can all contribute. Reference agents in [`mesh-node/`](mesh-node/). |
| **Rayhunter ingestion** | Ingests alerts from a real [EFF Rayhunter](https://github.com/EFForg/rayhunter) device via the reference relay script — this app doesn't reimplement IMSI-catcher detection, Rayhunter already does that properly. |
| **Shizuku diagnostics (optional)** | If you've separately set up [Shizuku](https://shizuku.rikka.app), a fixed allowlist of read-only diagnostics (telephony/connectivity dumpsys, system properties, a `/dev/diag` presence probe) is available. No free-form exec, no write path. |
| **Output DSP rack + boost** | Real Web Audio EQ/compressor/short convolution "space" on the master output, a movable **baseband channel** peaking filter (the app's own synthesis output — not the phone's cellular modem), and a boost stage up to **150%** gated by a fixed brickwall limiter so boost never just clips destructively. |

## What's new in 2.0

| Area | What it does |
|------|--------------|
| **30+ sources** | Original 15 (switching hash, arc, spurs, sweeps, digital bursts, resonant zaps, coil whine, geiger, S&H, mains hum, voice-babble, vocal-focus, chaos-audio, filter, crush/ring) **plus** TDMA/GSM buzz, inverter SPWM, plasma crackle, radar chirp, packet bursts, ultrasonic pilots, sub rumble, magnetron ripple, relay chatter. |
| **20 chaos attractors** | Lorenz, Rössler, Chua, Duffing, Hénon, Ikeda, logistic, tent, Bernoulli, standard map **plus** Clifford, de Jong, gingerbread, Tinkerbell, Gauss, sine, cubic, Thomas, Halvorsen, Sprott. |
| **Device sensors** | Gyroscope, accelerometer, magnetometer/heading, GPS speed/course/altitude, and network state are read as **inputs only** and normalised to −1..1. |
| **Modulation matrix** | Wire any sensor axis → any dial with signed depth. Tilt sweeps the filter, heading walks the spurs, speed opens the drive — the rig reacts to how you hold and move the phone. Shake = randomize. |
| **Accessories (BLE)** | Scan and link companion beacons/pucks. A linked accessory's RSSI feeds the entropy bus, or it acts as a remote start/stop trigger. BLE is used to **read** accessories, never to advertise or jam. |
| **Wi-Fi companion** | Connect a LAN WebSocket node (e.g. an ESP32 sensor puck) that streams sensor JSON in and takes profile/trigger commands out. Audio never leaves the device. |
| **Haptics** | Configurable vibration feedback on mash, overload and profile change, with intensity control. |
| **Profiles** | Save/load full-state presets (dials, toggles, mod-matrix, chaos maps, speed). Six built-ins (Boardroom, Café, Vehicle, Server room, Interview, Panic). Crossfade **morph** on load, JSON export/import, and a **scene scheduler** that cycles profiles on a timer with optional GPS geofencing. |
| **Radio environment** | Network type, downlink and cell signal level (where the platform exposes them) become another entropy channel and can auto-select a profile. |

## Architecture

The entire app is one self-contained file: [`app/src/main/assets/index.html`](app/src/main/assets/index.html).
It runs three ways, degrading gracefully:

1. **Native Android** — a thin `WebView` shell exposes `window.EMIBridge`
   (Kotlin `@JavascriptInterface`) for real gyro/magnetometer sampling, BLE
   scanning, telephony/network reads, precise haptics and a media-playback
   foreground service.
2. **Mobile browser** — falls back to the Web platform: `DeviceMotion` /
   `DeviceOrientation`, `navigator.geolocation`, `navigator.bluetooth`
   (Web Bluetooth where available), `navigator.vibrate`, `NetworkInformation`.
3. **Desktop / no sensors** — simulates accessory discovery and keeps every
   panel interactive so the UI is always testable.

```
app/src/main/
  assets/index.html                 the whole app (audio engine + UI + all subsystems)
  java/com/ant/emichaosbg/
    MainActivity.kt                 WebView host + runtime permissions
    EmiBridge.kt                    window.EMIBridge: sensors, BLE/Wi-Fi scan, cell/thermal, haptics, fg-service
    ShizukuBridge.kt                window.EMIShizuku: optional privileged-diagnostics status/permission/run
    ShizukuUserService.kt           runs under Shizuku's granted privilege — fixed read-only command allowlist
    MaskerService.kt                media-playback foreground service (background mode)
  aidl/com/ant/emichaosbg/
    IShizukuDiagService.aidl        binder contract for the Shizuku diagnostics helper
  AndroidManifest.xml               permissions (all input-side) + components
  res/                              icon, theme, strings
mesh-node/                          reference companion agents (OpenWRT, Rayhunter relay, generic template)
```

## Build

```bash
./gradlew assembleDebug
# APK at app/build/outputs/apk/debug/app-debug.apk
```

`minSdk 26`, `targetSdk 34`, Kotlin, AndroidX. One optional third-party
dependency pair: `dev.rikka.shizuku:api` / `:provider` (Shizuku client
plumbing — inert unless the user has separately set up Shizuku).

## Try the app without building

Open `app/src/main/assets/index.html` in any modern browser. Press **Start**
(or Space). Enable **Sensors** on a phone browser to feel the motion coupling.

## Permissions, and why

Every permission is for reading an input or for background audio — there is no
transmit path.

- `FOREGROUND_SERVICE` / `..._MEDIA_PLAYBACK`, `POST_NOTIFICATIONS`, `WAKE_LOCK` — keep the masker audible when backgrounded.
- `VIBRATE` — haptics.
- `BLUETOOTH_SCAN` (`neverForLocation`) / `BLUETOOTH_CONNECT` — enumerate/link accessory beacons, fingerprint tracker advertisements (read RSSI/manufacturer bytes only).
- `ACCESS_FINE/COARSE_LOCATION` — GPS as a modulation source and profile geofencing; also required by Android for BLE scan, Wi-Fi scan, and cell-signal reads.
- `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `HIGH_SAMPLING_RATE_SENSORS` — network entropy, Wi-Fi anomaly scan, high-rate gyro.
- `RECORD_AUDIO` — mic voice-activity + ultrasonic-injection detection. Analysed in-process only; never recorded, buffered to disk, or sent anywhere.
- `READ_PHONE_STATE` — cell generation/neighbor-count read for the IMSI-catcher heuristic panel.
- `INTERNET` — **LAN WebSocket mesh link to companion nodes only** (another phone, an OpenWRT router, a Rayhunter relay). No audio, mic data, or telemetry is sent to the internet.

Shizuku's own permission (granted through the separate Shizuku app, entirely
opt-in) gates the read-only diagnostics panel — see
[`ShizukuUserService.kt`](app/src/main/java/com/ant/emichaosbg/ShizukuUserService.kt)
for the exact fixed command allowlist.

## License

MIT — see [LICENSE](LICENSE).
