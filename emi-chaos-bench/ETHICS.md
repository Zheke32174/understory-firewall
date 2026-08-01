# Scope & intent

EMI Chaos Bench is an **audio** privacy tool. Read this before assuming it is
something it is not.

## It does not radiate

The names of the sound sources — "TDMA/GSM buzz", "radar chirp", "magnetron
ripple", "wandering spurs", "coil whine" — are **audio impressions** of what
those forms of electromagnetic interference *sound like* when demodulated. They
are generated entirely inside the Web Audio graph and come out of the speaker
as sound. **No radio frequency energy is produced, and the app contains no
transmit path of any kind.**

Building a device that actually radiates to interfere with radio, cellular,
GPS, Wi-Fi or Bluetooth (a "jammer") is illegal in most jurisdictions. This
project is not that, does not become that, and pull requests that add a real
transmit/jam capability will be rejected. **This has been asked for directly
during development — including "add a radiate option behind a disclaimer" —
and declined for the same reason a disclaimer doesn't legalize a jammer or
change who's liable when it takes out someone else's phone, Wi-Fi, or
emergency comms.** The line holds regardless of how the request is framed.

## What it is for

Masking the *intelligibility* of speech to a microphone that is near the
speaker — the same idea as a sound-masking "babble" generator or a white-noise
machine, but denser and speech-shaped. It only affects what a nearby mic picks
up. It has no effect beyond earshot.

## The radios and sensors are inputs, not weapons

Bluetooth, Wi-Fi, GPS, cellular and the motion sensors are used **read-only**:

- Bluetooth LE is *scanned* to list nearby accessory beacons and fingerprint
  tracker advertisements (AirTag/Find-My, SmartTag-style manufacturer data);
  their RSSI can feed the noise engine's entropy. The app never advertises,
  attacks, or spoofs.
- Wi-Fi scan results (SSID/BSSID/level) are read for the rogue-AP heuristic
  panel — a normal platform scan, never an active attack against a network.
- Wi-Fi is also used for an optional **LAN WebSocket mesh** link to companion
  nodes. No audio or personal data is sent to the internet.
- GPS / cell / network / gyro / magnetometer are normalised to a −1..1 signal
  that modulates audio dials AND feed the anomaly-fusion score. Location
  never leaves the device except to select a local profile (geofencing) that
  you saved yourself, or to a mesh node you've explicitly connected to.
- The **microphone** is analysed for voice-activity and ultrasonic-injection
  detection entirely in-process — raw audio is never recorded to disk,
  buffered beyond the current analysis window, or transmitted anywhere. Only
  two derived numbers (a speech-band level, an ultrasonic-band flag) ever
  leave the analysis function.
- **Shizuku diagnostics** (fully optional, requires the user to separately
  install and configure Shizuku) run a *fixed allowlist* of read-only shell
  commands — `dumpsys telephony.registry`, `dumpsys connectivity`,
  `getprop`, and an ls-only presence probe of `/dev/diag` — never free-form
  execution, never a write path. See
  `app/src/main/java/com/ant/emichaosbg/ShizukuUserService.kt`.
- **Rayhunter integration** ingests alerts from a real, separately-running
  [EFF Rayhunter](https://github.com/EFForg/rayhunter) device via a
  companion relay script. This project does not reimplement IMSI-catcher
  detection — Rayhunter already does that, correctly, and is the tool to
  trust for it. The relay only reads Rayhunter's own web UI.
- Every anomaly signal here (cell downgrade, magnetometer deviation, thermal
  delta, BLE tracker rotation, ultrasonic modulation) is a **heuristic**, not
  a certified detector. Treat a high score as "go look closer," not proof.

## Use it lawfully

Mask your own conversations, in your own space, with the consent of the people
present where consent is required. You are responsible for complying with local
recording, wiretap and radio law.
