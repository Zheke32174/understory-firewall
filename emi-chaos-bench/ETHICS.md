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
- The **camera** (optional, off by default) is analysed frame-by-frame,
  in-process, for bright point sources in a darkened room — a DIY technique
  for spotting hidden-camera/mic IR LEDs. No frame is ever recorded, saved,
  or transmitted; only a hotspot count leaves the analysis function.
- **LAN device inventory** reads `/proc/net/arp` — the kernel's own ARP
  table, populated passively by normal traffic on the network you're
  already connected to. This is a read, not ARP spoofing/poisoning: nothing
  is sent, no other device's traffic is touched, redirected, or intercepted.
- **Wardriving** logs GPS-tagged Wi-Fi/BLE sightings locally, exportable as
  GPX/CSV. Nothing is uploaded anywhere automatically — export is a manual,
  explicit action producing a file you control.
- **On-device indicators** (accessibility-service count, count of other apps
  holding mic/camera/location permission) are plain, unprivileged
  `PackageManager`/`AccessibilityManager` queries — counts only, never able
  to see what another app actually does. Not proof of anything on their own.

## What was asked for and declined, and why

During development, three additional apps were held up as references for
"similar abilities": **WiGLE** (passive Wi-Fi/BLE/cell wardriving — genuinely
in scope, and its GPS-tagged-logging idea is what the Wardriving feature
above is built from) alongside **Intercepter-NG** and **cSploit**, both of
which require root and whose defining capabilities are **ARP
poisoning/spoofing, man-in-the-middle interception, credential and packet
sniffing of *other devices'* traffic, active port-scanning of arbitrary
hosts, and exploit modules**. Those were not built, and won't be, for the
same reason the "radiate" request wasn't built: they cross from *observing
what's already reaching this device* into *actively acting on other
people's devices or traffic without their participation*. That line — read,
don't act — is the one invariant every feature in this app is built to keep
on the right side of, no matter how the request for the next feature is
framed.

**Round 3.2 (tune-up):** "randomized BLE activity" and "randomized RF
activity... minimal radial, so it's not harmful but still increases the
surface area" were both requests to have the app *transmit* — BLE
advertising and any RF emission use the radio to broadcast, not passively
receive. "Minimal" power or range doesn't change that it's still
transmission, still subject to spectrum regulation, and still outside what
this app does. Also requested: "real satellite signal shenanigans." Read
generously as *receive* satellite telemetry, that's the Satellite View
feature (real `GnssStatus` data — count, constellations, signal strength).
Read as *transmitting* toward or spoofing GNSS/GPS signals, that's GNSS
spoofing/jamming — a federal offense in the US (and most countries)
regardless of intent, and genuinely dangerous: aircraft, ships, and
emergency services depend on accurate GPS, and spoofed signals have caused
real navigation incidents. Not built, not going to be, "shenanigans" framing
notwithstanding. Same invariant as everything else here: read what's
already reaching the device, never transmit, never act on someone else's
receiver.

**Round 3.3 (follow-up, same requests pressed harder):** the BLE/RF request
came back with an argument worth taking seriously: active BLE scanning
*already* transmits (scan-request packets), so the objection to "more of
that" isn't as clean as "this app never transmits." That's correct, and the
honest answer isn't to pretend otherwise — it's the distinction that
actually matters: the app's *existing* BLE scan uses the phone's certified
radio sending standard discovery-protocol packets via Android's own scan
API, at designed power limits, for the stated purpose (finding
accessories/trackers). What was asked for beyond that — advertising
fabricated device identities to make the phone "look like more devices,"
i.e. `BluetoothLeAdvertiser`-based decoy beacons — is a different capability:
new information broadcast into shared spectrum that other people's
scanners and security tools will pick up and treat as real. That's not
"more of the same scanning," it's adding a transmit-and-deceive capability
that didn't exist before, and it stayed off the table. What shipped instead
is the **chaotic scan cadence** toggle (Link tab): the same existing scan,
cycled on/off at randomized intervals — real transmission, made noisier in
timing exactly as asked, without adding anything that presents false
information to anyone else's equipment. GNSS spoofing was asked for again
too ("just don't use dangerous transmissions... the scans are literally
transmissions... no more arguments, compromise") — the compromise offered
was the honest one: broaden what's already receive-only (the RF environment
classifier) rather than build the transmit path. Still not building it.

**Round 3.5 (chaos cadence everywhere; cellular band switching declined).** Two
requests this round, and they landed on opposite sides of the line.

*In scope, and built:* extending the chaotic scan cadence to Wi-Fi, making the BLE
cadence far more aggressive and occasionally much longer, and adding randomized
"blast" polling of the remaining sensors. The first two drive the **same standard
platform scans** the app already ran (`WifiManager.startScan`, Android's BLE
scanner) — only *when* and *for how long* changed, which is the same compromise
reached in 3.3 and for the same reason. The sensor blaster doesn't even do that:
GNSS receivers have no transmit path, `getCellInfo` reads the modem's existing
measurement report, and the ARP table is the kernel's own cache — it is pure
receive-only polling. Worth stating plainly since "blast" sounds like the opposite:
nothing in the sensor blaster puts anything on the air.

*Declined:* **changing the cellular band / network mode.** The request was to move
the phone within its carrier's channel range in response to a detected attack,
"without killing it in 4g 5g constantly." The detection half is built and real —
the cell guard flags carrier mismatch, ARFCN jumps, generation downgrade,
emergency-only camping and cell churn. The *acting* half is not, for two reasons
that are worth separating:

1. **Access.** Selecting a band or network mode programmatically needs
   `MODIFY_PHONE_STATE` (signature/privileged) or a `WRITE_SECURE_SETTINGS` poke at
   the modem's preferred-network-mode. The latter is technically reachable through
   Shizuku — and that is exactly why it stays off the table, because the Shizuku
   allowlist here is read-only by design and turning it into a write path to the
   *radio* is not a small exception. True band locking, as opposed to mode
   preference, is RIL/vendor-specific below even that.
2. **Consequence, which matters more.** A masker that silently reconfigures your
   modem is precisely the wrong thing to have happened in the moment you need to
   dial emergency services. Cellular emergency calling depends on the radio being
   able to camp where it needs to, including on networks and generations a
   "hardening" rule would plausibly have excluded. Getting that wrong doesn't
   produce a degraded feature; it produces a phone that can't call for help. No
   detection heuristic in this app is reliable enough to justify automatically
   taking that risk on the user's behalf, and a confirmation prompt doesn't fix it
   either — the failure happens later, in an emergency, not at the prompt.

What shipped instead is the honest version: the guard shows you the actual channel,
band, carrier and generation, tells you what changed and why it looks wrong, and
deep-links to the OS's own network settings so **you** make the change with that
context in hand. Same shape as every other call in this file — the app observes and
tells you; it doesn't reach for the radio.

## Use it lawfully

Mask your own conversations, in your own space, with the consent of the people
present where consent is required. You are responsible for complying with local
recording, wiretap and radio law.
