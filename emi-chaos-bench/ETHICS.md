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
transmit/jam capability will be rejected.

## What it is for

Masking the *intelligibility* of speech to a microphone that is near the
speaker — the same idea as a sound-masking "babble" generator or a white-noise
machine, but denser and speech-shaped. It only affects what a nearby mic picks
up. It has no effect beyond earshot.

## The radios and sensors are inputs, not weapons

Bluetooth, Wi-Fi, GPS, cellular and the motion sensors are used **read-only**:

- Bluetooth LE is *scanned* to list nearby accessory beacons; their RSSI can
  feed the noise engine's entropy. The app never advertises or attacks.
- Wi-Fi is used for an optional **LAN WebSocket** link to a companion sensor
  node. No audio or personal data is sent to the internet.
- GPS / cell / network / gyro / magnetometer are normalised to a −1..1 signal
  that modulates audio dials. Location never leaves the device except to select
  a local profile (geofencing) that you saved yourself.

## Use it lawfully

Mask your own conversations, in your own space, with the consent of the people
present where consent is required. You are responsible for complying with local
recording, wiretap and radio law.
