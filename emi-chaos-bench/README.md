# EMI Chaos Bench — Detect Edition

A local, on-device **audio voice-masker with a passive counter-surveillance
detection layer**. It synthesises a dense field of interference-styled sound
sources (30+), driven by chaos attractors and the phone's own motion, to
defeat the *intelligibility* of speech picked up by a nearby microphone —
and it listens back: mic-based voice/ultrasonic-injection detection,
Wi-Fi/BLE anomaly scanning, thermal and cellular (IMSI-catcher) heuristics,
fused into one anomaly score, plus an optional link out to EFF's Rayhunter
and a Shizuku-gated read-only diagnostics panel.

> **Baseband audio model — it does not radiate, and nothing here transmits.**
> Every "RF", "radar", "TDMA", "spur" or "magnetron" *source* is an *audio*
> model of what that interference sounds like — nothing is transmitted over
> the air. Every *detector* (mic, Wi-Fi/BLE scan, sensors, cell heuristics,
> Shizuku diagnostics) is **receive-only** — nothing here jams, injects,
> deauths, or transmits, and that will not change. See [ETHICS.md](ETHICS.md).

This edition expands the original single-source noise maker first into a
sensor-aware, accessory-connected instrument (2.0), then into a passive
detection instrument (3.0). It grew out of studying the feature surface of
BLE/Wi-Fi field tools (accessory pairing, sensor telemetry, profiles,
geofencing, anomaly detection) and porting those *interaction and detection*
ideas — never any transmit capability — onto an audio masker.

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
