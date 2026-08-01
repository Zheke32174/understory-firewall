# EMI Chaos Bench — Accessories Edition

A local, on-device **audio voice-masker**. It synthesises a dense field of
interference-styled sound sources (30+), driven by chaos attractors and the
phone's own motion, to defeat the *intelligibility* of speech picked up by a
nearby microphone.

> **Baseband audio model — it does not radiate.** Every "RF", "radar",
> "TDMA", "spur" or "magnetron" source is an *audio* model of what that
> interference sounds like. Nothing is transmitted over the air. The app masks
> what a microphone **near the speaker** hears; it has no effect beyond
> earshot. See [ETHICS.md](ETHICS.md).

This edition expands the original single-source noise maker into a
sensor-aware, accessory-connected instrument. It grew out of studying the
feature surface of BLE/Wi-Fi field tools (accessory pairing, sensor telemetry,
profiles, geofencing) and porting those *interaction* ideas — not any transmit
capability — onto an audio masker.

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
    EmiBridge.kt                    window.EMIBridge: sensors, BLE scan, network, haptics, fg-service
    MaskerService.kt                media-playback foreground service (background mode)
  AndroidManifest.xml               permissions (all input-side) + components
  res/                              icon, theme, strings
```

## Build

```bash
./gradlew assembleDebug
# APK at app/build/outputs/apk/debug/app-debug.apk
```

`minSdk 26`, `targetSdk 34`, Kotlin, AndroidX. No third-party runtime deps
beyond `androidx.core` / `androidx.activity`.

## Try the app without building

Open `app/src/main/assets/index.html` in any modern browser. Press **Start**
(or Space). Enable **Sensors** on a phone browser to feel the motion coupling.

## Permissions, and why

Every permission is for reading an input or for background audio — there is no
transmit path.

- `FOREGROUND_SERVICE` / `..._MEDIA_PLAYBACK`, `POST_NOTIFICATIONS`, `WAKE_LOCK` — keep the masker audible when backgrounded.
- `VIBRATE` — haptics.
- `BLUETOOTH_SCAN` (`neverForLocation`) / `BLUETOOTH_CONNECT` — enumerate/link accessory beacons (read RSSI/sensors).
- `ACCESS_FINE/COARSE_LOCATION` — GPS as a modulation source and profile geofencing; also required by Android for BLE scan and cell-signal reads.
- `ACCESS_NETWORK_STATE`, `HIGH_SAMPLING_RATE_SENSORS` — network entropy, high-rate gyro.
- `INTERNET` — **LAN WebSocket to a companion node only.** No audio or telemetry is sent to the internet.

## License

MIT — see [LICENSE](LICENSE).
