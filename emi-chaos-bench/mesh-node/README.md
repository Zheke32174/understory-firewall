# mesh-node — companion agents for the EMI Chaos Bench sensor mesh

The app's **Link** tab opens one WebSocket connection out to a "companion
address" (`ws://host:port`). Anything on the other end that speaks the small
JSON protocol below becomes a mesh node: another phone, a laptop, an OpenWRT
router, or a laptop with a passive RF accessory attached.

**Every message type here is receive-only from the app's point of view.**
Nothing in this protocol, or in any reference agent in this directory, can
key up a radio, send AT commands, deauth a client, or otherwise transmit.
Read [`../ETHICS.md`](../ETHICS.md) — that boundary is load-bearing for the
whole project.

## Protocol

One JSON object per WebSocket text frame.

```jsonc
// A node introduces/updates itself and streams sensor values (-1..1, same
// range the app's own on-device sensors use).
{"type":"sensor_report","node_id":"openwrt-livingroom","kind":"wifi_survey",
 "sensors":{"net":0.4,"shake":0}}

// A node raises something worth a human's attention. sev: 1=info,2=warn,3=crit.
{"type":"anomaly","node_id":"openwrt-livingroom","sev":2,
 "msg":"New client with randomized MAC associated 4x in 60s"}

// A relay forwards a Rayhunter device's own alert. level mirrors Rayhunter's
// own vocabulary (green/yellow/orange/red — see rayhunter-relay.py below).
{"type":"rayhunter_alert","node_id":"rayhunter-mifi","level":"orange",
 "msg":"Heuristic flagged: possible downgrade"}

// A passive broadband receiver (e.g. RTL-SDR in scanner mode) streams a
// spectrum snapshot. bins are 0..1 magnitude, evenly spaced up to sampleRate/2.
{"type":"spectrum_report","node_id":"laptop-sdr","sampleRate":2400000,
 "bins":[0.02,0.03,0.11, /* ... */]}

// Remote control, unchanged since v2 — a node (or a person driving it) can
// trigger start/stop or load a saved profile by name.
{"cmd":"start"}
{"cmd":"stop"}
{"profile":"Boardroom"}
```

Recognised `kind` values (shown in the app's Link → Accessory kinds panel):
`generic_sensor`, `wifi_survey`, `thermal`, `rtl_sdr_spectrum`,
`flipper_ble_scan`, `rayhunter_relay`. Anything else still works — `kind` is
just a label — but these are what the UI knows to badge specially.

## Reference agents in this directory

- **`openwrt-agent.sh`** — POSIX shell, no non-base dependencies beyond
  `iwinfo` (already on almost every OpenWRT build) and `nc`/`websocketd` for
  the WebSocket framing (see the comment header for the exact package). Runs
  directly on the router. Streams Wi-Fi survey (`wifi_survey`), connected
  client count, and `/sys/class/thermal` zones (`thermal`) as periodic
  `sensor_report`s, and raises an `anomaly` when it sees a new randomized-MAC
  client associate repeatedly in a short window.
- **`rayhunter-relay.py`** — Python 3, standard library + `websockets`. Run
  it on a laptop/Pi that has network access to your
  [Rayhunter](https://github.com/EFForg/rayhunter) device's own web UI
  (`http://<device-ip>:8080` by default on the Orbic hotspot). **Rayhunter's
  UI has no documented JSON API as of this writing** — this relay does a
  best-effort, clearly-labeled scrape of the page for its own
  green/yellow/orange/red severity indicators and forwards state changes as
  `rayhunter_alert`. Treat it as a starting point: open
  `SELECTORS`/`PATTERNS` at the top of the file and adjust to match what your
  Rayhunter version's page actually renders — verify against the real UI
  before trusting it unattended.
- **`generic-sensor-agent.py`** — minimal template for wiring up any other
  passive accessory (an RTL-SDR via `rtl_power`, a Flipper Zero's BLE-scan
  CLI output, anything that can print numbers) into a `sensor_report` or
  `spectrum_report` stream. Copy it and fill in `read_accessory()`.

## Running one

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install websockets
python3 rayhunter-relay.py --rayhunter http://192.168.1.1:8080 --mesh ws://<phone-ip>:PORT
```

For `openwrt-agent.sh`, the app needs to be the WebSocket *server* side
instead (the app currently only dials out as a client) — the simplest setup
today is the reverse: run a tiny WebSocket server on the OpenWRT box or
laptop and have the phone's **Wi-Fi companion** field point at it, i.e. the
companion node listens, the phone connects out. `openwrt-agent.sh` includes
a minimal `websocketd`-based listener for exactly that.
