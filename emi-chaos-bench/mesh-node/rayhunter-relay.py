#!/usr/bin/env python3
"""
rayhunter-relay.py — forward EFF Rayhunter's own alerts onto the EMI Chaos
Bench sensor mesh as `rayhunter_alert` messages.

WHY THIS EXISTS
----------------
Rayhunter (https://github.com/EFForg/rayhunter) is the real, maintained
IMSI-catcher detector. It runs on a dedicated device (an Orbic RC400L mobile
hotspot, community support for others) and exposes a small web UI, by
default at http://192.168.1.1:8080 (Orbic) or http://192.168.0.1:8080
(TP-Link) — see https://efforg.github.io/rayhunter/using-rayhunter.html.
That page shows warnings as colored indicators: a green line for normal
operation, yellow dots / orange dashes / solid red for escalating severity.

As of this writing Rayhunter's web UI has **no documented JSON API** — it is
a server-rendered HTML page, not a REST endpoint. This script does NOT
invent one. It does a best-effort, clearly-labeled scrape of the page for
those severity words/markers and forwards STATE CHANGES onward. Treat the
PATTERNS block below as a starting point you verify against your own
Rayhunter version's actual page source (view-source it, adjust the regexes),
not as a guaranteed-correct parser.

WHAT IT DOES NOT DO
--------------------
It never talks to the modem, never touches /dev/diag, never sends anything
to Rayhunter — it only reads Rayhunter's own web UI, the same way a browser
would. All it adds is: turn "the indicator changed color" into one JSON
message on the mesh.

USAGE
-----
    pip install websockets
    python3 rayhunter-relay.py --rayhunter http://192.168.1.1:8080 --listen 0.0.0.0:8765

Then in the app's Link tab, set "Companion address" to
ws://<this-machine's-LAN-IP>:8765 and press Connect — the app dials OUT to
this script, which is the WebSocket *server* side of the mesh link.
"""
import argparse
import asyncio
import json
import re
import time
import urllib.request

try:
    import websockets
except ImportError:
    raise SystemExit("Missing dependency. Run: pip install websockets")

# --- EDIT ME: verify these against your Rayhunter version's real HTML ---
# Ordered worst-first; the first pattern that matches wins.
PATTERNS = [
    ("red",    re.compile(r"\b(solid[-\s]?red|severity[-\s]?(high|red)|alert[-\s]?red)\b", re.I)),
    ("orange", re.compile(r"\b(orange[-\s]?dash|severity[-\s]?(medium|orange)|alert[-\s]?orange)\b", re.I)),
    ("yellow", re.compile(r"\b(yellow[-\s]?dot|severity[-\s]?(low|yellow)|alert[-\s]?yellow)\b", re.I)),
]
LEVEL_RANK = {"green": 0, "yellow": 1, "orange": 2, "red": 3}


def fetch_level(base_url: str, timeout=6):
    """Best-effort: fetch Rayhunter's root page and guess a severity word.
    Returns ('green', "no warning markers found") when nothing matches —
    that is the expected/normal state, not a failure."""
    req = urllib.request.Request(base_url, headers={"User-Agent": "emi-chaos-bench-relay/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        html = resp.read().decode("utf-8", "ignore")
    for level, pat in PATTERNS:
        m = pat.search(html)
        if m:
            return level, f"matched {m.group(0)!r}"
    return "green", "no warning markers found"


class Relay:
    def __init__(self, rayhunter_url, node_id, poll_seconds):
        self.rayhunter_url = rayhunter_url
        self.node_id = node_id
        self.poll_seconds = poll_seconds
        self.clients = set()
        self.last_level = None

    async def register(self, ws):
        self.clients.add(ws)
        try:
            await ws.send(json.dumps({"type": "hello", "relay": "rayhunter"}))
            async for _ in ws:
                pass  # this relay is send-only; ignore anything the app sends back
        finally:
            self.clients.discard(ws)

    async def broadcast(self, obj):
        if not self.clients:
            return
        msg = json.dumps(obj)
        await asyncio.gather(*(c.send(msg) for c in list(self.clients)), return_exceptions=True)

    async def poll_loop(self):
        while True:
            try:
                level, detail = await asyncio.to_thread(fetch_level, self.rayhunter_url)
            except Exception as e:
                level, detail = None, f"unreachable: {e}"
            if level is not None and level != self.last_level:
                if self.last_level is not None:  # don't fire on the very first read
                    print(f"[{time.strftime('%H:%M:%S')}] Rayhunter level {self.last_level} -> {level} ({detail})")
                    await self.broadcast({
                        "type": "rayhunter_alert",
                        "node_id": self.node_id,
                        "level": level,
                        "msg": detail,
                    })
                self.last_level = level
            await asyncio.sleep(self.poll_seconds)


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rayhunter", required=True, help="Rayhunter base URL, e.g. http://192.168.1.1:8080")
    ap.add_argument("--listen", default="0.0.0.0:8765", help="host:port to listen on for the phone to dial in")
    ap.add_argument("--node-id", default="rayhunter-relay", help="node_id reported in mesh messages")
    ap.add_argument("--poll-seconds", type=float, default=5.0)
    args = ap.parse_args()

    host, port = args.listen.rsplit(":", 1)
    relay = Relay(args.rayhunter, args.node_id, args.poll_seconds)

    async with websockets.serve(relay.register, host, int(port)):
        print(f"Listening on ws://{args.listen} — point the app's Wi-Fi companion address here.")
        print(f"Polling {args.rayhunter} every {args.poll_seconds}s (best-effort HTML scrape — see PATTERNS).")
        await relay.poll_loop()


if __name__ == "__main__":
    asyncio.run(main())
