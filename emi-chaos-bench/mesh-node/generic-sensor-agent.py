#!/usr/bin/env python3
"""
generic-sensor-agent.py — minimal template for wiring any passive accessory
into the EMI Chaos Bench mesh. Copy this file, fill in read_accessory(), run
it near your accessory (laptop/Pi with the hardware attached), point the
app's Wi-Fi companion address at ws://<this-machine>:<port>.

Fill in read_accessory() with whatever your accessory can passively read —
an RTL-SDR power scan (`rtl_power`), a Flipper Zero's BLE-scan CLI output, a
USB GPS dongle, anything. Return either a `sensors` dict (values -1..1 —
becomes a sensor_report) or a `bins` list (0..1 magnitudes — becomes a
spectrum_report). This template must never be extended to transmit,
jam, inject, or otherwise write to any radio — see ../ETHICS.md.
"""
import argparse
import asyncio
import json
import time

try:
    import websockets
except ImportError:
    raise SystemExit("Missing dependency. Run: pip install websockets")


def read_accessory():
    """EDIT ME. Return (kind, sensors_dict_or_None, bins_list_or_None)."""
    # Example stub: replace with a real read. Values must be -1..1 for
    # `sensors`, or 0..1 for `bins`.
    return "generic_sensor", {"net": 0.0}, None


async def stream(node_id, interval, ws_set):
    while True:
        kind, sensors, bins = read_accessory()
        if not ws_set:
            await asyncio.sleep(interval)
            continue
        if sensors is not None:
            msg = {"type": "sensor_report", "node_id": node_id, "kind": kind, "sensors": sensors}
        elif bins is not None:
            msg = {"type": "spectrum_report", "node_id": node_id, "sampleRate": 48000, "bins": bins}
        else:
            await asyncio.sleep(interval)
            continue
        payload = json.dumps(msg)
        await asyncio.gather(*(c.send(payload) for c in list(ws_set)), return_exceptions=True)
        await asyncio.sleep(interval)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:8766")
    ap.add_argument("--node-id", default="generic-node")
    ap.add_argument("--interval", type=float, default=2.0)
    args = ap.parse_args()

    clients = set()

    async def handler(ws):
        clients.add(ws)
        try:
            async for _ in ws:
                pass
        finally:
            clients.discard(ws)

    host, port = args.listen.rsplit(":", 1)
    async with websockets.serve(handler, host, int(port)):
        print(f"Listening on ws://{args.listen} — point the app's Wi-Fi companion address here.")
        await stream(args.node_id, args.interval, clients)


if __name__ == "__main__":
    asyncio.run(main())
