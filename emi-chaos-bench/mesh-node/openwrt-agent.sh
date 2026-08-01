#!/bin/sh
# openwrt-agent.sh — reference mesh node for OpenWRT routers.
#
# Streams periodic sensor_report JSON lines (Wi-Fi survey via `iwinfo`,
# thermal zones, associated-client count) and raises an `anomaly` when a
# new client with a randomized-looking MAC associates repeatedly in a short
# window. Everything here READS router state — it never touches radio
# transmit settings, never deauths, never modifies anything.
#
# This script speaks line-delimited JSON on stdout (one JSON object per
# line) and is meant to be run under `websocketd`, which turns exactly that
# into a real WebSocket server that the phone app dials into:
#
#   opkg update && opkg install websocketd    # if packaged for your target;
#                                              # otherwise grab a static build
#                                              # from https://github.com/joewalnes/websocketd
#   websocketd --port=8765 /path/to/openwrt-agent.sh
#
# Then in the app's Link tab, set "Companion address" to
# ws://<router-lan-ip>:8765 and press Connect.
#
# Config (override via environment):
#   NODE_ID          default "openwrt-$(hostname)"
#   WIFI_IFACE       default "wlan0" — pass your actual radio iface (see `iwinfo`)
#   POLL_SECONDS     default 8
set -u

NODE_ID="${NODE_ID:-openwrt-$(hostname 2>/dev/null || echo router)}"
WIFI_IFACE="${WIFI_IFACE:-wlan0}"
POLL_SECONDS="${POLL_SECONDS:-8}"
SEEN_FILE="/tmp/emi-mesh-seen-macs.$WIFI_IFACE"
touch "$SEEN_FILE" 2>/dev/null

json_escape() {
  # minimal JSON string escaping for the values we emit
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

read_thermal() {
  # emits a small JSON array of millidegree-C readings from every thermal zone
  first=1
  out="["
  for z in /sys/class/thermal/thermal_zone*/temp; do
    [ -r "$z" ] || continue
    t=$(cat "$z" 2>/dev/null)
    [ -n "$t" ] || continue
    [ "$first" = 1 ] || out="$out,"
    out="$out$((t))"
    first=0
  done
  out="$out]"
  echo "$out"
}

read_wifi_survey() {
  # iwinfo assoclist gives connected clients with signal; scanlist would
  # active-scan (noisier/more intrusive) so we deliberately use assoclist —
  # this only reads who's already associated to THIS router's radio.
  if command -v iwinfo >/dev/null 2>&1; then
    iwinfo "$WIFI_IFACE" assoclist 2>/dev/null
  fi
}

# Prints any new-randomized-MAC anomaly lines directly to real stdout (must
# NOT be called via $(...) command substitution — that would swallow them).
# Sets $client_count as a side effect for the caller to read afterward.
emit_client_anomalies() {
  survey="$1"
  client_count=$(printf '%s\n' "$survey" | grep -c '^[0-9A-Fa-f][0-9A-Fa-f]:')
  macs=$(printf '%s\n' "$survey" | grep -o '^[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f:]*[0-9A-Fa-f]')
  [ -n "$macs" ] || return 0
  echo "$macs" | while read -r mac; do
    [ -n "$mac" ] || continue
    if ! grep -qi "^$mac\$" "$SEEN_FILE" 2>/dev/null; then
      echo "$mac" >> "$SEEN_FILE"
      first_octet=${mac%%:*}
      # bit 1 (0x02) of the first octet set == locally-administered/randomized
      hexval=$(printf '%d' "0x$first_octet" 2>/dev/null || echo 0)
      if [ $((hexval & 2)) -ne 0 ]; then
        esc=$(json_escape "New randomized-MAC client associated: $mac")
        printf '{"type":"anomaly","node_id":"%s","sev":1,"msg":"%s"}\n' "$(json_escape "$NODE_ID")" "$esc"
      fi
    fi
  done
}

# trim the seen-MAC file so it doesn't grow forever
trim_seen() {
  [ -f "$SEEN_FILE" ] || return
  wc_l=$(wc -l < "$SEEN_FILE" 2>/dev/null || echo 0)
  if [ "$wc_l" -gt 500 ]; then
    tail -n 200 "$SEEN_FILE" > "$SEEN_FILE.tmp" && mv "$SEEN_FILE.tmp" "$SEEN_FILE"
  fi
}

while true; do
  survey=$(read_wifi_survey)
  client_count=0
  emit_client_anomalies "$survey"   # prints anomaly lines directly; sets $client_count
  thermal=$(read_thermal)
  net=$(awk -v c="$client_count" 'BEGIN{ v=c/30; if(v>1)v=1; printf "%.3f", v*2-1 }')
  printf '{"type":"sensor_report","node_id":"%s","kind":"wifi_survey","sensors":{"net":%s},"clientCount":%s,"thermalMilliC":%s}\n' \
    "$(json_escape "$NODE_ID")" "$net" "$client_count" "$thermal"
  trim_seen
  sleep "$POLL_SECONDS"
done
