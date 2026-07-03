# Firewall — capability boundary (v2)

This document supersedes the old phase-1.5 note. It states, honestly, what
Understory Net Audit does and does not do as shipped, so no copy anywhere
implies a capability the code lacks (CD-4b). The authoritative design is
`docs/design-v2/firewall.md`.

## What the app does today

The default mode is **Companion** (observe / advise / route). It is the
only mode a device with any VPN — e.g. a Tailscale phone — ever reaches.

- **Tunnel posture** — reads what a rootless app can (Tailscale installed
  + version; whether a VPN is up; best-effort always-on / lockdown) and
  renders a verdict that degrades to "unknown" on any inference gap. Never
  green on a gap.
- **Remote-admin audit** — enumerates apps holding device-admin /
  accessibility / notification-listener / usage-stats / overlay / all-files
  power, with a MODE_DEFAULT tri-state so an unreadable op shows "unknown",
  not "clean". The real fix is "Revoke in Settings"; watchlist is a
  reminder.
- **DNS hardening** — configures the platform's own **Private DNS (DoT)**,
  applied programmatically when `WRITE_SECURE_SETTINGS` is ADB-granted,
  otherwise via the Settings deep-link + paste flow. The "Active now" card
  reads the live `Settings.Global` value back, so the user sees what is in
  effect, not what we last wrote.
- **Traffic by app** — `NetworkStatsManager` accounting (opt-in Usage
  access). Accounting, not interception: totals after the fact, no hosts,
  no contents, no blocking.
- **Egress canaries** — explicit-tap-only probes (egress IP, resolver
  identity, DoT reachability) to named hosts, to prove on the wire what
  your DNS / exit actually is.
- **Restrict worklist** — flags apps and opens Android's own per-app
  controls (`resolveActivity`-guarded deep-links). The app itself enforces
  nothing here; Android does.

In Companion the app **never takes the VPN slot and blocks no traffic.**

## Standalone mode (opt-in, default-off)

Packet-level per-app blocking exists only in Standalone mode, which:

- is off by default and gated behind a full-screen explainer;
- runs the `VpnSlotProbe` guardrail (fail-closed CM `TRANSPORT_VPN` veto
  ANDed with `VpnService.prepare()`) before enabling, before arming, and
  live while armed — so it **refuses to start whenever any other VPN holds
  the slot**, and disarms neutrally if a VPN appears;
- when armed, drops the enabled apps' traffic via a local tun (app-drop
  only — there is no in-tunnel DNS forwarding or per-domain rule engine).

## Explicitly NOT present (removed as unshippable)

- **dnscrypt-proxy bundling** — removed (A8). The bundled proxy could never
  be queried without a tun and the binary was never in the repo. The
  enforced path is DoT via system Private DNS; the empirical check is the
  DNS canary.
- **Custom port blocking** — removed (A11). Structurally a no-op on every
  supported device (`/proc/net` restricted on Android 10+; minSdk 33).
- **Overlay routing (I2P / Lokinet / Yggdrasil)** — removed (A12);
  Lokinet/Yggdrasil are themselves VpnService transports (vetoed).
- **In-tunnel DNS forwarding / per-domain rules** — not shipped. The packet
  parser (`VpnPacketParser`) survives as a dormant, unit-tested library
  (`net-engine`) for a possible future userspace forwarder; the shipping
  app does not call it.
