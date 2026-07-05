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

## Slot-free policy tier (Shizuku, opt-in)

A genuine per-app firewall on Android 13+ that drops a blocked app's packets
on **every** network (Wi-Fi + mobile + VPN) **without a VpnService** — it never
takes the VPN slot, so it coexists with Tailscale. It arms the kernel
`OEM_DENY_3` chain via the Shizuku shell (`cmd connectivity`). Exemptions
(`UidExemptions`) always win, so it can never sever Tailscale or core
networking. Default policy (allow-all vs lockdown), block-when-screen-off,
saved profiles, and a Quick-Settings Lockdown tile. This is a **policy** lever
(may this app talk), not routing and not DNS filtering.

## Standalone tunnel tier (opt-in, default-off, XOR-Tailscale)

The one tier that **takes** Android's single VPN slot. Gated by the
`VpnSlotProbe` guardrail (fail-closed CM `TRANSPORT_VPN` veto ANDed with
`VpnService.prepare()`) before enabling, before arming, and live while armed —
so it **refuses to start whenever any other VPN holds the slot** (never evicts
Tailscale) and disarms neutrally if a VPN appears. A full-screen explainer
states the XOR-Tailscale trade before the first enable. Two flavors:

- **DNS_FILTER (default) — the adblock-DNS tunnel (S6).** A DNS-only tun
  (advertises a fake resolver, routes only that IP) captures DNS queries,
  matches each domain against an on-device blocklist (bundled gzip seed +
  user-updatable https list + custom block/allow; parent-domain suffix match),
  **sinkholes** blocked domains (NXDOMAIN or 0.0.0.0), and **forwards** allowed
  queries to the configured upstream resolver over a `protect()`ed socket. Each
  query is attributed to its app via `ConnectivityManager.getConnectionOwnerUid`
  and logged for the connection-visibility screen (S7). *Honest boundaries:*
  the upstream forward is **plaintext UDP** — encrypted-resolver routing
  (DoT/DoH/DNSCrypt/Tor) is a documented, **unimplemented stub**
  (`DnsFilterTun.UpstreamResolver.encryptedStub`); pair with system Private DNS
  (S4) for an encrypted system-resolver upstream. IPv6 DNS is not captured. It
  blocks by **domain name** only (not raw-IP connections; not an app's own DoH).
- **APP_DROP (legacy).** Captures the restricted apps and drops their packets
  entirely — no DNS filtering, no per-domain rules.

## DNS hardening (S4)

Configures the platform's own **Private DNS (DoT)** via `PrivateDnsApplier` /
the Shizuku shell (or the Settings deep-link). The "Active now" card reads the
live `Settings.Global` value back. Honest framing: this is a DNS **destination**
lever (encrypted upstream), **not content filtering** — for on-device ad/tracker
sinkholing, use the DNS-filter tunnel.

## Connection visibility (S7)

Rides the DNS-filter tun when armed: a live per-app DNS event log (domain +
app + allow/block), per-app counts, clear/export. When the tunnel is off it
shows the slot-free policy block **counters** instead — never a fabricated
per-domain log, because the slot-free tier has no tun and cannot see domains.
We never market slot-free packet capture.

## Root iptables tier (S8) — honest dormant stub

The granular per-network-type / LAN / per-port iptables tier is presented as
**"requires root — unavailable on this device."** A clean `RootDetector`
(su-binary path check + a read-only `id -u` through a granted Shizuku shell;
never runs `su`) drives the availability banner. Nothing is faked — no hidden
no-op toggles; the tier stays fully disabled until run on a genuinely rooted
device.

## Tier overview (coherence)

A single map screen lists all four tiers with: whether each is active, its
Tailscale-coexistence status, and a one-line honest caveat (policy = per-app
block, no slot, no routing; tunnel = adblock-DNS routing, takes the slot, XOR
Tailscale; DNS = encrypted destination; root = dormant).

## Explicitly NOT present (removed as unshippable)

- **dnscrypt-proxy bundling** — removed (A8). The bundled proxy could never
  be queried without a tun and the binary was never in the repo. The
  enforced path is DoT via system Private DNS; the empirical check is the
  DNS canary.
- **Custom port blocking** — removed (A11). Structurally a no-op on every
  supported device (`/proc/net` restricted on Android 10+; minSdk 33).
- **Overlay routing (I2P / Lokinet / Yggdrasil)** — removed (A12);
  Lokinet/Yggdrasil are themselves VpnService transports (vetoed).
- **Encrypted-resolver upstream routing in the tunnel (DoT/DoH/DNSCrypt/Tor)**
  — NOT implemented. The DNS-filter tunnel's upstream forward is plaintext UDP;
  the encrypted path is a documented stub
  (`DnsFilterTun.UpstreamResolver.encryptedStub`). The encrypted-DNS story we
  ship today is system Private DNS (S4). No DNSCrypt/Tor daemon is bundled.
- **Custom port blocking / per-network-type / LAN rules without root** — the
  slot-free tier is all-or-nothing per app; granular per-port/per-network/LAN
  rules need root and are the honest dormant S8 stub.

NOTE (updated): in-tunnel DNS forwarding **is** now shipped as the S6 adblock-DNS
tunnel — `VpnPacketParser` + the new `DnsMessage` (query parse + sinkhole build)
and `DnsBlocklist` in `net-engine` are called by `DnsFilterTun`. This supersedes
the earlier note that the packet library was dormant and uncalled.
