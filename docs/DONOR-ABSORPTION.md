# Godwall — donor absorption ledger

Godwall (the understory firewall) is built by reverse-engineering the feature
sets of a set of donor apps, then re-implementing each capability as a *superior
variant* native to our stack — never by bundling the donor or a daemon. This
ledger tracks, per donor, what the donor does, how Godwall covers it, and where
our variant is better or where a gap remains.

Method: **reverse-engineer → understand the function → innovate a superior
variant.** A row is only "done" when the capability runs inside Godwall's own
code paths (the Elevation Shizuku/Yojimbo shell, the DNS-filter tunnel, or the
policy backends), with honest degradation when a privilege isn't granted.

Donors: **InviZible Pro**, **RethinkDNS**, **De1984**, **Fyrypt**.

---

## Encrypted DNS (InviZible Pro · RethinkDNS · Fyrypt)

All three donors centre on encrypted DNS. InviZible and RethinkDNS ship a
resolver stack; Fyrypt manages an external `dnscrypt-proxy`. Godwall does it
**natively in the filter tunnel** — no bundled daemon, no separate process.

| Capability | Donor | Godwall | Variant note |
|---|---|---|---|
| DNS-over-TLS (RFC 7858) | all | **Done** — `UpstreamResolver.dot()` | Verified in-tunnel: socket `protect()`ed before handshake, SNI + HTTPS endpoint-id, **fail-closed** on a bad cert (never downgrades to plaintext). |
| DNS-over-HTTPS (RFC 8484) | all | **Done** — `UpstreamResolver.doh()` | Rides :443 so a `:853` block can't force plaintext. Minimal HTTP/1.1 POST of `application/dns-message`, Content-Length + chunked parsing, 64 KiB bound. Same verified-TLS setup as DoT. |
| Curated resolver presets | RethinkDNS | **Done** — `DOT_PRESETS` / `DOH_PRESETS` | Cloudflare / Quad9 / Google / AdGuard / Mullvad, each pairing IP with its verification hostname so they always match. |
| DNSCrypt v2 | InviZible / Fyrypt | **Done** — native `DnscryptClient` + `UpstreamResolver.dnscrypt()` | Pure-JVM DNSCrypt: Ed25519 cert verification, X25519 key agreement, XSalsa20/XChaCha20-Poly1305 secretbox, over `protect()`ed UDP. NO bundled `dnscrypt-proxy`. Gated behind a runtime `CryptoSelfTest` (known-answer vectors); `SecretBox.open` fails closed, so a crypto fault yields no answer, never a wrong one. |
| Resolver lists (`sdns://` stamps) | InviZible / dnscrypt-proxy | **Done** — `DnsStamp` + bundled `dnscrypt/*.md.gz` | The canonical public-resolvers/relays/ODoH lists bundled as a real snapshot (~900 resolvers, ~350 relays) and refreshable from the canonical HTTPS source; parser validated against all 1,415 real stamps. |
| System Private DNS (DoT) | — | **Done** (pre-existing) — `PrivateDnsApplier` | Slot-free, composes with Tailscale. Complements the in-tunnel path. |

## Anonymized DNS — Tor + I2P (InviZible Pro's other two engines)

InviZible bundles DNSCrypt **plus Tor plus Purple I2P**. Godwall is rootless and
single-slot, so it doesn't embed those daemons; it routes the filter tunnel's DNS
through the SOCKS proxy those apps already expose.

| Capability | Godwall | Variant note |
|---|---|---|
| DNS over Tor | **Done** — `AnonRouting` + `Socks5Client` + `UpstreamResolver.socksDns()` | DNS-over-TCP through Orbot's SOCKS (127.0.0.1:9050). Only used when the proxy actually answers a SOCKS5 greeting; else falls back to the base upstream instead of black-holing DNS. |
| DNS over I2P | **Done** — same path, I2P router SOCKS (127.0.0.1:4447) | Plus a custom SOCKS endpoint option. Orbot / I2P app presence is detected and surfaced. |
| Tor / I2P as an egress hop | *Seam* — `ProxyHop.Tor` / `ProxyHop.I2p` in the chain | Full-traffic chaining is a declared backend; DNS routing above is the working slice today. |

## Packet capture (PCAPdroid)

| Capability | Godwall | Variant note |
|---|---|---|
| Capture to a `.pcap` file | **Done** — `PcapWriter` + `PcapController` | Standard libpcap (LINKTYPE_RAW), openable in Wireshark / tcpdump / PCAPdroid. Captures the raw IP packets the tun sees: every app's DNS in filter mode, restricted-app packets in drop mode. Auto-stops at 64 MiB. |
| Export / share a capture | **Done** — `PacketCaptureScreen` + FileProvider | Per-share read grant only; app-private `files/pcap/` is the sole exposed path. |
| Whole-device capture | *Boundary* | PCAPdroid routes ALL traffic through a userspace TCP/IP stack; Godwall's tun claims only the DNS route (filter mode) or the restricted apps (drop mode). The UI states this. |

## DNS content filtering (InviZible · RethinkDNS)

| Capability | Godwall | Variant note |
|---|---|---|
| On-device blocklist + sinkhole | **Done** — `DnsBlocklist`, `DnsFilterTun` | NXDOMAIN or 0.0.0.0 sinkhole with parent-domain semantics, no upstream round-trip for blocked names. |
| User blocklist by URL | **Done** — `BlocklistRepository` | HTTPS-only fetch, size-capped, cached. |
| Manual allow/block a domain | **Done** — custom allow/block sets | |
| Per-app DNS attribution + log | **Done** — `ConnectionAttributor` + `DnsEventLog` | Each query attributed to its owning UID and recorded for the visibility surface. |

## Per-app firewall + universal rules (RethinkDNS · De1984 · Fyrypt)

| Capability | Donor | Godwall | Variant note |
|---|---|---|---|
| Per-app network block | all | **Done** — policy backends | Runs through the Shizuku shell (uid 2000) or ConnectivityManager/NetworkPolicy — **no VPN slot**, coexists with Tailscale. |
| Block-all / allow-all default | De1984 / RethinkDNS | **Done** — `DefaultPolicy` (lockdown) | Whitelist lockdown with always-honoured exemptions (VPN providers / system-critical). |
| Block when screen off / background | De1984 / RethinkDNS | **Done** — `ScreenPolicyMonitor` + policy flags | |
| Block newly installed apps | RethinkDNS | **Done** — auto-block toggle (below) | |
| Named policy profiles | — | **Done** — `PolicyStore` profiles | Home / Untrusted Wi-Fi / Lockdown, snapshot+restore. |
| Quick-settings lockdown tile | — | **Done** — `LockdownTileService` | |
| Per-UID + per-PID rules | Fyrypt | *Partial* — per-UID done, per-PID not | PID-scoped rules need the root iptables tier; the rootless tiers are UID-scoped. |
| Custom IP/port rules per app | Fyrypt | *Deferred* — needs root iptables tier | `PortBlockLimitation` exists in the engine; a per-app IP/port rule UI is future work. |

## New-app install watch (De1984 · Fyrypt)

| Capability | Godwall | Variant note |
|---|---|---|
| Notify when a new app is installed | **Done** — `PackageInstallReceiver` + `NewAppNotifier` | Skips updates and system apps; routes into the per-app firewall. |
| Auto-block newly installed apps | **Done (superior)** — auto-block toggle | Our addition over the donors' notify-only: a new app is blocked from the network the moment it installs (RethinkDNS's "block newly installed apps"), reversible per app. Honest: only claims a block when it actually applied. |

## Package manager (De1984)

De1984's other half is a rootless package manager. Godwall absorbs it as the
**App Manager** screen, backed by the existing Elevation shell.

| Capability | Godwall | Variant note |
|---|---|---|
| List apps, filter system/user/enabled | **Done** — `AppManagerScreen` | `MATCH_DISABLED_COMPONENTS` so disabled apps still show; filter User/System/Disabled/All + search. |
| Enable / disable a whole app | **Done** — `Elevation.setApplicationEnabled` | `pm disable-user --user 0` / `pm enable` — reversible, works on system apps a non-root user can't uninstall (the debloat path). |
| Force-stop | **Done** — `Elevation.forceStop` | |
| Clear app data | **Done** — `Elevation.clearAppData` | Behind a confirm. |
| Uninstall | **Done** — `Elevation.uninstall` | User apps only; behind a confirm. |
| Suspend / component disable / appops / revoke perm | **Done** (pre-existing) — `Elevation.*` | The scalpel set below uninstall — neutralise a11y/overlay/device-admin without removing the app. |

Honest degrade: with no privileged backend granted, App Manager is read-only and
says so; every action reports Success / Unsupported / Failed truthfully.

## Live connection monitor (Fyrypt · RethinkDNS connection tracker)

| Capability | Godwall | Variant note |
|---|---|---|
| DNS-level per-app event log | **Done** — `DnsEventLog` + Visibility | Which app asked for which domain, blocked or not. |
| Traffic accounting per app | **Done** — `TrafficAccounting` | |
| Live IP:port connection log | *Deferred* | Fyrypt's per-connection dest-IP/port live log needs the packet path or `/proc/net` polling with UID attribution; the DNS-level log covers the common "who is phoning where" question today. |

---

## Coverage summary

**Absorbed (native, superior or on-par):** encrypted DNS (DoT + DoH +
**native DNSCrypt v2** with the bundled resolver/relay lists), **DNS over Tor /
I2P** via the anon-routing SOCKS path, DNS content filtering + per-app
attribution, per-app firewall + universal rules + lockdown + profiles, new-app
watch **with auto-block**, the full rootless package-manager toolkit
(enable/disable/force-stop/clear/uninstall plus the appops/component scalpels),
and **PCAP packet capture** with export.

**Deferred (understood, not yet built):** full-traffic Tor/I2P/WireGuard/
Shadowsocks egress chaining (declared backends; DNS routing is the working
slice), per-PID and per-app IP/port rules (root iptables tier), and a live
per-connection IP:port monitor (Fyrypt). None block the "largely finished"
milestone — each is an additive tier, not a hole in the core.

Everything here runs inside Godwall's own code paths through the shared
Elevation Shizuku/Yojimbo shell — the firewall depends on Yojimbo, not on any
donor app being installed.
