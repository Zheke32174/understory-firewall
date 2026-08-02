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
| DNSCrypt | InviZible / Fyrypt | *Deferred* | DoT+DoH already give verified, encrypted, censorship-resistant DNS. DNSCrypt would add the third protocol but no new security property we lack. |
| System Private DNS (DoT) | — | **Done** (pre-existing) — `PrivateDnsApplier` | Slot-free, composes with Tailscale. Complements the in-tunnel path. |

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

**Absorbed (native, superior or on-par):** encrypted DNS (DoT + DoH),
DNS content filtering + per-app attribution, per-app firewall + universal
rules + lockdown + profiles, new-app watch **with auto-block**, and the full
rootless package-manager toolkit (enable/disable/force-stop/clear/uninstall
plus the appops/component scalpels).

**Deferred (understood, not yet built):** DNSCrypt (no new property over
DoT/DoH), per-PID and per-app IP/port rules (root iptables tier), and a live
per-connection IP:port monitor (Fyrypt). None block the "largely finished"
milestone — each is an additive tier, not a hole in the core.

Everything here runs inside Godwall's own code paths through the shared
Elevation Shizuku/Yojimbo shell — the firewall depends on Yojimbo, not on any
donor app being installed.
