# Godwall — donor absorption ledger

> **Method correction (2026-08-02).** An earlier pass wrote the method below as
> "reverse-engineer → re-implement a superior variant, never bundle the donor."
> That is **mimicry**, and it was wrong. It produced ~167 hand-written files in
> this repo containing **zero** donor code, then recorded them as "Done."
>
> The actual method is two staged phases:
>
> 1. **Stage 1 — graft.** Transplant the donor's real source and real layouts
>    into the tree and get them running. Not a lookalike: the donor's own code
>    paths, byte-identical on the way in, so it can be diffed against upstream.
> 2. **Stage 2 — replace.** Only *after* the graft is confirmed working, replace
>    the donor's parts piece by piece with native Godwall implementations.
>
> Everything marked "Done" below is a **stage-2-shaped native lookalike written
> without a stage-1 graft under it.** Those rows are not deleted — the code is
> real and is probably the right replacement target — but they must not be read
> as donor absorption. Stage 1 for InviZible begins at `donor/invizible/`
> (see its `PROVENANCE.md`); stage 1 for the other three donors has not started.

Godwall (the understory firewall) absorbs a set of donor apps. This ledger tracks,
per donor, what the donor does, how Godwall covers it, and where a gap remains.

A row is "stage-2 done" when the capability runs inside Godwall's own code paths
(the Elevation Shizuku/Yojimbo shell, the DNS-filter tunnel, or the policy
backends), with honest degradation when a privilege isn't granted. A row is
"stage-1 done" only when the donor's own code for it is in-tree and runs.

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

> Read every "Absorbed" claim below as **stage-2 native code with no stage-1 graft
> beneath it.** The capability exists in Godwall's own paths; it is not evidence
> that any donor was absorbed. Stage-1 status per donor:
> **InviZible — source + layouts grafted** (`donor/invizible/`, engine binaries and
> build wiring still pending); **RethinkDNS, De1984, Fyrypt — not started.**

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
