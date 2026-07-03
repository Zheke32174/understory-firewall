# Firewall — phase 2 boundary

Written to close the phase-1.5 honest-labelling release blocker: the UI
must not imply in-tunnel DNS enforcement, because there is none yet.

## What is enforced today (phase 1.5)

- **App blocking / port-derived blocking** — the VpnService tun captures
  blocked apps' traffic and drops it. Fully live.
- **DNS: system Private DNS only.** The DNS-preferences screen stores a
  provider selection; the selection is informational. The only apply
  path is Android's Private DNS (DoT):
  - programmatic via `PrivateDnsApplier.apply()` when
    `WRITE_SECURE_SETTINGS` is ADB-granted,
  - otherwise the Settings deep-link + paste flow.
  The UI reads the live `Settings.Global` value back
  (`PrivateDnsApplier.current()`, shown in the "Active now" card) so the
  user sees what is actually in effect, not what we last wrote.
- **dnscrypt-proxy** — selecting a DNSCrypt provider starts the bundled
  proxy as a local foreground service on `127.0.0.1:5354`. No app DNS
  reaches it; the UI and its notification say "running — app DNS not
  routed here yet".

Experimental code that exists but is deliberately NOT claimed by the UI:
`DnsRedirector` plus `FirewallVpnService`'s DNS-redirect mode (tun routes
a fake resolver IP and forwards UDP DNS to the local proxy). It is not
release-qualified, and it pauses app- and port-blocking while active —
treat it as a preview of phase 2, not a feature.

## What phase 2 adds

1. **Tun-level DNS forwarding** — apps' UDP port-53 queries captured in
   the tun and forwarded to the selected resolver (upstream or the local
   dnscrypt-proxy), making the provider selection *enforced in-tunnel*
   and composing with app/port blocking in a single tun session
   (userspace forwarder work).
2. **Per-domain rules** — parse DNS inside the tun to allow/deny by
   domain name.

Until both land, user-facing copy must keep saying: "selection is
informational; applied via system Private DNS only".

Numbering note: older code comments use "Phase B/C" and "phase 3/4" for
internal sub-steps of the same work; the roadmap term for this whole
tranche is **phase 2**.
