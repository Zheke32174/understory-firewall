# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately, not in a public issue. Use GitHub's
**"Report a vulnerability"** (Security → Advisories) on this repository, or open a
minimal issue asking for a private channel without including exploit detail.

Please include: the affected version (`versionName` from `app/build.gradle.kts`),
the device/Android version, and the smallest reproduction you can share. There is
no server and no user account behind this app — the attack surface is entirely
on-device — so reports are almost always about the app's local behaviour (the
WebView compartment, the Shizuku allowlist, the evidence vault, the exporters).

## The invariants this app is built to keep

These are not features that can be traded off later; they are commitments, and
several are enforced by tests (`app/src/test/.../InvariantsTest.kt`) so they
cannot decay silently. A security report that shows any of them is violated is
treated as high severity.

1. **It does not radiate.** There is no transmit/jam/spoof path of any kind. Every
   "RF/radar/TDMA" source is an *audio* model; the only radio use is standard,
   certified BLE/Wi-Fi *scanning* via Android's own APIs. See
   [`ETHICS.md`](ETHICS.md) — this line does not move regardless of how a feature
   request is framed.
2. **Read, don't act.** Radios and sensors are inputs only. Nothing here acts on
   another device's traffic, receiver, or radio (no ARP spoofing, no MITM, no
   band/RAT switching, no GNSS spoofing).
3. **The evidence vault cannot be emptied.** `SecureLog` is append-only,
   hash-chained, and StrongBox-sealed when available; it exposes no
   delete/clear/wipe/truncate method, and no page-facing bridge may either.
   Rotation keeps the rotated segment.
4. **Page-facing bridges are read + append only.** The WebView is the largest
   attack surface; every `@JavascriptInterface` it can reach can read state and,
   at most, *append* to the append-only log — never raise, edit, suppress, or
   delete a finding.
5. **The vault is location-free and identity-free.** Positions live only in the
   separate tower log (never uploaded, exported only on an explicit press). The
   case report inherits this: it carries findings and their integrity proof,
   never GPS/SSID/cell identity.

If you find a way to make the app transmit, to empty or forge the vault, to make
a page-facing bridge mutate a finding, or to get location/identity into the
vault or the case report, that is exactly the class of bug this project most
wants to hear about.

## Supported versions

The `main` branch and the most recent tagged `versionName` receive fixes. Older
builds do not.
