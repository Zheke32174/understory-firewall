# firestack — RethinkDNS's data plane, and what it unlocks

**Status: BUILT.** `godwall-next/libs/firestack.aar`, 28.9 MB, four ABIs
(`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`), 129 Java classes over a 19.5 MB
`libgojni.so` per ABI. Built from `celzero/firestack` at `d182b8f` via
`make intra`; see `tools/donor-assets/fetch.sh firestack` for the recipe and the
four blockers it works around.

Not committed — `.gitignore` covers `godwall-next/libs/*.aar`. It is a large
third-party binary with its own licence (MPL-2.0), and vendoring it silently
would hide both facts.

## Why this matters more than it looks

Godwall's own engine filters **DNS only**: the tun routes one address, and every
lookup is answered or forwarded. That is the honest ceiling of a rootless
userspace tun written from scratch, and the Shield screen says so on every launch.

firestack is a full **tun2socks** stack. It moves the ceiling from "decides which
names resolve" to "decides where every flow goes", and it does it with Go code
that RethinkDNS ships to real users rather than something invented here.

## What it actually provides

Read off the built `.aar`, not off documentation:

**`com.celzero.firestack.intra.Intra`** — the entry point.

```java
Tunnel connect(long fd, long mtu, long, String, String, DefaultDNS, Bridge)
```

`fd` is the tun file descriptor Godwall already owns from
`VpnService.Builder.establish()`. So this slots in *below* the existing
`GodwallVpnService` rather than replacing it — Godwall keeps the slot, the
notification, the consent flow and the per-app bypass; firestack becomes what
reads the fd.

**DNS transports, all native, no extra payload:**

```java
addDoHTransport(t, id, url, ips)
addDoTTransport(t, id, url, ips)
addODoHTransport(t, id, endpoint, target, ips)
addDNSCryptTransport(t, id, stamp)
addDNSCryptRelay(t, stamp)
addDNSProxy(t, id, addr)
addProxyDNS(t, proxy)
```

**This is the important one: DNSCrypt arrives here.** `docs/DONOR-ASSETS.md`
listed InviZible's `dnscrypt-proxy` ELF as OPEN — a per-ABI binary from a
separate toolchain repo that we would have had to build and ship renamed `.mp3`.
firestack implements DNSCrypt and anonymized-DNSCrypt relays in Go, so that
whole payload is no longer on the critical path. ODoH comes along with it, which
InviZible does not offer at all.

**`Tunnel`** — `getProxies()`, `getResolver()`, `getServices()`, `stat()`
(`NetStat`, with `TCPStat`/`UDPStat`/`ICMPStat`/`TUNStat`/`NICStat`),
`setPcap()`, `setLinkAndRoutes()`, `closeConns()`.

**`backend.Proxies` / `backend.Proxy` / `backend.WgKey`** — SOCKS5, HTTP, and
**WireGuard**. Godwall's `ChainDialer` composes SOCKS5 and HTTP CONNECT hops
itself; firestack adds WireGuard as a hop type, which the old build listed in its
add-hop UI with nothing behind it. A hop type you can pick should be a hop type
that carries traffic — now it can be.

**`backend.RDNS` / `RDNSResolver` / `RDNSInfo`** — the RethinkDNS blocklist stamp
format, i.e. the on-device blocklist selection the donor is known for, rather
than our single bundled `base.hosts.gz`.

**`backend.Router` / `IpTree` / `RadixTree`** — IP-rule matching, which is what
the FIREWALL section's global IP/port rules need.

## How to wire it

`godwall-next/build.gradle.kts` already has the pattern from libtailscale — an
optional local `.aar` that flips a `BuildConfig` flag and gates a source set:

```kotlin
val firestackAar: File = (
    (project.findProperty("firestack.aar") as String?) ?: System.getenv("FIRESTACK_AAR")
    )?.let(::File) ?: file("libs/firestack.aar")
val hasFirestack: Boolean = firestackAar.isFile
// buildConfigField("boolean", "HAS_PACKET_DATAPLANE", hasFirestack.toString())
// sourceSets: if (hasFirestack) java.srcDir("src/firestack/java")
// dependencies: if (hasFirestack) implementation(files(firestackAar))
```

Keep the same discipline as the mesh seam:

- **Present** ⇒ the packet tier compiles and Godwall can enforce per-flow.
- **Absent** ⇒ the build still succeeds, and the packet-tier controls report
  absent rather than silently degrading to the DNS-only engine while still
  claiming to block. Degrading quietly is the specific failure this suite exists
  to argue against.

`proguard.txt` inside the aar already carries the rules R8 needs:

```
-keep class go.** { *; }
-keep class com.celzero.firestack.** { *; }
```

AGP consumes those automatically from the aar, so no manual `proguard-rules.pro`
entry is required — unlike libtailscale, whose reflective link needed an explicit
`-keep` for `LibtailscaleBackend`.

## Two things to get right when wiring

1. **One tun, two consumers.** Godwall's `GodwallVpnService` currently reads the
   fd directly in its own pump thread. firestack's `connect()` takes ownership of
   that same fd. Both cannot read it. The wiring must choose per mode — DNS-only
   engine *or* firestack — and the UI must say which one is live, because "armed"
   means something different in each.
2. **Size.** 19.5 MB of native code per ABI. Without ABI splits the APK grows by
   roughly 78 MB. Either enable splits or restrict `abiFilters` to `arm64-v8a`
   for sideload builds, and say which in the release notes.

## Licence

MPL-2.0. Any artifact we distribute carrying it must include the licence and
attribution in `NOTICE`. Reverse-engineering a donor to build a superior native
variant is the method; shipping a donor's binary as if it were ours is not.
