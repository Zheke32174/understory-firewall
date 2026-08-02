# Godwall — Tailscale node + egress chain + privileged/container transports

Tailscale is the **most important firewall donor**, and its absorption reframes
Godwall from "a firewall that gets out of Tailscale's way" into "a firewall that
**is** a Tailscale node and an egress-chain orchestrator." This doc captures that
architecture and the cross-app defensive layer it plugs into.

## From coexistence to being the node
Android has ONE VPN slot. Today Godwall detects Tailscale (`com.tailscale.ipn`)
holding the slot and stays slot-free (see `VpnSlotProbe`, the tier overview's
XOR-Tailscale note). Absorbing Tailscale inverts this: Godwall runs the tailnet
**inside its own `FirewallVpnService`** (userspace WireGuard netstack via
Tailscale's Go data plane, libtailscale), so the single slot delivers the tailnet
AND the DNS/app firewall at once. `TailscaleController` is the seam; until
libtailscale is linked it reports config-only status and never fakes a tailnet
(honest-stub, same discipline as Genji's ArtCore).

Config lives in `TailscaleSettings`: login server (Tailscale or self-hosted
Headscale), auth key, exit node, accept-routes, MagicDNS, advertise-exit, hostname.

## Node AND endpoint chain
Godwall is not just a node — it's a **chainable egress orchestrator**. Traffic off
the tun runs an ordered `EndpointChain` of typed `ProxyHop`s and egresses from the
last one:

```
tun → DNS filter → [ Tailscale node → SOCKS5 → Container → … ] → internet
```

Tailscale is one hop type: "link the tailnet, then hop onward" into further
proxies. Hop types (`ProxyHop`): Tailscale (node + optional exit node), SOCKS5,
HTTP CONNECT, WireGuard (raw), Shadowsocks, Tor, **Container**, Direct. Order is
the route; hops add/remove/reorder. `ProxyChainController` validates the chain and
reports per-hop readiness honestly — a chain with any PENDING hop is saved and
previewed but never silently half-run.

## Above and beyond a normal Android VPN: privileged + container transports
A normal Android VPN/firewall is stuck in **userspace** (VpnService + in-process
sockets). Godwall reaches past that using capabilities the suite already ships,
giving each hop a `Transport`:

- **USERSPACE** — the default; pure in-tunnel sockets. No privilege assumed.
- **KERNEL** — real routing via the privilege brokers (Yojimbo's Shizuku/root
  shell): network namespaces, nftables/iptables policy routing, per-UID marks.
  This is firewalling the OS can enforce, not just what a userspace tunnel can drop.
- **CONTAINER** — a hop served *inside a container server*: the relay/routing stack
  runs in an nspawn/stratum/proot container (on-device, or exposed by a sibling
  app), and Godwall forwards into it. A container can run a full proxy/routing
  stack that a sandboxed Android app never could.

Each tier **degrades honestly** to USERSPACE when its privilege/container backend
is absent — the controller says so rather than pretending.

## Container-server donors (cross-app)
The CONTAINER transport is backed by container-server donors that extend **all**
the apps, not just Godwall:

- **Docker-on-Android** (e.g. `com.pavit.docker`) — a Docker/container manager for
  Android. As a container server it lets Godwall run proxy/routing containers,
  gives Masamune a container runtime for the ryznix/second-OS layer, and gives
  Yojimbo privileged container orchestration. One donor, capability for the whole
  suite.
- The `underhall` stratum model (nspawn + distro strata under `/strat/<name>`) is
  the same idea at the substrate level.

## No external device needed: ryznix container as a local "external" node
A normal multi-hop setup needs a *second machine* to be the next node/exit. The
suite removes that requirement. **ryznix** — the second OS being built into
Masamune (a KernelSU guest userspace) — plus the app family can **launch a node
inside a local container and treat that container as external to Android.** From
Android's point of view the container is a separate host: it can run tailscaled,
a SOCKS/WireGuard relay, an exit node, a full routing stack — reachable over the
container's own network interface. So Godwall's chain can hop tun → Tailscale →
**local-ryznix-container-node** → internet, getting the exit-node / multi-hop
posture **on one device, no external hardware.** The `CONTAINER` transport is the
firewall-side handle for exactly this; ryznix + the container-server donors
(Docker-on-Android, the underhall strata) are what make the "external" node local.

## Honest status (what is real vs seam today)
- REAL: the chain model, typed hops, ordering, persistence, per-hop readiness, the
  Tailscale config surface, and the transport tiering + honest degradation.
- SEAM (PENDING): the data planes — libtailscale (Tailscale), the userspace
  SOCKS5/HTTP clients, WireGuard/Shadowsocks/Tor transports, and the KERNEL/
  CONTAINER establishment via the privilege brokers + container servers. Each is a
  declared backend the controller lights up as it lands. Nothing claims to carry
  traffic until its backend is linked.

## Build order
1. Userspace SOCKS5 + HTTP CONNECT hops (no external dependency — pure in-tunnel).
2. Link libtailscale → Tailscale node in the slot (the headline donor).
3. KERNEL transport via the Yojimbo shell (netns/nftables).
4. CONTAINER transport via a container-server donor (Docker-on-Android / strata).
5. WireGuard / Shadowsocks / Tor hops as demand dictates.
