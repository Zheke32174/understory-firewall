# Closing the Tailscale seam — what `libtailscale` actually is

Findings are from the real `tailscale/tailscale-android` tree, not from docs.

## It is NOT a Maven artifact

The single most important correction. Upstream declares it as a **local file**:

```gradle
// android/build.gradle:168
implementation ':libtailscale@aar'
```

resolved through a `flatDir` repository (`android/build.gradle:24`) pointing at
`android/libs/`. There is no `com.tailscale:libtailscale:x.y.z` to depend on.

The aar is **generated from Go source** by gomobile (`Makefile:44,208-225`):

```make
LIBTAILSCALE_AAR := android/libs/libtailscale.aar
$(GOBIN)/gomobile: ; ./tool/go install golang.org/x/mobile/cmd/gomobile
build-unstripped-aar: $(GOBIN)/gomobile
	$(GOBIN)/gomobile bind -target android -androidapi 26 \
		-tags "$$(./build-tags.sh) $(GOMOBILE_BUILD_TAGS)" \
		-o $(ABS_UNSTRIPPED_AAR) ./libtailscale
```

**So the seam is closeable by including the lib — it just has to be *obtained*,
not *declared*.**

## How to obtain it

1. **Build it** (canonical). Requires a **Go toolchain + gomobile + the Android
   NDK**: clone `tailscale/tailscale-android` and run its `make` target above.
   Go is present in this container; **the NDK is not**, so it cannot be built
   *here* — but it builds fine on any normal dev machine or a CI job with the NDK.
2. **Extract it** from an official Tailscale Android release: the aar's payload
   (`classes.jar` + `jni/<abi>/libgojni.so`) is inside the shipped APK. Faster,
   but you inherit whatever version that APK carries and you should verify it.

Then drop it at **`firewall/libs/libtailscale.aar`**.

Licence note: Tailscale's client is BSD-3-Clause; `libtailscale.aar` is a
redistributable binary of it. Check the licence of the exact build you ship and
add the attribution to `NOTICE` before shipping.

## The wiring is already done — it is a drop-in

`firewall/build.gradle.kts` detects the file:

- **Present** → `implementation(files(libtailscaleAar))` and the extra source dir
  `firewall/src/tailscale/java` joins the `main` source set, so the real backend
  compiles with direct `import libtailscale.*` (no reflection).
- **Absent** → the build still succeeds and `TailscaleController` reports
  `NOT_LINKED`. CI stays green on a clean checkout; a missing optional data plane
  is not a build error.

Gradle logs which path it took at configure time.

## The contract the backend must satisfy

Recovered from `libtailscale/*.go` (gomobile exports Go's capitalised symbols,
and binds Go `interface` types as Java interfaces the app implements).

**Functions Go exposes to us** (`libtailscale.Libtailscale.*`):

```
Start(dataDir, directFileRoot, appCtx)   ServiceDisconnect(...)
RequestVPN(...)                          OnDNSConfigChanged(...)
OnGatewayChanged(...)                    SendLog(...)
SetShareFileHelper(...)
```

**Interfaces WE implement** (Go calls *into* us — this is the bulk of the work):

| Interface | Our side |
|---|---|
| `AppContext` | app services: file paths, prefs, network state |
| `IPNService` | **`FirewallVpnService`** — Go asks it to bring the tun up/down |
| `VPNServiceBuilder` | wrapper over `VpnService.Builder` (routes, DNS, MTU) |
| `ParcelFileDescriptor` | the tun fd handed to Go |
| `NotificationManager` / `NotificationCallback` | status + auth-URL surfacing |
| `InputStream` / `OutputStream` | stream bridging |
| `ShareFileHelper` / `FileParts` | Taildrop (optional — can be stubbed) |
| `LocalAPIResponse` | LocalAPI plumbing |

So the shape is: **Go drives the data plane; our `VpnService` implements
`IPNService`.** That is a well-defined bridge, not open-ended research.

## Why this is a real advantage for us

Upstream's app *is* the tailnet. Ours is a firewall that also runs a tailnet
**inside its own `FirewallVpnService`**, so one VPN slot delivers mesh **and**
the DNS/app firewall — instead of Tailscale and the firewall fighting over the
single Android VPN slot. And because the Tailscale node is just one
`ProxyHop` in the `EndpointChain`, traffic can join the tailnet and then **hop
onward** through SOCKS5/HTTP/container hops, which upstream cannot do.

## Honest status

The **wiring** is real and committed. The **backend implementation** is not
written: it needs to compile against the actual generated API, and that is not
possible in this container (no NDK ⇒ no aar ⇒ no `libtailscale.*` classes).
Writing ~9 interface implementations blind against a generated API would produce
plausible, uncompilable code — exactly the failure mode this project refuses.
Drop the aar in and the backend is the next commit.
