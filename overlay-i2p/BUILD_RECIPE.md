# Bundling the i2pd binary (phase β)

This document is the future-Claude / future-contributor instruction
sheet for landing the actual `i2pd` native binary in the
`:overlay-i2p` module. The Kotlin scaffolding is already there;
phase β replaces the `phase β not yet implemented` error path in
`I2pProxyService.startBinary()` with a real ProcessBuilder launch.

## Why we ship our own binary

`androidx.webkit.ProxyController` can be pointed at any localhost
HTTP proxy. To use I2P from the WebView, *something* has to be
listening on that local port — and that something is i2pd (or an
equivalent). We bundle our own copy rather than depend on a separate
"I2P installed?" probe because:

1. The supervisor lifecycle is part of our trust model. We control
   the version, the config, the data directory permissions.
2. The browser starts/stops the proxy as the user toggles. A user
   who hasn't installed an external I2P app shouldn't be told "go
   install another app first."
3. Reproducible builds want one source of truth. An external
   dependency has its own update cadence and signing chain.

## NDK build outline

i2pd is a C++ project (CMake). Cross-compiling for Android requires
the Android NDK. The official i2pd repo has an `android/` subtree
with a `build_locally.sh` and `Application.mk` configuration; the
recipe below is a thin wrapper.

```sh
# Prerequisites:
#   - Android NDK r26+ (API 21+ NDK toolchains)
#   - CMake 3.18+
#   - The four standard ABIs Android still ships: arm64-v8a, armeabi-v7a, x86_64
#     (we drop x86 — 32-bit Intel Android is ~0% of the install base)

git clone https://github.com/PurpleI2P/i2pd.git
cd i2pd
git checkout 2.55.0   # pin the version we ship
cd android
ANDROID_NDK_HOME=$NDK ABI_LIST="arm64-v8a armeabi-v7a x86_64" \
    ./build_locally.sh
```

This produces `libs/<abi>/libi2pd.so` for each ABI.

## Drop into `:overlay-i2p`

```
android/overlay-i2p/
  src/main/jniLibs/
    arm64-v8a/libi2pd.so      ← from build_locally.sh
    armeabi-v7a/libi2pd.so
    x86_64/libi2pd.so
```

AGP picks up `jniLibs/<abi>/lib*.so` automatically and copies them
into the APK at the expected per-ABI offset. At install time
PackageManager extracts each one to
`/data/app/<pkg>/lib/<abi>/libi2pd.so`. The path is the consumer
app's `applicationInfo.nativeLibraryDir`, which is what
`I2pProxyService.startBinary()` already looks at.

**Why .so for an executable?** Android refuses to extract files from
the APK that aren't named `lib*.so`. If we shipped `i2pd` (no
prefix, no extension) it'd stay zip-compressed inside the APK and
ProcessBuilder couldn't exec it. The `.so` rename is what Orbot
(tor), Briar (mailrunner), and a half-dozen other projects do for
the exact same reason.

## Update `I2pProxyService.startBinary()`

Replace the phase-α error path with the real launch. Sketch:

```kotlin
private fun startBinary() {
    val binDir = File(applicationInfo.nativeLibraryDir)
    val candidate = File(binDir, "libi2pd.so")
    if (!candidate.exists()) {
        I2pStatus.update(I2pStatus.State.BinaryMissing)
        stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); return
    }
    val data = ensureDataDir()
    writeI2pdConfig(data)              // see I2pProvider for values to template in

    val pb = ProcessBuilder(
        candidate.absolutePath,
        "--datadir", data.absolutePath,
        "--conf",    File(data, "i2pd.conf").absolutePath,
    )
    pb.redirectErrorStream(true)
    pb.environment()["HOME"] = data.absolutePath
    process = pb.start()

    Thread({
        // Drain stdout/stderr to logcat so logs survive the supervisor
        // process going away.
        process?.inputStream?.bufferedReader()?.useLines { lines ->
            lines.forEach { android.util.Log.i("i2pd", it) }
        }
    }, "i2pd-stdout").start()

    Thread({
        // Readiness probe: try TCP connect to 127.0.0.1:4444 every
        // second; emit Ready when it succeeds. Bound to 90s, after
        // which we transition to Error("did not become ready").
        if (probeReady(port = 4444, timeoutMillis = 90_000)) {
            I2pStatus.update(I2pStatus.State.Ready(httpPort = 4444, socksPort = 4447))
        } else {
            I2pStatus.update(I2pStatus.State.Error("i2pd did not become ready in 90s"))
        }
    }, "i2pd-readiness").start()
}
```

The actual implementation of `writeI2pdConfig` and `probeReady` is
left for the phase β PR; the comments in `I2pProvider.kt` describe
the config-template surface.

## Reproducible-build coupling

When phase β lands, add the i2pd version + git commit + build
flags to `BUILD_REPRODUCIBILITY.md` so an independent observer can
rebuild a byte-identical APK. NDK toolchain version is already
captured there for the rest of the suite; we just add i2pd's pin
alongside.

## Server-mode opt-in (phase δ)

Out of scope for phase β. When that lands:

- Add a "participate in network" toggle in the I2P UI surface. Off
  by default (client-only). On = generate a transit tunnel
  configuration in `i2pd.conf` (`floodfill = true`, `share = X`).
- Server-mode toggle changes are persistent. They don't auto-revert
  on restart — turning your phone into a participating I2P router
  is a deliberate user act, not a session toggle.
- Bandwidth caps + scheduling (e.g. participate only on Wi-Fi, or
  only when charging) live next to the toggle.

Don't add server-mode in phase β — the security model for a
participating router is different from a client-only router and
deserves its own design pass.
