# Contributing to EMI Chaos Bench

## Build & test

Requires **JDK 17** and the Android SDK (`compileSdk`/`targetSdk` 34, `minSdk` 26).

```bash
# copy the example and point it at your SDK
cp local.properties.example local.properties   # set sdk.dir=/path/to/Android/sdk

./gradlew testDebugUnitTest     # pure-JVM unit tests — the fastest signal
./gradlew lintDebug             # Android lint
./gradlew assembleDebug         # APK -> app/build/outputs/apk/debug/
```

The unit tests run on a plain JVM (no device, no Robolectric). `org.json`'s real
implementation is on the test classpath so `JSONObject` actually works there.

## The line every contribution keeps

Read [`ETHICS.md`](ETHICS.md) and [`SECURITY.md`](SECURITY.md) before writing a
feature. In one sentence: **the app observes what is already reaching the device
and masks local audio — it never transmits, never acts on anyone else's device
or radio, and never lets its evidence store be emptied, forged, or filled with
location/identity.** Pull requests that add a transmit/jam/spoof path, a
destructive vault method, a mutating page bridge, or location/identity into the
vault will be declined — this has been asked for repeatedly and declined every
time, and `InvariantsTest` fails the build if any of it slips in.

## How this codebase is shaped (match it, don't fight it)

- **No new UI framework.** Screens are plain `android.widget` built imperatively
  from the `Nx` toolkit (`ui/NativeShell.kt`) — no Compose, no Material. A new
  screen is a `ScrollView` built in `init{}`; see `ui/AuditScreen.kt` /
  `ui/DataScreen.kt` as templates, and add it to `ShellView.DESTS` + `show()`.
- **Feature modules return JSON strings.** A detector is a plain
  `class Foo(ctx, log)` with `scan()`/`cached()` returning `org.json` strings,
  owned by the service via a `MaskerService.ensureFoo(ctx)` double-checked
  factory, and driven from the background timer. State is JSON, not StateFlow.
- **Nothing touches `SecureLog` or a detector on the main thread.** Screens
  gather through `Async.load(view, gather, apply)`; the UI thread only assigns
  strings to `TextView`s.
- **Make judgement logic JVM-testable.** Pure logic goes in a dependency-free
  object (`AuditFusion`, `CaseReport`) or takes an injected sink lambda
  (`TrackerWatch`), so it can be tested against fabricated inputs with no device.
  New heuristics ship with a test in that style.
- **A new hard invariant gets a test.** If your change makes a promise
  ("this bridge can't mutate", "this stays bounded"), assert it in
  `InvariantsTest` so a later refactor can't quietly break it.
- **Comments stay honest.** If you change a count, a bound, or a shape a comment
  describes, update the comment in the same diff — the reflection/source-scan
  tests strip comments precisely so documentation and behaviour can't diverge.

## Commits & PRs

Small, described commits. State in the PR what you built, what you deliberately
did *not* build, and whether you ran the build (and on what). If you couldn't run
it, say so — an honest "not built here" is worth more than an implied green.
