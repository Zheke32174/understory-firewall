# :elevation

Optional-elevation broker for the Understory suite. **The suite is rootless by
default.** Nothing in this module runs unless the user has installed
[Shizuku](https://github.com/RikkaApps/Shizuku) **and explicitly granted this
app access**. Elevated actions only *light up* when a tier is granted; they
never gate core functionality and never auto-grant.

> **Ships the SHIZUKU tier only.** `ElevTier.DHIZUKU` (the delegated
> Device-Owner tier) is **stubbed/deferred** in this build: the `Dhizuku-API`
> artifact is published only on JitPack (`com.github.iamr0s:Dhizuku-API`), which
> does not resolve reliably on CI, so its dependency and code path are removed.
> The `DHIZUKU` enum value is kept and `requestDhizuku()` is a no-op returning
> `false`, so `availableTiers`/`grantedTier` never surface it. Restoring the
> tier (likely by **vendoring** the API) is a follow-up — see `DEFERRED` note in
> `build.gradle.kts`.

The `ElevTier` enum still defines all three values — `NONE` (rootless),
`SHIZUKU` (privileged shell at the granted uid), and `DHIZUKU` (deferred; see
above) — so switching the tier back on is a localized change.

## Using the broker

Prefer **capability predicates** over tier checks in feature code — ask "can I
block an app's network?", not "is Shizuku present?":

```kotlin
if (Elevation.canControlAppNetwork(ctx)) {
    when (val r = Elevation.setAppBackgroundNetworkBlocked(ctx, pkg, blocked = true)) {
        is Outcome.Success     -> toast("Blocked")
        is Outcome.Unsupported -> showRootlessFallback(r.reason)
        is Outcome.Failed      -> toast(r.message)
    }
} else {
    // rootless path — e.g. deep-link to Settings > Network > Data usage
}
```

High-level helpers never throw to the UI — they return a sealed `Outcome`
(`Success` / `Unsupported` / `Failed`). Only the low-level `runShell` throws
`NotElevated` when no shell tier is granted; gate it on `canRunShell(ctx)`.

Drop-in UI: `ElevationCard(unlocks = […], rootlessFallback = "…", onRootlessFallback = { … })`.
It shows the current tier, an honest "what this unlocks / rootless fallback"
explanation, and a grant button **only when a tier is actually grantable** —
never a dead/disabled button. For custom layouts, read
`rememberElevationState()` and render your own.

## Consumer manifest wiring (per app)

A consuming app opts in by adding the following. **Do all of this in the app's
own manifest** — the module ships no app-level elevation hooks by design.

### Shizuku

```xml
<!-- Permission the Shizuku manager checks when this app requests access. -->
<uses-permission android:name="moe.shizuku.manager.permission.API_V23" />

<application …>
    <!-- Shizuku hands the app a binder through this provider. -->
    <provider
        android:name="rikka.shizuku.ShizukuProvider"
        android:authorities="${applicationId}.shizuku"
        android:multiprocess="false"
        android:enabled="true"
        android:exported="true"
        android:permission="android.permission.INTERACT_ACROSS_USERS_FULL" />
</application>
```

The shell `UserService` (`com.understory.elevation.shizuku.ShellUserService`)
is **not** declared in the manifest — Shizuku instantiates it by name across the
process boundary from the `UserServiceArgs` the broker builds. It ships inside
`:elevation`, so the app inherits it by depending on this module. The
`consumer-rules.pro` keeps it (and the `IShellService` AIDL stub) from being
stripped by R8.

### Dhizuku

*Deferred — no wiring needed in this build.* The `Dhizuku-API` dependency is not
compiled in (see the note at the top), so there is nothing to merge and no
per-app manifest step. When the tier is restored, the `Dhizuku-API` AAR merges
its own `<uses-permission android:name="com.rosan.dhizuku.permission.API" />`
and the `<queries>` block, so still **no per-app manifest copy is required** for
Dhizuku — just depend on `:elevation`.

## What each helper maps to

Every helper currently runs the **Shizuku (shell)** path; the Dhizuku column
documents the intended mapping for when the deferred tier is restored (it is not
executed in this build).

| Helper | Shizuku (shell) | Dhizuku (DPM, as Device Owner) — *deferred* |
|---|---|---|
| `setPrivateDns` | `settings put global private_dns_mode/_specifier` | `setGlobalSetting` |
| `setAppBackgroundNetworkBlocked` | `cmd netpolicy add/remove restrict-background-blacklist <uid>` | *Unsupported* — no per-app metered DPM API (reported honestly) |
| `revokePermission` | `pm revoke <pkg> <perm>` | `setPermissionGrantState(…DENIED)` |
| `forceStop` | `am force-stop <pkg>` | suspend+unsuspend cycle (closest owner effect) |
| `uninstall` | `pm uninstall <pkg>` | `setApplicationHidden(true)` (owner equivalent) |
| `setAppSuspended` | `pm suspend/unsuspend <pkg>` | `setPackagesSuspended` |

Where a tier has no faithful equivalent, the helper returns `Outcome.Unsupported`
with a precise reason rather than silently doing something different.

## Dependencies

- `dev.rikka.shizuku:api:13.1.5`, `dev.rikka.shizuku:provider:13.1.5` (mavenCentral)
- `:common-security` (UnderstoryTheme tokens for the shared card)
- `org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1`
- ~~`com.github.iamr0s:Dhizuku-API` (JitPack)~~ — **removed / deferred** (JitPack
  does not resolve on CI; the DHIZUKU tier is stubbed until the API is vendored).

## Security invariants (unchanged)

No elevation is ever required. No tier is auto-granted. The vault threat-model
invariant holds — this module renders/types no recovery secret. Honest
degradation: an ungrantable action shows the rootless path, never a dead button.
