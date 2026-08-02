# Suite design language

> "change layouts, make menu appearances unique and matching." — user
>
> **Matching** comes from one shared system: neutrals, type scale, spacing grid,
> shapes, chrome, motion, and the component vocabulary. Those are identical in all
> five apps and an app has no freedom to vary them.
>
> **Unique** comes from exactly three per-app knobs: an **accent pair**, a **motif**,
> and a **pillar set**. Nothing else.
>
> Five unrelated designs is the failure on one side. Five identical apps in five
> icons is the failure on the other — and it is the one we actually shipped
> (Yojimbo and Genji both ran `UnderstoryAccent.MANAGER`, the same seed, so on
> device they *were* the same app twice).

Per `docs/REBUILD-CHARTER.md`, claims here are marked with their state:
**[verified]** = read out of the source in this tree; **[proposed]** = designed
here, not yet written; **[measured]** = a number computed, shown with its inputs.
Nothing below is described as working because it compiles.

---

## 0. Inventory — what the shared system already provides

**[verified 2026-08-02]** by reading
`common-security/src/main/java/com/understory/security/`. This is more than the
brief assumed: section headers, empty/error states and a tabbed shell already
exist. Do not rebuild them.

| File | LoC | Provides |
|---|---|---|
| `ui/theme/Color.kt` | 142 | Ink900→Ink600 dark neutrals, Fog100→Fog500 text ladder, Paper50/Paper100/Slate900/Slate600 light neutrals, `Danger`/`Caution`/`Success`/`SuccessDim`, `understoryDarkColors(seed)`, `understoryLightColors(seed)`, `SuiteSemanticColors(warning/success/dim + containers)`. Base hues are `internal` — apps physically cannot reach a raw hex. |
| `ui/theme/Spacing.kt` | 23 | `Spacing(xs 4, sm 8, md 12, lg 16, xl 24, xxl 32)` via `LocalSpacing`. |
| `ui/theme/Shape.kt` | 21 | `UnderstoryShapes` — 4 / 8 / 12 / 20 / 28 dp. |
| `ui/theme/Type.kt` | 81 | `UnderstoryType`; **14sp body floor**; 12sp captions; 11sp `labelSmall` reserved for `SuiteStatusFooter` only. |
| `ui/theme/Theme.kt` | 128 | `UnderstoryTheme(accent, darkTheme, dynamicColor, content)`; `UnderstoryAccent` enum (13 entries, incl. the five); `UnderstoryTheme` accessor object (`.colors .semantic .spacing .type .shapes`); `LocalUnderstoryThemeActive` legacy-fallback flag. |
| `ui/components/SuiteComponents.kt` | 314 | `SuiteSectionHeader`, `SuiteCard`, `SuiteListRow`, `SwitchRow`, `SliderRow`, `RevealToggle`. All tap-jack-hardened via `secureClickable`, 48/56dp minimum targets, merged TalkBack semantics. |
| `ui/components/SuiteScaffold.kt` | 85 | Single-leaf-screen chrome: `TopAppBar` + optional back + `SuiteStatusFooter`. |
| `ui/components/SuiteNavShell.kt` | 241 | `SuiteTab`, `SuiteNavShell`, `MAX_PRIMARY_TABS = 5`. Enforces the five-tab ceiling: past five it renders four tabs + **More** and puts the rest in a `ModalBottomSheet`. Bottom bar shows only at a tab root. |
| `ui/components/SuiteStates.kt` | 270 | `UiState` sealed interface, `LoadingState`, `EmptyState`, `ErrorState`, `UiStateHost`, `FatalScreen`. |
| `ui/components/SuiteDialogs.kt` | 155 | `ConfirmDestructiveDialog` + hold-to-confirm. |
| `nav/SuiteNav.kt` | 212 | `SuiteNav` (`push`/`selectTab`/`pop`/`popTo`/`minimize`/`back`, `depth`, `trail`, `currentAs<E>()`), `rememberSuiteNav`, `SuiteNavHost` — **the app's only `BackHandler`**. Back contract: overlay → pop one → home tab → `moveTaskToBack` (never `finish()`). |
| `SecureButton.kt`, `SuiteStatusFooter.kt`, `Diagnostics.kt` | — | `SecureButton`, `SecureOutlinedButton`, `secureClickable`, the shared status footer, the diagnostics ring. |

### 0.1 What is missing for a rich multi-screen app

| Capability | Present? | Verdict |
|---|---|---|
| Section headers | **Yes** — `SuiteSectionHeader` | Keep; add a motif rule (§2.4). |
| Empty / error / loading / fatal states | **Yes** — `SuiteStates.kt` | Keep; add `PermissionState` + `DegradedState` (§4.7). |
| Tabs (top-level) | **Yes** — `SuiteNavShell`, ceiling 5 + overflow sheet | Keeps ~8–15 destinations legible. Does not scale past that. |
| **Nav rail / drawer** | **No** | Nothing adapts to width. A tablet or unfolded foldable renders a phone bottom bar. §3.4. |
| **In-screen tab strip / segmented control** | **No** | Every lateral split inside a screen has to become another push. §4.6. |
| **Dense list variants** | **No** | `SuiteListRow` has a hard 56dp floor. A 900-row app list or a live DNS query log needs ~36–40dp. §4.5. |
| **Status chips** | **No** | Every app hand-rolls its state pill. This is where stray hexes come back. §4.4. |
| **Search / jump-to** | **No** | With dozens of destinations, browsing is not a navigation strategy. §3.5. |
| **Breadcrumb / trail UI** | Data only — `SuiteNav.trail` exists, nothing renders it | §4.3. |
| **Hierarchical route model** | **No** | `SuiteNav` is a flat `List<String>`; a route carries no parent. §3.1. |
| **Route catalog / generated menus** | **No in common-security.** Masamune has a local one (`dev.pleiades.masamune.nav.RouteCatalog`, 85 LoC, salvaged from a donor's 765-line registry) | The pattern is proven in-tree. Promote it. §3.2. |
| **Light-safe accents** | **No** | Hard fail, measured in §2.1. |
| **Non-colour app differentiation** | **No** | Colour alone excludes ~8% of male users. §2.4. |

### 0.2 The distribution problem (must be read before §5)

**[verified]** `common-security/src/main/java/com/understory/security/` is
**byte-identical** across `understory-firewall`, `understory-yojimbo` and
`understory-genji` (`diff -rq` returns nothing). It is vendored, not shared.
Meanwhile:

- **`tracendroid/masamune-next`** has a **hand-written mirror** at
  `dev/pleiades/masamune/ui/theme/Theme.kt`, whose own header says it copies the
  palette "rather than pretending to depend on a module that is not here." It
  declares `val MasamuneSeed = Color(0xFF2FD3C3)` — **the exact seed of
  `UnderstoryAccent.YOJIMBO`.** The reported bug is already reproducing in the
  next generation, in a different repository, by a different mechanism.
- **`emi-chaos-bench`** (Chaos Orb) is a standalone Gradle build with
  `include(":app")` only. It has no `common-security` and no `UnderstoryTheme`
  usage at all.

So four copies, one mirror, one abstainer. Any design language that does not fix
distribution is a design language that will diverge again within one round.

---

## 1. The shared system (unchanged, restated as law)

These are not per-app choices. An app that varies one of them is out of spec.

1. **Ground.** `background = Ink900 #0E1512` dark / `Paper50 #FAFAFA` light. The
   "forest floor" near-black is green-biased; accents read as a constellation
   against it. Never a pure `#000` or `#FFF`.
2. **Ladder.** Surfaces `Ink900 → Ink800 → Ink700`; text `Fog100 → Fog300 → Fog500`.
   Exactly three surface levels. A fourth means the hierarchy is wrong.
3. **Grid.** 4dp. All spacing via `UnderstoryTheme.spacing`. No bare `.dp` for layout.
4. **Type.** `UnderstoryType`. 14sp body floor. 11sp exists only in the status footer.
5. **Shape.** Cards `medium` 12dp, dialogs `large` 20dp, chips/rows `small` 8dp,
   micro `extraSmall` 4dp.
6. **Semantics are warm, brand is cool.** `Danger` red, `Caution` amber,
   `Success` green. **No app accent may occupy a warm hue** (§2.2). This is the
   single rule that makes a status readable at a glance in all five apps.
7. **Touch.** 48dp minimum, 56dp for list rows, via the shared components.
8. **Chrome.** One `TopAppBar`, one bottom/rail/drawer affordance, one snackbar host,
   one `BackHandler` — all owned by the shell, never by a screen.
9. **Motion.** 150ms `fastOutSlowIn` for state, 250ms for navigation, 0ms when
   `Settings.Global.TRANSITION_ANIMATION_SCALE == 0`. No decorative motion in a
   security tool: motion means something changed.
10. **Dynamic colour stays off.** Wallpaper-derived hues would let an arbitrary
    colour repaint a "safe" chip. Plumbing exists; default is `false`; leave it.

---

## 2. Per-app identity

### 2.1 Why the current accents fail — measured

**[measured]** hue is HSL hue angle; contrast is WCAG 2.x on the stated ground.

| Pair | Separation | Consequence |
|---|---|---|
| `GODWALL #E7B24A` (39.7°) vs semantic `Caution #FFB74D` (36.0°) | **3.7°** | Godwall's brand colour *is* its warning colour. A firewall cannot signal caution with colour. |
| `MASAMUNE #FF7A45` (17.1°) vs `Danger #EF5350` (1.2°) | **15.9°** | Same defect, error-flavoured. |
| `MASAMUNE` vs `GODWALL` | **22.6°** | Two apps read as the same warm app. |
| `YOJIMBO #2FD3C3` (174.1°) vs `CHAOS_ORB #4FE0FF` (190.6°) | **16.4°** | Two apps read as the same cyan app. |
| `MasamuneSeed #2FD3C3` vs `YOJIMBO #2FD3C3` | **0.0°** | Byte-identical. |

And the light theme is not "half-done", it is **broken**:
`understoryLightColors(seed)` sets `primary = seed` with `onPrimary = Paper50`
(white). White text on the current seeds measures:

| Seed | White-on-accent |
|---|---|
| `#2FD3C3` Yojimbo | **1.79 : 1** |
| `#4FE0FF` Chaos Orb | **1.50 : 1** |
| `#E7B24A` Godwall | **1.85 : 1** |
| `#FF7A45` Masamune | **2.48 : 1** |
| `#B07CF5` Genji | **2.85 : 1** |

WCAG AA needs 4.5:1. Every filled button, active switch track and selected nav
item in light mode is currently unreadable. **The root cause is structural: one
seed cannot serve two grounds.** An accent bright enough to sit on `#0E1512` is
by construction too bright to carry white text.

### 2.2 The Aurora ring

**Rule.** The semantic layer owns the warm arc — `Danger` 1°, `Caution` 36°,
`Success` 122°. Brand accents live in the cool→magenta arc **150°–330°**, and
every accent is ≥ 38° from every other accent *and* from every semantic hue.

**[measured]** With those three hues reserved at ±38°, the usable arc is ~162°–321°;
five points across it give a maximum achievable minimum separation of ≈40°. The
ring below lands at **38.0°–41.2°** — i.e. at the ceiling of what is possible.

Each app declares **two** seeds. `seedDark` is tuned for `Ink900`; `seedLight` is
the same hue pushed dark enough to carry `Paper50` text.

| App | Character (one line) | Hue | `seedDark` | on Ink900 | `seedLight` | white-on |
|---|---|---|---|---|---|---|
| **Yojimbo** | *The retainer holds the keys.* Foundation and gatekeeper — the ground the other four stand on. | 161° | `#1FC48F` jade | **8.24 : 1** | `#0A6B4E` | **6.24 : 1** |
| **Chaos Orb** | *Something is always emitting.* Noise, disruption, signal — the loudest thing in the suite. | 201° | `#3FB5F5` ion cyan | **8.05 : 1** | `#0B639C` | **6.14 : 1** |
| **Godwall** | *A wall is not a warning.* Barrier and perimeter — cold, structural, immovable. | 242° | `#A3A0F0` cobalt steel | **7.79 : 1** | `#4A43D6` | **6.56 : 1** |
| **Genji** | *A cut, not a crash.* Precision, surgery, blades — hooks and rewrites. | 282° | `#D28CF0` arc violet | **7.71 : 1** | `#9226C4` | **6.10 : 1** |
| **Masamune** | *The hottest part of the flame is not orange.* Depth and forge — a named sword, a second OS. | 320° | `#F27ACA` quench rose | **7.41 : 1** | `#B22078` | **5.97 : 1** |

Derived roles verified at the same time (`primaryContainer` = seed @16% over
`Ink800` dark / @18% over `Paper100` light):

| App | dark container | `Fog100` on it | light container | `Slate900` on it |
|---|---|---|---|---|
| Yojimbo | `#17392C` | 10.89 | `#C8DAD4` | 11.96 |
| Chaos Orb | `#1C363C` | 10.99 | `#C8D8E3` | 11.92 |
| Godwall | `#2C333B` | 10.98 | `#D4D3ED` | 11.88 |
| Genji | `#33303B` | 11.10 | `#E1CDEA` | 11.70 |
| Masamune | `#382D35` | 11.32 | `#E6CCDC` | 11.63 |

**Two deliberate breaks with the tree, stated openly:**

1. **Godwall gives up amber.** The in-tree comment keeps it "by lineage" from
   `FIREWALL`. Lineage is not a reason to make an app's chrome indistinguishable
   from its own alarm. Cobalt steel is also the better read: a wall is cold and
   structural, and a firewall is the app that shows the *most* caution chips.
2. **Masamune gives up forge orange.** "Forge" survives as *quench rose* — steel
   the instant it leaves the fire, and the one hue neither a status nor a sibling
   ever speaks.

If the user wants a warm accent back, the thing that must change is the semantic
palette, not the separation rule — and that is a decision for the user, not this
document. Everything else in §2.2 is arithmetic.

### 2.3 Hue is not enough — the motif axis

Roughly 8% of men have a red-green colour vision deficiency, and a suite that is
"unique" only by hue is a suite that is not unique to them. Each app therefore
also owns a **motif**: a mark, a section-header rule style, and a default
empty-state glyph. These render identically in greyscale.

| App | Mark (motif glyph) | Section-header rule | Reads as |
|---|---|---|---|
| **Yojimbo** | Gate — two uprights + a lintel | Solid 2dp bar, full width | A threshold you pass through. Foundation. |
| **Godwall** | Course — offset brick chevrons | Double hairline (a wall has two faces) | Layered barrier. |
| **Genji** | Slash — a single 45° stroke through a rule | Rule with a 45° tapered terminal | A cut. |
| **Masamune** | Fold — three stacked laminations | Three stacked hairlines | Layers folded into one blade. |
| **Chaos Orb** | Emission — three concentric arcs from a point | Dotted rule | Broadcast. |

The mark appears in exactly three places, never more: the nav rail/drawer header,
the default `EmptyState` icon, and the About screen. It is chrome, not decoration.

### 2.4 Icon families

To keep sibling screens consistent, each app draws its nav icons from one
Material family, so a Godwall screen and a Genji screen never look like they came
from different products.

| App | Family | Examples |
|---|---|---|
| Yojimbo | `Filled` shield/key/badge | `Security`, `VpnKey`, `Groups`, `Assignment` |
| Godwall | `Filled` network/barrier | `Shield`, `Dns`, `Hub`, `Link`, `Apps` |
| Genji | `Filled` tools/edit | `Extension`, `Construction`, `Build`, `Layers` |
| Masamune | `Filled` terminal/storage | `Terminal`, `Folder`, `Memory`, `Chat` |
| Chaos Orb | `Filled` waves/sensors | `Sensors`, `GraphicEq`, `Radar`, `Bolt` |

---

## 3. Navigation for a deep, donor-derived tree

### 3.1 Why the current model does not scale

**[verified]** `SuiteNav` holds `SnapshotStateList<String>` — a flat stack of
opaque route names. `SuiteNavShell` renders ≤ 5 primary tabs plus a "More" sheet.
That is a good, correct design for **8–15 destinations**, and it already fixed
three real back-stack defects. It does not survive a donor-derived tree:

- **Godwall** absorbs InviZible + RethinkDNS + De1984 + Fyrypt + Tailscale. The
  ledger in `docs/DONOR-ABSORPTION.md` already names dozens of distinct
  capabilities (DoT/DoH presets, blocklists, per-app rules, profiles, chain hops,
  tailnet peers, exit nodes, logs).
- **Genji** absorbs LSPosed + ReVanced + apktool + NPatch + microG.
- **Masamune** is a second OS.

Three structural blockers:

1. **A route has no parent.** `push("BLOCKLIST_CUSTOM")` from a search result
   leaves the stack `[SHIELD, BLOCKLIST_CUSTOM]` — back goes to Shield, not to
   DNS → Blocklists. The user is teleported and then stranded.
2. **Menus are hand-written twice** (once as `SuiteTab` list, once as the `when`
   arm). A destination can exist with no path to it, silently.
3. **The overflow sheet is a flat list.** At 30 items it is a scroll of
   undifferentiated rows — the same "not proportioned well" failure the tab
   ceiling was introduced to fix, moved one layer down.

### 3.2 The model: pillars → sections → leaves, all generated from one catalog

```
PILLAR  (≤5, always visible)          bottom bar / nav rail / drawer root
  └ SECTION  (a hub screen)           SuiteHubScreen of grouped rows + cards
      └ SECTION                       nests arbitrarily
          └ LEAF                      the actual screen
```

Routes become **`/`-separated paths**, so the hierarchy is in the route itself:

```
"dns"                        PILLAR
"dns/upstream"               SECTION
"dns/upstream/presets"       LEAF
"dns/blocklists"             SECTION
"dns/blocklists/custom"      LEAF
```

Everything — bottom bar, rail, drawer tree, breadcrumbs, search index, the
navigation-map screen, and the reachability test — is **generated from one
declared list**. A destination absent from the catalog cannot be reached; a
destination present in it is guaranteed a path. This is the Masamune
`RouteCatalog` pattern (**[verified]** in-tree, 85 LoC, itself salvaged from a
donor's 765-line registry) promoted to `common-security` and given depth.

### 3.3 Back, with hierarchy

`SuiteNav.back()` keeps its contract exactly — overlay → pop one → home pillar →
`moveTaskToBack`. The one addition is `pushPath`, which **materialises ancestors**:

```
nav.pushPath("dns/blocklists/custom")
// stack: ["dns", "dns/blocklists", "dns/blocklists/custom"]
// back → blocklists → dns → home pillar → minimize.  Correct from a search hit.
```

That single change is what makes jump-to safe, and it is why search can exist at all.

### 3.4 Adaptivity — the same catalog, three chromes

| Window width | Chrome | Notes |
|---|---|---|
| **Compact** (< 600dp) — phone portrait | `NavigationBar`, ≤5 pillars | Today's behaviour, unchanged. |
| **Medium** (600–839dp) — phone landscape, small tablet, folded outer | `NavigationRail` with the app **mark** in the header | Pillars as rail items; content gains the reclaimed width. |
| **Expanded** (≥ 840dp) — tablet, unfolded foldable, desktop mode | `PermanentNavigationDrawer` showing **pillars + their sections** as a tree | The deep tree finally becomes visible instead of hidden behind sheets. |

The **More** overflow sheet stays as the compact-width escape hatch, but it now
renders overflow pillars *grouped by section with their child counts*, not as a
flat list.

### 3.5 Search / jump-to — the real answer to depth

A tree of 200 destinations is not navigated, it is *queried*. Every pillar's app
bar carries one search action (also bound to a keyboard `/`). It searches the
catalog — titles, `keywords`, and `navPath` — and renders each hit **with its
breadcrumb**, so selecting one both teleports and teaches:

```
┌ Search  "block"                                          ✕ ┐
│ DNS ▸ Blocklists                            section        │
│   Custom rules            DNS ▸ Blocklists                 │
│   Blocklist sources       DNS ▸ Blocklists                 │
│ Apps ▸ Per-app policy                                      │
│   Blackhole              Apps ▸ Per-app policy             │
└────────────────────────────────────────────────────────────┘
```

Selecting a hit calls `nav.pushPath(hit.route)` — ancestors materialised, back
correct. Search is not a nicety here; without it a donor-derived tree is
unusable, and with it the tree can grow without the chrome degrading.

---

## 4. Component additions — concrete signatures for `common-security`

All new code lives in `com.understory.security.*`. Everything reads tokens through
`UnderstoryTheme`; no hex, no bare design `.dp`/`.sp`, outside `ui/theme/`.

### 4.1 `ui/theme/Theme.kt` — accents gain a second seed and a motif

```kotlin
enum class UnderstoryAccent(
    val seedDark: Color,
    val seedLight: Color,
    val motif: SuiteMotif,
) {
    YOJIMBO  (Color(0xFF1FC48F), Color(0xFF0A6B4E), SuiteMotif.Gate),
    CHAOS_ORB(Color(0xFF3FB5F5), Color(0xFF0B639C), SuiteMotif.Emission),
    GODWALL  (Color(0xFFA3A0F0), Color(0xFF4A43D6), SuiteMotif.Course),
    GENJI    (Color(0xFFD28CF0), Color(0xFF9226C4), SuiteMotif.Slash),
    MASAMUNE (Color(0xFFF27ACA), Color(0xFFB22078), SuiteMotif.Fold),
    // legacy single-seed apps keep working: seedLight defaults are derived, see §5.
    ;
    /** Back-compat shim for call sites that predate the pair. Remove after migration. */
    @Deprecated("use seedDark / seedLight", ReplaceWith("seedDark"))
    val seed: Color get() = seedDark
}

@Composable
fun UnderstoryTheme(
    accent: UnderstoryAccent,
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit,
)   // now: understoryDarkColors(accent.seedDark) / understoryLightColors(accent.seedLight)
    // and additionally provides LocalSuiteMotif = accent.motif

object UnderstoryTheme {
    val motif: SuiteMotif @Composable @ReadOnlyComposable get() = LocalSuiteMotif.current
    // .colors .semantic .spacing .type .shapes unchanged
}
```

### 4.2 `ui/theme/Motif.kt` — the non-colour identity axis (new file)

```kotlin
/** An app's non-colour identity. Renders identically in greyscale. */
@Immutable
sealed class SuiteMotif(val id: String) {
    data object Gate     : SuiteMotif("gate")      // Yojimbo
    data object Course   : SuiteMotif("course")    // Godwall
    data object Slash    : SuiteMotif("slash")     // Genji
    data object Fold     : SuiteMotif("fold")      // Masamune
    data object Emission : SuiteMotif("emission")  // Chaos Orb
}

val LocalSuiteMotif = staticCompositionLocalOf<SuiteMotif> { SuiteMotif.Gate }

/** The app mark. Nav-rail/drawer header, default EmptyState glyph, About. Nowhere else. */
@Composable
fun SuiteMark(
    modifier: Modifier = Modifier,
    motif: SuiteMotif = UnderstoryTheme.motif,
    tint: Color = MaterialTheme.colorScheme.primary,
    size: Dp = 32.dp,
)

/** The motif's section-header rule: solid / double / tapered / stacked / dotted. */
@Composable
fun SuiteMotifRule(
    modifier: Modifier = Modifier,
    motif: SuiteMotif = UnderstoryTheme.motif,
    color: Color = MaterialTheme.colorScheme.outlineVariant,
)
```

### 4.3 `nav/SuiteRouteCatalog.kt` — the generated menu tree (new file)

```kotlin
enum class SuiteSurface {
    /** A top-level pillar: bottom bar / rail / drawer root. Max 5 per app. */
    PILLAR,
    /** A hub screen that lists its children. Rendered by SuiteHubScreen. */
    SECTION,
    /** A terminal screen. */
    LEAF,
}

@Immutable
data class SuiteDestination(
    /** Slash-separated path, e.g. "dns/blocklists/custom". Its own hierarchy. */
    val route: String,
    val title: String,
    val surface: SuiteSurface,
    val icon: ImageVector? = null,
    /** Sort order among siblings. */
    val order: Int = 0,
    /** One line under the title on hub screens and in search results. */
    val summary: String? = null,
    /** Extra search terms — donor names count ("lsposed", "rethinkdns"). */
    val keywords: List<String> = emptyList(),
    /** Hidden from menus but still routable + still reachability-tested. */
    val hidden: Boolean = false,
) {
    val parentRoute: String? get() = route.substringBeforeLast('/', "").ifEmpty { null }
    val depth: Int get() = route.count { it == '/' } + 1
}

@Immutable
class SuiteRouteCatalog(destinations: List<SuiteDestination>) {
    val all: List<SuiteDestination>
    val pillars: List<SuiteDestination>            // surface == PILLAR, by order, ≤ MAX_PRIMARY_TABS enforced
    val home: SuiteDestination                     // pillars.first()

    fun find(route: String): SuiteDestination?
    fun childrenOf(route: String): List<SuiteDestination>
    /** Root → … → route. Powers breadcrumbs and pushPath. */
    fun trailOf(route: String): List<SuiteDestination>
    fun pillarOf(route: String): SuiteDestination?
    fun search(query: String, limit: Int = 40): List<SuiteSearchHit>

    /** Fails on: orphan parents, duplicate routes, >5 pillars, a LEAF with children. */
    fun validate(): List<String>

    companion object {
        fun of(vararg destinations: SuiteDestination): SuiteRouteCatalog
    }
}

@Immutable
data class SuiteSearchHit(
    val destination: SuiteDestination,
    val breadcrumb: String,   // "DNS ▸ Blocklists"
    val score: Int,
)

val LocalSuiteCatalog = staticCompositionLocalOf<SuiteRouteCatalog> {
    error("No SuiteRouteCatalog in scope — wrap the app in SuiteAdaptiveShell")
}
```

### 4.4 `nav/SuiteNav.kt` — hierarchy-aware additions (edits, contract unchanged)

```kotlin
/**
 * Push a path, materialising every ancestor that is not already on the stack, so
 * back walks the tree. This is what makes a search jump safe.
 */
fun SuiteNav.pushPath(route: String, catalog: SuiteRouteCatalog)

/** Titles of the current stack, for SuiteBreadcrumb. */
fun SuiteNav.trailTitles(catalog: SuiteRouteCatalog): List<String>

/** Collapse to the current pillar's root without leaving it. */
fun SuiteNav.popToPillar(catalog: SuiteRouteCatalog)
```

### 4.5 `ui/components/SuiteAdaptiveShell.kt` — one shell, three chromes (new file)

```kotlin
/**
 * Replaces SuiteNavShell for catalog-driven apps. Chooses bar / rail / drawer from
 * window width, renders the pillar set, owns the search action, and delegates the
 * single BackHandler to SuiteNavHost exactly as before.
 *
 * SuiteNavShell stays for apps that are genuinely flat; it becomes a thin wrapper
 * that builds a PILLAR-only catalog, so nothing existing breaks.
 */
@Composable
fun SuiteAdaptiveShell(
    nav: SuiteNav,
    catalog: SuiteRouteCatalog,
    modifier: Modifier = Modifier,
    windowSizeClass: WindowWidthSizeClass = currentWindowWidthSizeClass(),
    snackbarHost: SnackbarHostState? = null,
    actions: @Composable RowScope.() -> Unit = {},
    overlayShowing: Boolean = false,
    onDismissOverlay: () -> Unit = {},
    searchEnabled: Boolean = true,
    content: @Composable (destination: SuiteDestination, padding: PaddingValues) -> Unit,
)
```

### 4.6 `ui/components/SuiteHub.kt` — section hubs and breadcrumbs (new file)

```kotlin
/**
 * Renders a SECTION from the catalog: title, motif rule, then its children as
 * SuiteListRow (leaves) or SuiteSectionCard (sub-sections, with child counts).
 * A section screen is DECLARED, not written — the whole body is one call.
 */
@Composable
fun SuiteHubScreen(
    route: String,
    onOpen: (String) -> Unit,
    modifier: Modifier = Modifier,
    catalog: SuiteRouteCatalog = LocalSuiteCatalog.current,
    header: (@Composable () -> Unit)? = null,   // live status above the list
)

/** A sub-section entry point: icon, title, summary, child count, chevron. */
@Composable
fun SuiteSectionCard(
    title: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    summary: String? = null,
    icon: ImageVector? = null,
    childCount: Int? = null,
    status: SuiteStatus? = null,   // roll up the worst child status here
)

/** "DNS ▸ Blocklists ▸ Custom" — each ancestor tappable via nav.popTo. */
@Composable
fun SuiteBreadcrumb(
    trail: List<SuiteDestination>,
    onNavigate: (String) -> Unit,
    modifier: Modifier = Modifier,
    maxVisible: Int = 3,   // elides from the middle: "DNS ▸ … ▸ Custom"
)
```

### 4.7 `ui/components/SuiteChips.kt` — status vocabulary (new file)

This is where the ad-hoc hexes keep coming back. One enum, one chip, five apps.

```kotlin
/** The suite's status vocabulary. Colour comes from the SEMANTIC layer, never the accent. */
enum class SuiteStatus { ACTIVE, IDLE, DEGRADED, BLOCKED, ERROR, UNKNOWN }

/**
 * Small pill. Carries a dot AND a label — never colour alone (§2.3).
 * ACTIVE→success, DEGRADED→warning, ERROR/BLOCKED→error, IDLE/UNKNOWN→dim.
 */
@Composable
fun SuiteStatusChip(
    status: SuiteStatus,
    label: String,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
)

/** Label + value + optional delta. The unit of every dashboard readout. */
@Composable
fun SuiteMetricRow(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    supporting: String? = null,
    status: SuiteStatus? = null,
)

/**
 * Full-width inline banner for a persistent condition — "Privilege unavailable",
 * "Filter running without upstream verification". The honest-degradation surface
 * the charter demands, instead of a screen that silently lies.
 */
@Composable
fun SuiteBanner(
    status: SuiteStatus,
    title: String,
    modifier: Modifier = Modifier,
    body: String? = null,
    action: (@Composable () -> Unit)? = null,
    onDismiss: (() -> Unit)? = null,
)
```

### 4.8 `ui/components/SuiteLists.kt` — dense variants and grouping (new file)

```kotlin
/**
 * 40dp-tall row for long machine-generated lists (installed apps, DNS query log,
 * peers, modules). Keeps the 48dp touch target via negative-inset padding, so it
 * is dense without violating §3 A-1.
 */
@Composable
fun SuiteDenseRow(
    headline: String,
    modifier: Modifier = Modifier,
    supporting: String? = null,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
    status: SuiteStatus? = null,
    selected: Boolean = false,
    onClick: (() -> Unit)? = null,
)

/** SuiteSectionHeader + motif rule + a hairline-outlined group of rows. */
@Composable
fun SuiteGroup(
    title: String,
    modifier: Modifier = Modifier,
    trailing: (@Composable () -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
)

/** Collapsible group; collapsed state is rememberSaveable per title. */
@Composable
fun SuiteExpandableGroup(
    title: String,
    modifier: Modifier = Modifier,
    initiallyExpanded: Boolean = true,
    summaryWhenCollapsed: String? = null,
    content: @Composable ColumnScope.() -> Unit,
)

/** In-list filter field. Debounced 120ms, IME search action, clear button. */
@Composable
fun SuiteSearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String = stringResource(R.string.action_search),
)

/** Horizontal scrollable filter chips over a dense list. */
@Composable
fun SuiteFilterBar(
    filters: List<String>,
    selected: Set<String>,
    onToggle: (String) -> Unit,
    modifier: Modifier = Modifier,
)
```

### 4.9 `ui/components/SuiteCommandBar.kt` — jump-to (new file)

```kotlin
/** Full-screen catalog search. Results grouped by pillar, each hit with a breadcrumb. */
@Composable
fun SuiteCommandBar(
    visible: Boolean,
    onDismiss: () -> Unit,
    onNavigate: (String) -> Unit,      // caller does nav.pushPath(route, catalog)
    modifier: Modifier = Modifier,
    catalog: SuiteRouteCatalog = LocalSuiteCatalog.current,
)
```

### 4.10 `ui/components/SuiteTabs.kt` — *within-screen* tabs (new file)

Distinct from navigation. Lateral views of one subject (Log: All / Blocked / Allowed).

```kotlin
@Composable
fun SuiteSegmented(
    options: List<String>,
    selectedIndex: Int,
    onSelect: (Int) -> Unit,
    modifier: Modifier = Modifier,
)

/** Scrollable strip for >3 options. Never a navigation affordance. */
@Composable
fun SuiteTabStrip(
    options: List<String>,
    selectedIndex: Int,
    onSelect: (Int) -> Unit,
    modifier: Modifier = Modifier,
)
```

### 4.11 `ui/components/SuiteStates.kt` — two additions (edit)

```kotlin
/** Blocked on a permission or on privilege from Yojimbo. Names what is missing and how to get it. */
@Composable
fun PermissionState(
    title: String,
    reason: String,
    modifier: Modifier = Modifier,
    grantLabel: String? = null,
    onGrant: (() -> Unit)? = null,
)

/**
 * Charter honesty, made a component: the feature is running but NOT at full
 * capability. Renders what works, what does not, and why — instead of a green
 * screen that implies more than is true.
 */
@Composable
fun DegradedState(
    title: String,
    working: List<String>,
    notWorking: List<String>,
    modifier: Modifier = Modifier,
    onRetry: (() -> Unit)? = null,
)
```

### 4.12 `ui/components/SuiteComponents.kt` — one edit

`SuiteSectionHeader` gains an optional motif rule so section headers differ per
app while staying the same component:

```kotlin
@Composable
fun SuiteSectionHeader(
    text: String,
    modifier: Modifier = Modifier,
    rule: Boolean = true,          // draws SuiteMotifRule under the label
    trailing: (@Composable () -> Unit)? = null,
)
```

### 4.13 Gates

Mechanical, CI-checkable, and each one traces to a defect above.

| Gate | Rule |
|---|---|
| `HardcodedColor` | `Color(0x…)` outside `ui/theme/` fails the build. Already the intent; now absolute. |
| `RawNavigationBar` | `NavigationBar` / `NavigationRail` / `ModalNavigationDrawer` outside `ui/components/` fails. Chrome belongs to the shell. |
| `RawBackHandler` | `BackHandler` outside `SuiteNavHost` fails. |
| `AccentSeparation` | Unit test: every `UnderstoryAccent` pair, and every accent vs `Danger`/`Caution`/`Success`, ≥ 38° apart. |
| `AccentContrast` | Unit test: `seedDark` ≥ 4.5:1 on `Ink900`; `Paper50` on `seedLight` ≥ 4.5:1. |
| `CatalogValid` | Unit test: `catalog.validate()` empty, and every destination reachable from a pillar by `trailOf`. |
| `TabCeiling` | `catalog.pillars.size <= MAX_PRIMARY_TABS`. |

---

## 5. Migration — how five rebuilt apps adopt this without diverging

### 5.1 Fix distribution first (§0.2), or none of the rest holds

Four vendored copies, one hand-written mirror, one app with nothing. Sequence:

1. **Name the source of truth.**
   `understory-firewall/common-security/` is canonical. Written down here so the
   next session does not have to re-derive it from timestamps.
2. **Add `tools/sync-common-security.sh`** — rsync canonical → each consumer repo,
   plus `--check` mode that `diff -rq`s and exits non-zero. Wire `--check` into
   CI in all four repos. Drift becomes a red build, not a discovery six weeks later.
3. **Masamune deletes its mirror.** `dev/pleiades/masamune/ui/theme/Theme.kt` is
   removed; `tracendroid/settings.gradle.kts` gains
   `include(":common-security")` pointed at the synced copy. The mirror's own
   header already names itself a drop-in replacement target, and its
   `MasamuneSeed = 0xFF2FD3C3` collision (§2.1) is deleted with it.
4. **Chaos Orb joins.** `emi-chaos-bench/settings.gradle.kts` gains
   `:common-security`; `app` wraps `setContent` in
   `UnderstoryTheme(accent = UnderstoryAccent.CHAOS_ORB)`.
5. **Longer term** — publish `common-security` as a versioned AAR to one shared
   Maven and delete the copies. The sync script is the bridge, not the destination.

### 5.2 Per-app adoption, in this order

Ordered so each step is independently shippable and independently verifiable.
Do **not** batch them: a half-migrated app that compiles is exactly the state the
charter says not to report as working.

1. **Theme** — `UnderstoryTheme(accent = <APP>)` at every `setContent`. Delete any
   local `MaterialTheme(...)`. *Verify: launch in light and dark; no crash, no
   unreadable button.*
2. **Seeds** — take `seedDark`/`seedLight` from §2.2 verbatim. No app invents a hue.
3. **Catalog** — write `<App>Routes.kt` declaring every destination as a
   `SuiteDestination` with `route`, `title`, `surface`, `summary`, `keywords`.
   Donor names go in `keywords` ("lsposed", "rethinkdns", "shizuku") so users
   search for what they came from. *Verify: `catalog.validate()` returns empty.*
4. **Shell** — swap `SuiteNavShell` → `SuiteAdaptiveShell(nav, catalog)`. The
   `when(route)` body becomes `when(destination.surface)`: `SECTION` → one
   `SuiteHubScreen` call, `LEAF` → the screen. *Verify: back from a depth-4 leaf
   walks up one level at a time and minimises at the home pillar.*
5. **Chips** — every hand-rolled state pill → `SuiteStatusChip`. *Verify: grep
   for `Color(0x` in the app module returns nothing.*
6. **Dense lists** — app lists, logs, peer lists, module lists → `SuiteDenseRow`.
7. **States** — `PermissionState` / `DegradedState` wherever the app currently
   shows a green screen it cannot justify.
8. **Motif** — `SuiteMark` in the rail/drawer header, About, and default empty state.

### 5.3 Divergence controls

- **Nothing app-local in `ui/`.** If two apps need it, it goes in
  `common-security`. If one app needs it, it is probably a `SuiteHubScreen` or a
  `SuiteCard` and does not need to exist.
- **The three knobs are the whole freedom budget**: accent pair, motif, pillar
  set. Everything else is inherited. A PR that adds a fourth knob is rejected.
- **Gates in CI** (§4.13) in all four repos, from the shared source.
- **`AGENTS.md` / `.github/copilot-instructions.md`** in each repo point at this
  document as the design authority, so an agent cannot re-invent a parallel theme
  the way `masamune-next` did.

### 5.4 Acceptance — what "unique and matching" means concretely

Per the charter, "compiles" is not "verified". The acceptance artifact is a
**screenshot matrix**, captured on device:

**5 apps × 4 screens (pillar hub, depth-3 leaf, empty, error) × 2 themes = 40 shots.**

Two questions, both answerable by looking:

1. **Matching** — cover the accent with a thumb. Can you still tell which app it
   is? If yes, something app-local leaked into the shared layer.
2. **Unique** — show any two shots side by side, in **greyscale**. Can you tell
   them apart? If no, the motif axis (§2.3) is not doing its job and colour alone
   is carrying identity — which is the failure this document exists to end.

---

## Appendix A — measurement method

Contrast is WCAG 2.x relative luminance (sRGB, `0.2126 R + 0.7152 G + 0.0722 B`
after gamma-linearisation), `(L_hi + 0.05) / (L_lo + 0.05)`. Hue is the HSL hue
angle, separation measured as the shorter arc. Grounds: `Ink900 #0E1512`,
`Ink800 #151E19`, `Paper50 #FAFAFA`, `Paper100 #F2F2F2`. Semantic hues measured
from the shipping tokens: `Danger #EF5350` 1.2°, `Caution #FFB74D` 36.0°,
`Success #81C784` 122.4°. Every number in §2.1 and §2.2 was computed, not
estimated; `AccentSeparation` and `AccentContrast` (§4.13) re-check them on every
build so they cannot silently rot.

## Appendix B — worked pillar sets (illustrative, ≤5 each)

Sketches to show the model carries a deep tree — not a spec of features. The
authoritative destination lists are each app's `<App>Routes.kt`.

| App | Pillars | Example depth |
|---|---|---|
| **Yojimbo** | Server · Clients · Owner · Ledger · Diagnostics | `clients/approved/<pkg>/scopes` |
| **Godwall** | Shield · Apps · DNS · Chain · Mesh | `dns/upstream/presets/mullvad`, `apps/policy/<pkg>/rules` |
| **Genji** | Modules · Patch · Targets · Runtime · Diagnostics | `patch/static/<apk>/passes`, `modules/<id>/scope` |
| **Masamune** | Files · Shell · Chat · Harness · About | `harness/capabilities/<cap>/declines` |
| **Chaos Orb** | Emit · Sensors · Sweep · Profiles · Diagnostics | `sweep/results/<scan>/detail` |

Godwall's existing eight `SuiteTab`s become **five pillars**, with Log, Privilege
and Diagnostics demoted to sections under Shield and Mesh — reachable by name via
search, and no longer competing for bottom-bar width.
