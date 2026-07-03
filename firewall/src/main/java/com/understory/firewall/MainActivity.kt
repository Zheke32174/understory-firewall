package com.understory.firewall

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.foundation.Image
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import com.understory.security.A11yProbe
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.KeepAliveBackHandler
import com.understory.security.SuiteAttestation
import com.understory.security.Tamper
import com.understory.security.TestingMode
import com.understory.security.secureClickable
import kotlinx.coroutines.delay

/**
 * Firewall Phase B — VPN-slot outbound traffic gate.
 *
 *   Toggle on  + add apps to blocklist  → those apps' traffic is captured
 *                                          by our local tun and dropped.
 *                                          Apps not on the list are
 *                                          unaffected (use normal network).
 *   Toggle off                          → no VPN, everything works as
 *                                          normal.
 *
 * Phase C will add packet parsing (per-domain rules, DNS overrides).
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        DiagnosticsDump.activateIfEng(this)
        Diagnostics.log("firewall.MainActivity", "onCreate (savedInstanceState=${savedInstanceState != null})")
        super.onCreate(savedInstanceState)
        try {
            initialize()
        } catch (t: Throwable) {
            Diagnostics.error("firewall.MainActivity", "onCreate threw: ${t.javaClass.simpleName}: ${t.message}")
            setContent {
                Surface(modifier = Modifier.fillMaxSize(), color = Color.Black) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("firewall crash", color = Color(0xFFEF5350), fontSize = 18.sp)
                        Text(t.toString(), color = Color(0xFFE0E0E0), fontSize = 11.sp)
                    }
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        Diagnostics.log("firewall.MainActivity", "onPause")
        DiagnosticsDump.snapshotState(this, "onPause")
    }

    override fun onStop() {
        super.onStop()
        Diagnostics.log("firewall.MainActivity", "onStop (changingConfigs=$isChangingConfigurations)")
        DiagnosticsDump.snapshotState(this, "onStop")
    }

    override fun onDestroy() {
        super.onDestroy()
        Diagnostics.log("firewall.MainActivity", "onDestroy")
    }

    private fun initialize() {
        val debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        if (debuggerAttached ||
            Tamper.check(applicationContext).hardFail ||
            SuiteAttestation.verify(applicationContext).hardFail
        ) {
            finishAndRemoveTask(); return
        }

        if (!TestingMode.ALLOW_SCREENSHOTS) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                window.setHideOverlayWindows(true)
            }
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                setRecentsScreenshotEnabled(false)
            }
        }
        runCatching { WindowCompat.setDecorFitsSystemWindows(window, false) }

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0A0A0A)) {
                    FirewallRoot(activity = this)
                }
            }
        }

        // Note: we do NOT set filterTouchesWhenObscured = true on the
        // decor view here. The original device test on Samsung One UI
        // showed the Switch onCheckedChange not firing — Edge Panel or
        // similar system overlays trigger FLAG_WINDOW_IS_OBSCURED on
        // touches, and the global decor filter dropped the toggle.
        // Tap-jacking defense for *destructive* paths in this app comes
        // from secureClickable / SecureButton wrappers on those specific
        // controls; the firewall toggle's destructive action (granting
        // VPN) is gated by the system VpnService consent dialog, which
        // is rendered by Android with its own anti-overlay protection.
        // FLAG_SECURE on the window still prevents screenshots /
        // screen-recording overlays from capturing the UI.
    }

    override fun onResume() {
        super.onResume()
        Diagnostics.log("firewall.MainActivity", "onResume")
        Tamper.invalidate()
        if (Tamper.check(applicationContext).hardFail) {
            Diagnostics.error("firewall.MainActivity", "Tamper.check hardFail on resume — finishing")
            finishAndRemoveTask()
        }
    }
}

private enum class FirewallRoute { Main, DnsPrefs, Posture, Audit, OverlayRouting, PortBlocks, Diagnostics }

/**
 * Filter applied to the app list above the search field. "All" is the
 * default unscoped view. "Blocked" shows only currently-blocked rules
 * (including stale uninstalled ones). "Apps" hides FLAG_SYSTEM packages —
 * useful when you don't want bundled system apps cluttering the list.
 * "System" shows only the user-launchable system apps that AppListLoader
 * lets through (it already hides system apps without a launcher intent).
 */
private enum class AppListFilter { All, Blocked, Apps, System }

@Composable
private fun FirewallRoot(activity: ComponentActivity) {
    // String-encoded saveable state — bulletproof across activity recreation.
    var routeName by androidx.compose.runtime.saveable.rememberSaveable {
        mutableStateOf(FirewallRoute.Main.name)
    }
    val route = remember(routeName) { FirewallRoute.valueOf(routeName) }
    val setRoute: (FirewallRoute) -> Unit = {
        Diagnostics.log("firewall.Root", "route transition: $routeName → ${it.name}")
        routeName = it.name
    }
    val backToMain: () -> Unit = { setRoute(FirewallRoute.Main) }
    when (route) {
        FirewallRoute.Main -> {
            KeepAliveBackHandler("firewall.Root.Main")
            FirewallScreen(
                activity = activity,
                onOpenDnsPrefs = { setRoute(FirewallRoute.DnsPrefs) },
                onOpenPosture = { setRoute(FirewallRoute.Posture) },
                onOpenAudit = { setRoute(FirewallRoute.Audit) },
                onOpenOverlayRouting = { setRoute(FirewallRoute.OverlayRouting) },
                onOpenPortBlocks = { setRoute(FirewallRoute.PortBlocks) },
                onDiagnostics = { setRoute(FirewallRoute.Diagnostics) },
            )
        }
        FirewallRoute.DnsPrefs -> {
            androidx.activity.compose.BackHandler { backToMain() }
            DnsPrefsScreen(onBack = backToMain)
        }
        FirewallRoute.Posture -> {
            androidx.activity.compose.BackHandler { backToMain() }
            PostureScreen(onBack = backToMain)
        }
        FirewallRoute.Audit -> {
            androidx.activity.compose.BackHandler { backToMain() }
            AuditScreen(onBack = backToMain)
        }
        FirewallRoute.OverlayRouting -> {
            androidx.activity.compose.BackHandler { backToMain() }
            OverlayRoutingScreen(onBack = backToMain)
        }
        FirewallRoute.PortBlocks -> {
            androidx.activity.compose.BackHandler { backToMain() }
            PortBlocksScreen(onBack = backToMain)
        }
        FirewallRoute.Diagnostics -> {
            androidx.activity.compose.BackHandler { backToMain() }
            DiagnosticsScreen(onBack = backToMain)
        }
    }
}

@Composable
private fun FirewallScreen(
    activity: ComponentActivity,
    onOpenDnsPrefs: () -> Unit,
    onOpenPosture: () -> Unit,
    onOpenAudit: () -> Unit,
    onOpenOverlayRouting: () -> Unit,
    onOpenPortBlocks: () -> Unit,
    onDiagnostics: () -> Unit,
) {
    val ctx = LocalContext.current
    var vpnEnabled by remember {
        mutableStateOf(FirewallSettings.isVpnRequested(ctx))
    }
    var preempted by remember {
        mutableStateOf(FirewallSettings.isVpnPreempted(ctx))
    }
    var blocked by remember {
        mutableStateOf(FirewallSettings.getBlockedPackages(ctx))
    }
    var query by remember { mutableStateOf("") }
    var apps by remember { mutableStateOf<List<AppEntry>>(emptyList()) }
    var dropTotal by remember { mutableStateOf(0L) }
    var dropLastMillis by remember { mutableStateOf(0L) }
    var auditFindings by remember { mutableStateOf<List<AuditFinding>>(emptyList()) }
    var firstRunDone by remember {
        mutableStateOf(FirewallSettings.isFirstRunAuditDone(ctx))
    }
    var acknowledged by remember {
        mutableStateOf(FirewallSettings.getAuditAcknowledged(ctx))
    }
    val a11yState = remember { A11yProbe.check(ctx) }

    LaunchedEffect(Unit) {
        apps = AppListLoader.load(ctx)
        auditFindings = RemoteAdminAudit.scan(ctx)
    }

    // Poll DropStats while the firewall is on. The VpnService runs in
    // the same process, so the counters are visible without IPC. 1s is
    // a coarse cadence on purpose — finer would just burn CPU for no
    // perceptual gain on a numeric-with-relative-time readout.
    LaunchedEffect(vpnEnabled) {
        if (!vpnEnabled) {
            dropTotal = 0L
            dropLastMillis = 0L
            return@LaunchedEffect
        }
        while (true) {
            dropTotal = DropStats.totalPackets()
            dropLastMillis = DropStats.lastDropAt()
            delay(1000)
        }
    }

    // Re-read persisted state on every ON_START so the UI reflects
    // service-side mutations. The VpnService self-stops + flips
    // vpnRequested=false when the user removes the last blocked app
    // while the VPN is on; without this, the switch would stay "on" in
    // the UI while the service is gone, with no obvious recovery path.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) {
                vpnEnabled = FirewallSettings.isVpnRequested(ctx)
                preempted = FirewallSettings.isVpnPreempted(ctx)
                blocked = FirewallSettings.getBlockedPackages(ctx)
                firstRunDone = FirewallSettings.isFirstRunAuditDone(ctx)
                acknowledged = FirewallSettings.getAuditAcknowledged(ctx)
                // Re-scan on resume — the user may have revoked a
                // capability via Settings and come back; without this
                // refresh the audit count would still show the stale
                // higher number until a process restart.
                auditFindings = RemoteAdminAudit.scan(ctx)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val vpnConsentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        Diagnostics.log("firewall.Main",
            "VPN consent result: ${if (result.resultCode == android.app.Activity.RESULT_OK) "OK" else "DENIED/CANCELLED (rc=${result.resultCode})"}")
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            FirewallSettings.setVpnRequested(ctx, true)
            FirewallSettings.setVpnPreempted(ctx, false)
            vpnEnabled = true
            preempted = false
            startVpn(ctx)
        }
    }

    val requestVpnEnable: () -> Unit = {
        // Single path for "I want firewall on" — used by both the main
        // Switch and the preempted-banner re-enable button.
        val prepare = VpnService.prepare(ctx)
        Diagnostics.log("firewall.Main",
            "requestVpnEnable: prepare=${if (prepare != null) "needs-consent" else "already-consented"}")
        if (prepare != null) {
            vpnConsentLauncher.launch(prepare)
        } else {
            FirewallSettings.setVpnRequested(ctx, true)
            FirewallSettings.setVpnPreempted(ctx, false)
            vpnEnabled = true
            preempted = false
            startVpn(ctx)
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(20.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("firewall", color = Color(0xFFE0E0E0), fontSize = 22.sp)
                Text(
                    if (vpnEnabled) "${blocked.size} app(s) blocked"
                    else "off",
                    color = Color(0xFF9E9E9E),
                    fontSize = 12.sp,
                )
                if (vpnEnabled) {
                    Text(
                        formatDropStatus(dropTotal, dropLastMillis),
                        color = Color(0xFF707070),
                        fontSize = 11.sp,
                    )
                }
            }
            Switch(
                checked = vpnEnabled,
                onCheckedChange = { wantOn ->
                    Diagnostics.log("firewall.Main", "VPN switch: wantOn=$wantOn")
                    if (wantOn) {
                        requestVpnEnable()
                    } else {
                        FirewallSettings.setVpnRequested(ctx, false)
                        FirewallSettings.setVpnPreempted(ctx, false)
                        vpnEnabled = false
                        preempted = false
                        stopVpn(ctx)
                    }
                },
            )
        }

        Spacer(Modifier.height(8.dp))

        if (preempted) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF3D2A00), RoundedCornerShape(6.dp))
                    .padding(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        "Firewall preempted",
                        color = Color(0xFFFFB74D),
                        fontSize = 12.sp,
                    )
                    Text(
                        "Another VPN (e.g. Proton) took the tunnel slot. " +
                            "Android only allows one VPN at a time and " +
                            "requires fresh consent to switch back.",
                        color = Color(0xFFFFB74D),
                        fontSize = 10.sp,
                    )
                }
                Spacer(Modifier.width(8.dp))
                Button(onClick = {
                    Diagnostics.log("firewall.Main", "Re-enable preempted VPN: tap")
                    requestVpnEnable()
                }) { Text("Re-enable") }
            }
            Spacer(Modifier.height(8.dp))
        }

        if (a11yState.activeServiceCount > 0) {
            Box(
                modifier = Modifier.fillMaxWidth()
                    .background(Color(0xFF3D2A00), RoundedCornerShape(6.dp))
                    .padding(10.dp),
            ) {
                Text(
                    "⚠  ${a11yState.activeServiceCount} third-party accessibility service(s) active. " +
                        "An a11y service can read this screen and exfiltrate your blocklist.",
                    color = Color(0xFFFFB74D),
                    fontSize = 11.sp,
                )
            }
            Spacer(Modifier.height(8.dp))
        }

        // First-run audit prompt. Shown once, on the first launch where
        // there's at least one detected remote-admin-class app that's
        // not already on the blocklist. The user has three actions:
        //
        //   - "Block all (N)" — adds every detected package to the
        //     blocklist and restarts the VPN if it's running.
        //   - "Review" — opens the AuditScreen for per-app handling
        //     without committing to a bulk block.
        //   - "Not now" — dismisses without action.
        //
        // All three set firstRunAuditDone=true so the banner doesn't
        // reappear; the AuditScreen itself remains permanently
        // available via AuditLink for follow-up review.
        // First-run prompt operates on findings that are neither already
        // blocked (no point re-blocking) nor acknowledged-as-fine. Note
        // that on a fresh install acknowledged is empty, so the first
        // run sees the full set; the acknowledge-aware filter only
        // matters if the user dismissed first-run with "Not now," went
        // to AuditScreen, acknowledged a few legitimate apps, and the
        // banner somehow re-fires (it shouldn't — firstRunDone protects
        // it — but the filter is a defense-in-depth correctness move).
        val unblockedFindings = remember(auditFindings, blocked, acknowledged) {
            auditFindings.filter {
                it.packageName !in blocked && it.packageName !in acknowledged
            }
        }
        if (!firstRunDone && unblockedFindings.isNotEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF3D2A00), RoundedCornerShape(6.dp))
                    .padding(12.dp),
            ) {
                Text(
                    "First-run audit: ${unblockedFindings.size} app(s) hold remote-admin capabilities",
                    color = Color(0xFFFFB74D),
                    fontSize = 12.sp,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Apps with device-admin, accessibility, notification access, " +
                        "or usage access can control the device or read its " +
                        "screen. Want to block their network access now? You can " +
                        "still revoke the capabilities themselves via Android " +
                        "Settings — that's the strongest action; this is a " +
                        "compensating control.",
                    color = Color(0xFFFFB74D),
                    fontSize = 10.sp,
                )
                Spacer(Modifier.height(10.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Button(onClick = {
                        Diagnostics.log(
                            "firewall.FirstRunAudit",
                            "Block all: tap (count=${unblockedFindings.size})",
                        )
                        val newBlocked = blocked + unblockedFindings.map { it.packageName }
                        FirewallSettings.setBlockedPackages(ctx, newBlocked)
                        FirewallSettings.setFirstRunAuditDone(ctx, true)
                        blocked = newBlocked
                        firstRunDone = true
                        if (vpnEnabled) startVpn(ctx)
                    }) { Text("Block all (${unblockedFindings.size})") }
                    OutlinedButton(onClick = {
                        Diagnostics.log("firewall.FirstRunAudit", "Review: tap")
                        FirewallSettings.setFirstRunAuditDone(ctx, true)
                        firstRunDone = true
                        onOpenAudit()
                    }) { Text("Review") }
                    OutlinedButton(onClick = {
                        Diagnostics.log("firewall.FirstRunAudit", "Not now: tap")
                        FirewallSettings.setFirstRunAuditDone(ctx, true)
                        firstRunDone = true
                    }) { Text("Not now") }
                }
            }
            Spacer(Modifier.height(8.dp))
        }

        Text(
            if (vpnEnabled) {
                "Apps toggled on are blocked. Their outbound network is captured by a local tun and dropped. Apps not toggled use the normal network unmodified."
            } else {
                "Toggle the switch above to enable. You'll be prompted by Android to consent to a VPN profile — that's our local tun. No traffic leaves your phone except as you allow."
            },
            color = Color(0xFF9E9E9E),
            fontSize = 12.sp,
        )

        Spacer(Modifier.height(12.dp))

        DnsPrefsButton(onClick = onOpenDnsPrefs)

        Spacer(Modifier.height(8.dp))

        AuditLink(
            // Badge shows un-acknowledged findings — apps the user has
            // not yet triaged. Acknowledged apps are still visible
            // inside AuditScreen behind a toggle, but they don't drive
            // the main-screen attention indicator.
            findingCount = auditFindings.count { it.packageName !in acknowledged },
            totalFindings = auditFindings.size,
            onClick = onOpenAudit,
        )

        Spacer(Modifier.height(8.dp))

        PostureLink(onClick = onOpenPosture)

        Spacer(Modifier.height(12.dp))

        // Filter chips: "All / Blocked / Apps / System". A small UI for
        // the "I just want to see what I've blocked" / "I just want to
        // see user apps" cases — without one, finding a single rule in
        // a list of 200+ apps means scrolling or guessing search terms.
        // Chip state is rememberSaveable as a String (same .name pattern
        // we use for FirewallRoute) so it survives configuration change.
        var filterName by androidx.compose.runtime.saveable.rememberSaveable {
            mutableStateOf(AppListFilter.All.name)
        }
        val activeFilter = remember(filterName) { AppListFilter.valueOf(filterName) }
        FilterChipRow(
            active = activeFilter,
            onSelect = { filterName = it.name },
        )

        Spacer(Modifier.height(8.dp))

        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            label = { Text("Search apps") },
            singleLine = true,
            // Trailing X clears the field — the soft keyboard's
            // backspace is a long way to cover when scanning a long
            // list. Only render when there's something to clear.
            trailingIcon = if (query.isNotEmpty()) {
                @Composable {
                    Text(
                        "✕",
                        color = Color(0xFF9E9E9E),
                        fontSize = 16.sp,
                        modifier = Modifier
                            .secureClickable {
                                Diagnostics.log("firewall.Main", "Search clear: tap")
                                query = ""
                            }
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                    )
                }
            } else null,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(8.dp))

        val filtered = remember(apps, query, blocked, activeFilter) {
            // Synthesize entries for blocked packages that aren't in the
            // installed list — otherwise stale rules would be invisible
            // (the blocklist is keyed by package name; uninstalled apps
            // don't appear in `apps`, so the user has no UI path to
            // remove them, and the "Blocked (N)" header undercounts).
            // We don't auto-prune: a temporary uninstall (e.g. clearing
            // app data) shouldn't silently lose the rule.
            val installed = apps.mapTo(HashSet(apps.size)) { it.packageName }
            val stale = (blocked - installed).map { pkg ->
                AppEntry(packageName = pkg, label = pkg, isSystemApp = false, isStale = true)
            }
            val effective = apps + stale
            // Apply the chip filter first — narrows the candidate set
            // before the (potentially expensive) text search, and means
            // "Blocked" mode is a clean view of just the rules.
            val byFilter = when (activeFilter) {
                AppListFilter.All -> effective
                AppListFilter.Blocked -> effective.filter { it.packageName in blocked }
                AppListFilter.Apps -> effective.filter { !it.isSystemApp }
                AppListFilter.System -> effective.filter { it.isSystemApp && !it.isStale }
            }
            val q = query.trim().lowercase()
            val matched = if (q.isEmpty()) byFilter else byFilter.filter {
                it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q)
            }
            // Show blocked apps first, then alphabetical.
            matched.sortedWith(
                compareByDescending<AppEntry> { it.packageName in blocked }
                    .thenBy { it.label.lowercase() }
            )
        }

        if (apps.isEmpty()) {
            Text("Loading installed apps…", color = Color(0xFF9E9E9E), fontSize = 12.sp)
            androidx.compose.foundation.layout.Spacer(Modifier.weight(1f))
        } else {
            // Sectioned view: "Blocked (N)" at top so the user can see
            // their current rules at a glance, "Other apps (M)" below.
            // Splitting the already-sorted `filtered` list at the
            // first non-blocked entry — `filtered` was sorted blocked-
            // first, then alphabetical, so the boundary is predictable.
            val blockedPart = filtered.filter { it.packageName in blocked }
            val otherPart = filtered.filter { it.packageName !in blocked }
            val onToggleBlocked: (AppEntry, Boolean) -> Unit = { entry, wantBlocked ->
                FirewallSettings.setBlocked(ctx, entry.packageName, wantBlocked)
                blocked = FirewallSettings.getBlockedPackages(ctx)
                if (vpnEnabled) startVpn(ctx)
            }
            // Icon cache scoped to FirewallScreen. Each entry is loaded
            // once per app lifetime; LazyColumn item recycling would
            // otherwise drop the per-row `remember` state and cause
            // PackageManager.getApplicationIcon() to fire on every
            // scroll-back. ~200 entries * a few KB each fits comfortably
            // in the small-icon bitmap budget at 48x48.
            val iconCache = remember { HashMap<String, ImageBitmap?>() }
            val pm = remember { ctx.packageManager }
            val getIcon: (String, Boolean) -> ImageBitmap? = { pkg, isStale ->
                if (isStale) null else iconCache.getOrPut(pkg) {
                    runCatching {
                        pm.getApplicationIcon(pkg).toBitmap(96, 96).asImageBitmap()
                    }.getOrNull()
                }
            }
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(4.dp),
                modifier = Modifier.fillMaxWidth().weight(1f),
            ) {
                if (blockedPart.isNotEmpty()) {
                    item(key = "header-blocked") {
                        SectionHeader("Blocked (${blockedPart.size})", Color(0xFFEF5350))
                    }
                    items(blockedPart, key = { "b-${it.packageName}" }) { entry ->
                        AppRow(
                            entry = entry,
                            icon = getIcon(entry.packageName, entry.isStale),
                            isBlocked = true,
                            onToggle = { wantBlocked -> onToggleBlocked(entry, wantBlocked) },
                        )
                    }
                }
                if (otherPart.isNotEmpty()) {
                    item(key = "header-other") {
                        SectionHeader("Other apps (${otherPart.size})", Color(0xFF9E9E9E))
                    }
                    items(otherPart, key = { "o-${it.packageName}" }) { entry ->
                        AppRow(
                            entry = entry,
                            icon = getIcon(entry.packageName, entry.isStale),
                            isBlocked = false,
                            onToggle = { wantBlocked -> onToggleBlocked(entry, wantBlocked) },
                        )
                    }
                }
                if (blockedPart.isEmpty() && otherPart.isEmpty()) {
                    // Filter or query yielded nothing. Without this hint
                    // the user sees blank space and assumes the app
                    // froze — happens most often the first time someone
                    // taps the "Blocked" chip with no rules set yet.
                    item(key = "empty-hint") {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 24.dp, bottom = 24.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(
                                when {
                                    activeFilter == AppListFilter.Blocked && query.isEmpty() ->
                                        "No apps blocked yet."
                                    query.isNotEmpty() -> "No matches for \"$query\"."
                                    else -> "Nothing here under this filter."
                                },
                                color = Color(0xFF707070),
                                fontSize = 12.sp,
                            )
                        }
                    }
                }
            }
        }
        OutlinedButton(onClick = onOpenOverlayRouting, modifier = Modifier.fillMaxWidth()) {
            Text("Overlay routing (I2P / Lokinet / Yggdrasil)")
        }
        OutlinedButton(onClick = onOpenPortBlocks, modifier = Modifier.fillMaxWidth()) {
            Text("Custom port blocking")
        }
        OutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) {
            Text("Diagnostics")
        }
        com.understory.security.SuiteStatusFooter()
    }
}

@Composable
private fun AppRow(
    entry: AppEntry,
    icon: ImageBitmap?,
    isBlocked: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (isBlocked) Color(0xFF2A1A1A) else Color(0xFF1C1C1C),
                RoundedCornerShape(6.dp),
            )
            .secureClickable { onToggle(!isBlocked) }
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Icon slot — fixed size whether the icon is present or not so
        // rows align across the list. Stale (uninstalled) entries get
        // a placeholder square instead of the real icon, since the
        // package no longer resolves through PackageManager.
        Box(
            modifier = Modifier
                .size(28.dp)
                .background(Color(0xFF111111), RoundedCornerShape(4.dp)),
            contentAlignment = Alignment.Center,
        ) {
            if (icon != null) {
                Image(
                    bitmap = icon,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                )
            } else {
                Text(
                    if (entry.isStale) "?" else entry.label.take(1).uppercase(),
                    color = Color(0xFF707070),
                    fontSize = 11.sp,
                )
            }
        }
        Spacer(Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    entry.label,
                    color = Color(0xFFE0E0E0),
                    fontSize = 13.sp,
                )
                if (entry.isStale) {
                    Spacer(Modifier.width(6.dp))
                    Box(
                        modifier = Modifier
                            .background(Color(0xFF3D2A00), RoundedCornerShape(3.dp))
                            .padding(horizontal = 5.dp, vertical = 1.dp),
                    ) {
                        Text(
                            "uninstalled",
                            color = Color(0xFFFFB74D),
                            fontSize = 9.sp,
                        )
                    }
                }
            }
            Text(
                entry.packageName,
                color = Color(0xFF707070),
                fontSize = 9.sp,
            )
        }
        // Switch is a passive visual indicator — onCheckedChange = null
        // makes it non-interactive. The whole Row is the click target via
        // secureClickable above; the Switch double-fire was the cause of
        // the "all toggles look on briefly" recomposition cascade users
        // were seeing on toggle.
        Switch(checked = isBlocked, onCheckedChange = null)
    }
}

@Composable
private fun FilterChipRow(
    active: AppListFilter,
    onSelect: (AppListFilter) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        for (filter in AppListFilter.values()) {
            val isActive = filter == active
            Box(
                modifier = Modifier
                    .weight(1f)
                    .background(
                        if (isActive) Color(0xFF1A2A3A) else Color(0xFF1C1C1C),
                        RoundedCornerShape(6.dp),
                    )
                    .secureClickable {
                        Diagnostics.log("firewall.Main", "Filter chip: ${filter.name}")
                        onSelect(filter)
                    }
                    .padding(vertical = 8.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    filter.label(),
                    color = if (isActive) Color(0xFF90CAF9) else Color(0xFF9E9E9E),
                    fontSize = 11.sp,
                )
            }
        }
    }
}

private fun AppListFilter.label(): String = when (this) {
    AppListFilter.All -> "All"
    AppListFilter.Blocked -> "Blocked"
    AppListFilter.Apps -> "Apps"
    AppListFilter.System -> "System"
}

@Composable
private fun SectionHeader(label: String, accent: Color) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp, bottom = 4.dp, start = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .background(accent, RoundedCornerShape(2.dp)),
        )
        Spacer(Modifier.width(8.dp))
        Text(
            text = label.uppercase(java.util.Locale.ROOT),
            color = accent,
            fontSize = 10.sp,
        )
    }
}

@Composable
private fun DnsPrefsButton(onClick: () -> Unit) {
    val ctx = LocalContext.current
    val current = remember { DnsProvider.byId(FirewallSettings.getDnsProviderId(ctx)) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
            .secureClickable { onClick() }
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text("DNS preferences", color = Color(0xFFE0E0E0), fontSize = 13.sp)
            Text(
                // "Selected", not "Current" — the stored choice is
                // informational until applied via system Private DNS
                // (in-tunnel DNS enforcement is phase 2; see PHASE2.md).
                "Selected: ${current.name} · applied via system Private DNS only",
                color = Color(0xFF9E9E9E),
                fontSize = 11.sp,
            )
        }
        Text("›", color = Color(0xFF707070), fontSize = 18.sp)
    }
}

@Composable
private fun AuditLink(
    findingCount: Int,
    totalFindings: Int,
    onClick: () -> Unit,
) {
    // Visual weight tracks un-acknowledged findings, not total. If the
    // user has acknowledged every finding (e.g. all are work MDM), the
    // row goes back to the quiet "audit clean" treatment even though
    // there are still apps with caps — that's correct: the user has
    // triaged them.
    val hasUnacknowledged = findingCount > 0
    val secondary = when {
        hasUnacknowledged && totalFindings > findingCount ->
            "$findingCount need review · ${totalFindings - findingCount} acknowledged"
        hasUnacknowledged ->
            "$findingCount app(s) hold device-admin, accessibility, " +
                "notification, or usage-access grants"
        totalFindings > 0 ->
            "All $totalFindings finding(s) acknowledged"
        else ->
            "No installed apps hold remote-admin-class grants"
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (hasUnacknowledged) Color(0xFF2A2010) else Color(0xFF1C1C1C),
                RoundedCornerShape(6.dp),
            )
            .secureClickable {
                Diagnostics.log(
                    "firewall.Main",
                    "AuditLink: tap (unacknowledged=$findingCount total=$totalFindings)",
                )
                onClick()
            }
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                "Remote-admin audit",
                color = if (hasUnacknowledged) Color(0xFFFFB74D) else Color(0xFFE0E0E0),
                fontSize = 13.sp,
            )
            Text(
                secondary,
                color = if (hasUnacknowledged) Color(0xFFFFB74D) else Color(0xFF9E9E9E),
                fontSize = 11.sp,
            )
        }
        Text(
            "›",
            color = if (hasUnacknowledged) Color(0xFFFFB74D) else Color(0xFF707070),
            fontSize = 18.sp,
        )
    }
}

@Composable
private fun AuditScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var findings by remember { mutableStateOf<List<AuditFinding>>(emptyList()) }
    var blocked by remember {
        mutableStateOf(FirewallSettings.getBlockedPackages(ctx))
    }
    var acknowledged by remember {
        mutableStateOf(FirewallSettings.getAuditAcknowledged(ctx))
    }
    var showAcknowledged by androidx.compose.runtime.saveable.rememberSaveable {
        mutableStateOf(false)
    }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        findings = RemoteAdminAudit.scan(ctx)
        loading = false
    }

    // Re-scan when the user comes back from a Settings deep-link — they
    // may have just revoked a capability and the screen should reflect
    // that without a process restart.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) {
                blocked = FirewallSettings.getBlockedPackages(ctx)
                acknowledged = FirewallSettings.getAuditAcknowledged(ctx)
                findings = RemoteAdminAudit.scan(ctx)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    Column(modifier = Modifier.fillMaxSize().padding(20.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Remote-admin audit", color = Color(0xFFE0E0E0), fontSize = 22.sp)
                Text(
                    "Apps holding screen-reading or device-control grants.",
                    color = Color(0xFF9E9E9E),
                    fontSize = 11.sp,
                )
            }
            OutlinedButton(onClick = onBack) { Text("Back") }
        }

        Spacer(Modifier.height(12.dp))

        Text(
            "Network-blocking these apps in the firewall is a compensating " +
                "control — it prevents an app from phoning home with what it " +
                "can see, but it does not stop on-device actions (a device-admin " +
                "can still lock the device offline; an a11y service can still " +
                "click your screen offline). The strongest fix is to revoke the " +
                "capability itself in Android Settings.",
            color = Color(0xFF9E9E9E),
            fontSize = 11.sp,
        )

        Spacer(Modifier.height(8.dp))

        if (loading) {
            Text("Scanning…", color = Color(0xFF9E9E9E), fontSize = 12.sp)
            return@Column
        }

        if (findings.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 24.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    "No installed apps hold remote-admin-class grants.",
                    color = Color(0xFF66BB6A),
                    fontSize = 12.sp,
                )
            }
            return@Column
        }

        // "Eligible to block" = not already blocked AND not acknowledged.
        // Bulk-block does not touch acknowledged apps even if they're
        // not yet blocked — acknowledging is the user's explicit "leave
        // this one alone" signal, and bulk-block must respect it.
        val bulkEligible = remember(findings, blocked, acknowledged) {
            findings.filter {
                it.packageName !in blocked && it.packageName !in acknowledged
            }
        }
        val acknowledgedCount = remember(findings, acknowledged) {
            findings.count { it.packageName in acknowledged }
        }
        if (bulkEligible.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "Block ${bulkEligible.size} app(s) at once",
                    color = Color(0xFFE0E0E0),
                    fontSize = 12.sp,
                    modifier = Modifier.weight(1f),
                )
                Button(onClick = {
                    Diagnostics.log(
                        "firewall.AuditScreen",
                        "Block all: tap (count=${bulkEligible.size})",
                    )
                    val newBlocked = blocked + bulkEligible.map { it.packageName }
                    FirewallSettings.setBlockedPackages(ctx, newBlocked)
                    blocked = newBlocked
                    if (FirewallSettings.isVpnRequested(ctx)) startVpn(ctx)
                }) { Text("Block all") }
            }
            Spacer(Modifier.height(8.dp))
        }

        // Acknowledged-toggle row. Only shown when there's at least one
        // acknowledged finding to reveal — no point offering a toggle
        // for an empty set.
        if (acknowledgedCount > 0) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
                    .secureClickable {
                        Diagnostics.log(
                            "firewall.AuditScreen",
                            "Toggle showAcknowledged: ${!showAcknowledged}",
                        )
                        showAcknowledged = !showAcknowledged
                    }
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    if (showAcknowledged) {
                        "Hide $acknowledgedCount acknowledged"
                    } else {
                        "Show $acknowledgedCount acknowledged"
                    },
                    color = Color(0xFF9E9E9E),
                    fontSize = 12.sp,
                    modifier = Modifier.weight(1f),
                )
                Switch(checked = showAcknowledged, onCheckedChange = null)
            }
            Spacer(Modifier.height(8.dp))
        }

        val displayedFindings = remember(findings, acknowledged, showAcknowledged) {
            if (showAcknowledged) findings
            else findings.filter { it.packageName !in acknowledged }
        }

        if (displayedFindings.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxWidth().padding(top = 24.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    if (acknowledgedCount > 0)
                        "All findings are acknowledged. Toggle above to review them."
                    else
                        "No installed apps hold remote-admin-class grants.",
                    color = Color(0xFF66BB6A),
                    fontSize = 12.sp,
                )
            }
            return@Column
        }

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(6.dp),
            modifier = Modifier.fillMaxWidth().weight(1f),
        ) {
            items(displayedFindings, key = { "audit-${it.packageName}" }) { finding ->
                AuditFindingCard(
                    finding = finding,
                    isBlocked = finding.packageName in blocked,
                    isAcknowledged = finding.packageName in acknowledged,
                    onToggleBlock = {
                        FirewallSettings.setBlocked(ctx, finding.packageName, it)
                        blocked = FirewallSettings.getBlockedPackages(ctx)
                        if (FirewallSettings.isVpnRequested(ctx)) startVpn(ctx)
                    },
                    onToggleAcknowledge = {
                        FirewallSettings.setAuditAcknowledged(ctx, finding.packageName, it)
                        acknowledged = FirewallSettings.getAuditAcknowledged(ctx)
                    },
                )
            }
        }
    }
}

@Composable
private fun AuditFindingCard(
    finding: AuditFinding,
    isBlocked: Boolean,
    isAcknowledged: Boolean,
    onToggleBlock: (Boolean) -> Unit,
    onToggleAcknowledge: (Boolean) -> Unit,
) {
    val ctx = LocalContext.current
    // Three visual states: blocked (red-tinted), acknowledged-not-blocked
    // (green-tinted, "this one's fine"), and unhandled (default neutral).
    // Blocked takes priority over acknowledged in the visual since the
    // network-level rule is the more constraining state.
    val cardColor = when {
        isBlocked -> Color(0xFF2A1A1A)
        isAcknowledged -> Color(0xFF1A2A1A)
        else -> Color(0xFF1C1C1C)
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(cardColor, RoundedCornerShape(6.dp))
            .padding(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(finding.label, color = Color(0xFFE0E0E0), fontSize = 13.sp)
                    if (isAcknowledged) {
                        Spacer(Modifier.width(6.dp))
                        Box(
                            modifier = Modifier
                                .background(Color(0xFF1F3A1F), RoundedCornerShape(3.dp))
                                .padding(horizontal = 5.dp, vertical = 1.dp),
                        ) {
                            Text(
                                "acknowledged",
                                color = Color(0xFF81C784),
                                fontSize = 9.sp,
                            )
                        }
                    }
                }
                Text(finding.packageName, color = Color(0xFF707070), fontSize = 9.sp)
            }
            Switch(
                checked = isBlocked,
                onCheckedChange = onToggleBlock,
            )
        }
        Spacer(Modifier.height(8.dp))
        for (cap in finding.capabilities) {
            Column(modifier = Modifier.padding(vertical = 4.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .background(Color(0xFFFFB74D), RoundedCornerShape(3.dp)),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        cap.display,
                        color = Color(0xFFFFB74D),
                        fontSize = 11.sp,
                    )
                }
                Text(
                    cap.explanation,
                    color = Color(0xFF9E9E9E),
                    fontSize = 10.sp,
                    modifier = Modifier.padding(start = 14.dp, top = 2.dp),
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        // Action row: revoke-at-source on the left (the strong fix),
        // acknowledge on the right (the "this is legitimate, stop
        // flagging it" escape hatch). Acknowledge is always present;
        // the revoke deep-link is conditional on having a known action.
        //
        // We pick the highest-severity capability's revokeAction as
        // the primary target — sort order on the finding already
        // brings the most-urgent cap first within capabilities, so
        // .firstOrNull() yields the right page to deep-link to.
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            finding.capabilities.firstOrNull()?.revokeAction?.let { action ->
                OutlinedButton(
                    onClick = {
                        Diagnostics.log(
                            "firewall.AuditScreen",
                            "Open settings: ${finding.packageName} -> $action",
                        )
                        val intent = Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        runCatching { ctx.startActivity(intent) }
                            .recoverCatching {
                                ctx.startActivity(
                                    Intent(android.provider.Settings.ACTION_SETTINGS)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                )
                            }
                    },
                    modifier = Modifier.weight(1f),
                ) { Text("Revoke in Settings") }
            }
            OutlinedButton(
                onClick = {
                    Diagnostics.log(
                        "firewall.AuditScreen",
                        "Toggle acknowledge: ${finding.packageName} -> ${!isAcknowledged}",
                    )
                    onToggleAcknowledge(!isAcknowledged)
                },
                modifier = Modifier.weight(1f),
            ) {
                Text(if (isAcknowledged) "Un-acknowledge" else "Acknowledge")
            }
        }
    }
}

@Composable
private fun PostureLink(onClick: () -> Unit) {
    // Subdued link row matching DnsPrefsButton's visual weight. The
    // Posture screen is documentation, not a settings surface — kept
    // visually quieter than DNS prefs which actually affects behavior.
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
            .secureClickable { onClick() }
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text("Network posture", color = Color(0xFFE0E0E0), fontSize = 13.sp)
            Text(
                "Sovereign mode — no remote admin, no telemetry, no cloud.",
                color = Color(0xFF9E9E9E),
                fontSize = 11.sp,
            )
        }
        Text("›", color = Color(0xFF707070), fontSize = 18.sp)
    }
}

@Composable
private fun PostureScreen(onBack: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize().padding(20.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Network posture", color = Color(0xFFE0E0E0), fontSize = 22.sp)
                Text(
                    "What this app structurally cannot do.",
                    color = Color(0xFF9E9E9E),
                    fontSize = 11.sp,
                )
            }
            OutlinedButton(onClick = onBack) { Text("Back") }
        }

        Spacer(Modifier.height(16.dp))

        // The posture surface is intentionally a wall of plain text.
        // Each section is one structural property of the suite, stated
        // honestly: what it is, why it's structural (not just policy),
        // and what would have to change to break it. Users reading this
        // screen are auditing the trust model; bullet-points / pretty
        // cards would obscure the audit.
        androidx.compose.foundation.lazy.LazyColumn(
            verticalArrangement = Arrangement.spacedBy(14.dp),
            modifier = Modifier.fillMaxWidth().weight(1f),
        ) {
            item { PostureSection(
                title = "Blind by default",
                body = "The firewall has no remote-admin path. There is no exported " +
                    "BroadcastReceiver, no exported Service that accepts control intents " +
                    "from other UIDs, no IPC server bound to a TCP socket. The only " +
                    "control surface is the in-app UI on the unlocked device. Breaking " +
                    "this would require shipping a new exported component with a " +
                    "public API — visible in the manifest diff at update time.",
            ) }
            item { PostureSection(
                title = "No telemetry",
                body = "No analytics SDK, no crash reporter, no feature-flag service. " +
                    "Diagnostics are an in-app screen the user reads themselves; " +
                    "nothing is shipped off-device.",
            ) }
            item { PostureSection(
                title = "No cloud",
                body = "Of the seven suite apps, only the firewall and the browser " +
                    "request the INTERNET permission — and those uses are direct " +
                    "(VpnService.protectedSocket fallbacks; the user's own browser " +
                    "traffic). Every other app strips INTERNET via " +
                    "tools:node=\"remove\" so no transitive library can silently add " +
                    "it back.",
            ) }
            item { PostureSection(
                title = "One-VPN-slot exclusivity",
                body = "Android only allows one active VpnService at a time. The " +
                    "firewall claims that slot when armed. To run another tunnel — " +
                    "Yggdrasil, Lokinet, DNSCrypt, an official VPN client — turn the " +
                    "firewall off (the toggle on the main screen). There is no " +
                    "remote-admin command to do this; it's a deliberate user act.",
            ) }
            item { PostureSection(
                title = "Browser-level proxy is a separate layer",
                body = "The browser's optional 'Route via I2P' (when bundled) is a " +
                    "browser-process userspace proxy on 127.0.0.1. It does not claim " +
                    "the VpnService slot and composes with the firewall: armed " +
                    "firewall + I2P-on browser is a valid configuration. See " +
                    "android/OVERLAY_NETWORKS.md for the chain diagram.",
            ) }
            item { PostureSection(
                title = "Open source, reproducible target",
                body = "The full source is published. Reproducible builds + a real " +
                    "release keystore + cert pinning are tracked as release " +
                    "blockers — the posture is honest about not yet being there.",
            ) }
        }
    }
}

@Composable
private fun PostureSection(title: String, body: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
            .padding(14.dp),
    ) {
        Text(title, color = Color(0xFFE0E0E0), fontSize = 13.sp)
        Spacer(Modifier.height(6.dp))
        Text(body, color = Color(0xFF9E9E9E), fontSize = 11.sp)
    }
}

@Composable
private fun DnsPrefsScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var selectedId by remember { mutableStateOf(FirewallSettings.getDnsProviderId(ctx)) }
    val selected = remember(selectedId) { DnsProvider.byId(selectedId) }

    Column(modifier = Modifier.fillMaxSize().padding(20.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("DNS preferences", color = Color(0xFFE0E0E0), fontSize = 22.sp)
                Text(
                    "Phase 2 pending — selection is informational; " +
                        "applied via system Private DNS only.",
                    color = Color(0xFF9E9E9E),
                    fontSize = 11.sp,
                )
            }
            OutlinedButton(onClick = onBack) { Text("Back") }
        }

        Spacer(Modifier.height(12.dp))

        Text(
            "Picking a provider stores your choice — it does not change " +
                "how DNS resolves by itself.\n\n" +
                "DoT providers (Cloudflare, Quad9, Google, OpenDNS, NextDNS) " +
                "take effect only through Android's system Private DNS — " +
                "programmatic when WRITE_SECURE_SETTINGS is granted, else " +
                "the deep-link below.\n\n" +
                "DNSCrypt providers (Quad9 / AdGuard / Cisco) start the " +
                "bundled dnscrypt-proxy as a local service, but apps' DNS " +
                "queries are NOT forwarded to it yet — that needs tun-level " +
                "DNS forwarding, which is phase 2 (see PHASE2.md). If the " +
                "firewall VPN (re)starts while a DNSCrypt provider is " +
                "selected it enters an experimental DNS-redirect mode that " +
                "pauses app- and port-blocking; treat that as a preview, " +
                "not enforcement.",
            color = Color(0xFF9E9E9E),
            fontSize = 11.sp,
        )

        Spacer(Modifier.height(12.dp))

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(4.dp),
            modifier = Modifier.fillMaxWidth().weight(1f),
        ) {
            item(key = "dns-active-mechanism") {
                DnsActiveMechanismCard()
                Spacer(Modifier.height(8.dp))
            }
            items(DnsProvider.ALL, key = { "dns-${it.id}" }) { provider ->
                DnsProviderRow(
                    provider = provider,
                    isSelected = provider.id == selectedId,
                    onSelect = {
                        FirewallSettings.setDnsProviderId(ctx, provider.id)
                        selectedId = provider.id
                        // Auto-manage the DNSCrypt proxy service on
                        // selection changes. DNSCrypt picks start the
                        // service (which writes a fresh config matching
                        // the new stamp + restarts the binary). Non-
                        // DNSCrypt picks stop it. Idempotent — repeated
                        // start commands re-config the running service.
                        if (provider.protocol == DnsProtocol.DNSCRYPT) {
                            DnsCryptProxyService.start(ctx)
                        } else {
                            DnsCryptProxyService.stop(ctx)
                        }
                    },
                )
            }
            item(key = "dns-actions") {
                Spacer(Modifier.height(12.dp))
                DnsActionsCard(selected)
            }
        }
    }
}

/**
 * "Active now" readout — which DNS mechanism is actually in effect,
 * as opposed to which provider is selected. Two live facts:
 *
 *   - the device's system Private DNS state, read back from
 *     Settings.Global via PrivateDnsApplier (reads need no permission,
 *     so this reflects reality even when our write path lacks the
 *     ADB grant — including changes the user made in Settings);
 *   - whether the local dnscrypt-proxy service is running (with the
 *     explicit caveat that app DNS is not routed to it until phase 2).
 */
@Composable
private fun DnsActiveMechanismCard() {
    val ctx = LocalContext.current
    var privateDns by remember { mutableStateOf(PrivateDnsApplier.current(ctx)) }
    var proxyRunning by remember { mutableStateOf(DnsCryptProxyService.isRunning()) }
    // 1s poll, same cadence rationale as the drop counter on the main
    // screen: the reads are cheap, and the card must track changes made
    // outside this screen (Settings edits, service start/stop) without
    // lifecycle plumbing.
    LaunchedEffect(Unit) {
        while (true) {
            privateDns = PrivateDnsApplier.current(ctx)
            proxyRunning = DnsCryptProxyService.isRunning()
            delay(1000)
        }
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1A2A3A), RoundedCornerShape(6.dp))
            .padding(12.dp),
    ) {
        Text("Active now", color = Color(0xFF90CAF9), fontSize = 13.sp)
        Spacer(Modifier.height(6.dp))
        Text(
            when (privateDns.mode) {
                "hostname" -> "System Private DNS: " +
                    (privateDns.specifier ?: "(hostname mode, no hostname set)")
                "off" -> "System Private DNS: off — cleartext resolver " +
                    "from the network"
                else -> "System Private DNS: automatic (opportunistic DoT)"
            },
            color = Color(0xFFE0E0E0),
            fontSize = 11.sp,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            if (proxyRunning) {
                "dnscrypt-proxy: running on " +
                    "127.0.0.1:${DnsCryptProxyService.LOCAL_PORT} — app DNS " +
                    "is not routed here yet (phase 2)"
            } else {
                "dnscrypt-proxy: not running"
            },
            color = if (proxyRunning) Color(0xFFFFB74D) else Color(0xFF9E9E9E),
            fontSize = 11.sp,
        )
    }
}

@Composable
private fun DnsProviderRow(
    provider: DnsProvider,
    isSelected: Boolean,
    onSelect: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (isSelected) Color(0xFF1A2A1A) else Color(0xFF1C1C1C),
                RoundedCornerShape(6.dp),
            )
            .secureClickable { onSelect() }
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(10.dp)
                .background(
                    if (isSelected) Color(0xFF66BB6A) else Color(0xFF424242),
                    RoundedCornerShape(5.dp),
                ),
        )
        Spacer(Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(provider.name, color = Color(0xFFE0E0E0), fontSize = 13.sp)
            if (provider.dotHostname.isNotEmpty()) {
                Text(provider.dotHostname, color = Color(0xFF707070), fontSize = 10.sp)
            }
            Text(
                provider.privacyNote,
                color = Color(0xFF9E9E9E),
                fontSize = 10.sp,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}

@Composable
private fun DnsActionsCard(selected: DnsProvider) {
    val ctx = LocalContext.current
    var actionStatus by remember { mutableStateOf<String?>(null) }
    val hasGrant = remember(actionStatus) { PrivateDnsApplier.hasGrant(ctx) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
            .padding(12.dp),
    ) {
        Text(
            "Apply your selection",
            color = Color(0xFFE0E0E0),
            fontSize = 13.sp,
        )
        Spacer(Modifier.height(6.dp))

        // DNSCrypt providers don't go through Android Private DNS, and
        // apps' DNS doesn't reach the local proxy until phase-2 tun
        // forwarding — so there is nothing to "apply" here yet. Say so.
        if (selected.protocol == DnsProtocol.DNSCRYPT) {
            Text(
                "Phase 2 — selection is informational. The bundled " +
                    "dnscrypt-proxy runs as a local service (status above), " +
                    "but apps' DNS queries are not forwarded to it until " +
                    "tun-level DNS forwarding lands. For an enforced DNS " +
                    "override today, pick a DoT provider and apply it via " +
                    "system Private DNS.",
                color = Color(0xFFFFB74D), fontSize = 11.sp,
            )
            return@Column
        }

        if (selected.dotHostname.isEmpty()) {
            Text(
                "System default has no DoT hostname to apply. Choose a provider above.",
                color = Color(0xFF9E9E9E),
                fontSize = 11.sp,
            )
        } else {
            // Prefer programmatic apply when WRITE_SECURE_SETTINGS is
            // granted; fall back to the deep-link + copy flow otherwise.
            // Show the user which path is in effect so they're not
            // surprised by a tap doing nothing visible.
            if (hasGrant) {
                Text(
                    "ADB-grant present. \"Apply now\" sets Android's Private " +
                        "DNS specifier to ${selected.dotHostname} directly — " +
                        "no Settings round-trip.",
                    color = Color(0xFF66BB6A), fontSize = 11.sp,
                )
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Button(onClick = {
                        Diagnostics.log("firewall.DnsPrefs",
                            "Apply Private DNS programmatically: ${selected.id}")
                        actionStatus = when (val r = PrivateDnsApplier.apply(ctx, selected.dotHostname)) {
                            is PrivateDnsApplier.Result.Applied ->
                                "Applied. Private DNS is now ${r.hostname}."
                            is PrivateDnsApplier.Result.NeedsAdbGrant ->
                                "Grant missing — run: ${r.adbCommand}"
                            is PrivateDnsApplier.Result.Failed ->
                                "Apply failed: ${r.reason}"
                        }
                    }) { Text("Apply now") }
                    Spacer(Modifier.width(8.dp))
                    OutlinedButton(onClick = {
                        Diagnostics.log("firewall.DnsPrefs", "Disable Private DNS: tap")
                        actionStatus = when (val r = PrivateDnsApplier.clear(ctx)) {
                            is PrivateDnsApplier.Result.Applied ->
                                "Private DNS disabled."
                            is PrivateDnsApplier.Result.NeedsAdbGrant ->
                                "Grant missing — run: ${r.adbCommand}"
                            is PrivateDnsApplier.Result.Failed ->
                                "Clear failed: ${r.reason}"
                        }
                    }) { Text("Disable") }
                }
                actionStatus?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, color = Color(0xFF9E9E9E), fontSize = 11.sp)
                }
            } else {
                Text(
                    "Two options:\n\n" +
                        "  Option A (one-time, automated): grant " +
                        "WRITE_SECURE_SETTINGS via ADB, then tap \"Apply now\" " +
                        "from now on.\n" +
                        "    adb shell pm grant com.understory.firewall \\\n" +
                        "      android.permission.WRITE_SECURE_SETTINGS\n\n" +
                        "  Option B (manual every time):\n" +
                        "  1. Tap \"Open Private DNS settings\".\n" +
                        "  2. Pick \"Private DNS provider hostname\".\n" +
                        "  3. Paste:  ${selected.dotHostname}",
                    color = Color(0xFF9E9E9E),
                    fontSize = 11.sp,
                )
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Button(onClick = {
                        Diagnostics.log("firewall.DnsPrefs", "Open Private DNS settings: tap")
                        val primary = Intent("android.settings.PRIVATE_DNS_SETTINGS")
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        runCatching { ctx.startActivity(primary) }
                            .recoverCatching {
                                ctx.startActivity(
                                    Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                )
                            }
                    }) { Text("Open Private DNS settings") }
                    Spacer(Modifier.width(8.dp))
                    OutlinedButton(onClick = {
                        Diagnostics.log("firewall.DnsPrefs", "Copy hostname: tap (${selected.id})")
                        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        cm?.setPrimaryClip(
                            ClipData.newPlainText("DoT hostname", selected.dotHostname)
                        )
                    }) { Text("Copy hostname") }
                }
                OutlinedButton(
                    onClick = {
                        Diagnostics.log("firewall.DnsPrefs", "Copy ADB grant: tap")
                        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        cm?.setPrimaryClip(
                            ClipData.newPlainText(
                                "ADB grant",
                                "adb shell pm grant com.understory.firewall " +
                                    "android.permission.WRITE_SECURE_SETTINGS",
                            )
                        )
                        actionStatus = "ADB command copied to clipboard."
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Copy ADB grant command") }
                actionStatus?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, color = Color(0xFF9E9E9E), fontSize = 11.sp)
                }
            }
        }
    }
}

private fun formatDropStatus(total: Long, lastMillis: Long): String {
    if (total == 0L) return "no packets dropped yet"
    val ago = if (lastMillis == 0L) "" else {
        val secs = ((System.currentTimeMillis() - lastMillis) / 1000L).coerceAtLeast(0L)
        when {
            secs < 5 -> " · just now"
            secs < 60 -> " · ${secs}s ago"
            secs < 3600 -> " · ${secs / 60}m ago"
            else -> " · ${secs / 3600}h ago"
        }
    }
    return "dropped $total packet${if (total == 1L) "" else "s"}$ago"
}

private fun startVpn(ctx: Context) {
    val intent = Intent(ctx, FirewallVpnService::class.java)
    ctx.startForegroundService(intent)
}

private fun stopVpn(ctx: Context) {
    val intent = Intent(ctx, FirewallVpnService::class.java).apply {
        action = FirewallVpnService.ACTION_STOP
    }
    runCatching { ctx.startService(intent) }
}

data class AppEntry(
    val packageName: String,
    val label: String,
    val isSystemApp: Boolean,
    /**
     * True when this entry was synthesized for a package that's on the
     * blocklist but no longer installed. The rule still exists in
     * SharedPreferences and will re-attach if the app is reinstalled,
     * but right now there's nothing to capture. Surfaced in the UI with
     * an "uninstalled" pill so the user can audit + clear stale rules.
     */
    val isStale: Boolean = false,
)

private object AppListLoader {
    fun load(ctx: Context): List<AppEntry> {
        val pm = ctx.packageManager
        val flags = PackageManager.GET_META_DATA
        return runCatching {
            pm.getInstalledApplications(flags)
                .filter { it.packageName != ctx.packageName }
                .map { ai ->
                    AppEntry(
                        packageName = ai.packageName,
                        label = ai.loadLabel(pm).toString(),
                        isSystemApp = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                    )
                }
                .filter {
                    // Hide most system apps; keep ones that have a launcher
                    // intent (= user-facing) even if FLAG_SYSTEM is set.
                    !it.isSystemApp || pm.getLaunchIntentForPackage(it.packageName) != null
                }
        }.getOrDefault(emptyList())
    }
}
