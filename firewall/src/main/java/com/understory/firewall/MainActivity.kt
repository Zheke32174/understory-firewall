package com.understory.firewall

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.core.view.WindowCompat
import com.understory.security.KeepAliveBackHandler
import com.understory.security.SuiteAttestation
import com.understory.security.Tamper
import com.understory.security.TestingMode
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.ui.components.FatalScreen
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * Understory Net Audit — the offline egress dashboard for a Tailscale user
 * (design-v2/firewall.md). Observe + advise + route in the default Companion
 * mode; real per-app blocking only inside the walled-off Standalone mode,
 * which refuses to start whenever any other VPN is present.
 */
class MainActivity : ComponentActivity() {

    companion object {
        /**
         * Optional intent extra naming a [FirewallRoute] to open on launch. Set
         * by the Posture Watch notification's tap PendingIntent so tapping the
         * alert lands on the review screen. Ignored if absent or unparseable.
         */
        const val EXTRA_OPEN_ROUTE = "com.understory.firewall.OPEN_ROUTE"
    }

    /**
     * A one-shot deep-link route request published by onCreate/onNewIntent and
     * consumed by [FirewallRoot]. Held as compose state so a tap that arrives
     * while the activity is alive still navigates.
     */
    private val deepLinkRoute = androidx.compose.runtime.mutableStateOf<FirewallRoute?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        DiagnosticsDump.activateIfEng(this)
        Diagnostics.log("firewall.MainActivity", "onCreate")
        super.onCreate(savedInstanceState)
        // One-time V2 settings migration — before any screen reads settings.
        runCatching { FirewallSettings.migrateV2IfNeeded(this) }
            .onFailure { Diagnostics.error("firewall.MainActivity", "migrateV2 threw: ${it.message}") }
        try {
            initialize()
        } catch (t: Throwable) {
            Diagnostics.error("firewall.MainActivity", "onCreate threw: ${t.javaClass.simpleName}: ${t.message}")
            setContent {
                UnderstoryTheme(accent = UnderstoryAccent.FIREWALL) {
                    FatalScreen(
                        title = "Net Audit couldn't start",
                        reason = "An unexpected error occurred while starting the app.",
                        details = t.toString(),
                    )
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        DiagnosticsDump.snapshotState(this, "onPause")
    }

    override fun onStop() {
        super.onStop()
        DiagnosticsDump.snapshotState(this, "onStop")
    }

    private fun initialize() {
        val debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        if (debuggerAttached ||
            Tamper.check(applicationContext).hardFail ||
            SuiteAttestation.verify(applicationContext).hardFail
        ) {
            // CD-4c: don't die silently. Show the suite tamper hard-fail
            // explanation, then let the user dismiss to exit.
            setContent {
                UnderstoryTheme(accent = UnderstoryAccent.FIREWALL) {
                    FatalScreen(
                        title = "Net Audit is locked",
                        reason = "This copy of Understory Net Audit failed an integrity " +
                            "or attestation check and won't run. This protects you from a " +
                            "tampered or repackaged build. Reinstall the app from a trusted " +
                            "source.",
                    )
                }
            }
            return
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

        deepLinkRoute.value = parseRouteExtra(intent)
        setContent {
            UnderstoryTheme(accent = UnderstoryAccent.FIREWALL) {
                FirewallRoot(activity = this, deepLink = deepLinkRoute)
            }
        }
    }

    /**
     * The activity is singleTask, so a notification tap while it is already
     * running arrives here, not via a fresh onCreate. Publish the requested
     * route to the compose state so FirewallRoot navigates to it. A one-shot:
     * FirewallRoot consumes and clears it so a config change doesn't re-navigate.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        parseRouteExtra(intent)?.let { deepLinkRoute.value = it }
    }

    /** Read + validate the optional [EXTRA_OPEN_ROUTE] into a route, or null. */
    private fun parseRouteExtra(intent: Intent?): FirewallRoute? {
        val name = intent?.getStringExtra(EXTRA_OPEN_ROUTE) ?: return null
        return runCatching { FirewallRoute.valueOf(name) }.getOrNull()
    }

    override fun onResume() {
        super.onResume()
        Tamper.invalidate()
        if (Tamper.check(applicationContext).hardFail) {
            Diagnostics.error("firewall.MainActivity", "Tamper hardFail on resume — finishing")
            finishAndRemoveTask()
        }
    }
}

/**
 * The six destinations off the Egress Dashboard, plus the walled-off
 * Standalone hub (design-v2/firewall.md §2). Hand-rolled saveable route
 * enum + per-route BackHandler (audit C.4 "actually solid").
 */
enum class FirewallRoute {
    Main, TunnelPosture, Audit, Dns, Traffic, Restrict, Canary, Posture, Limits,
    StandaloneHub, Diagnostics, PostureWatch, Elevation,
}

/** Helper to start/stop the Standalone engine service. */
internal fun startEngine(ctx: Context) {
    val intent = Intent(ctx, FirewallVpnService::class.java)
    ctx.startForegroundService(intent)
}

internal fun stopEngine(ctx: Context) {
    val intent = Intent(ctx, FirewallVpnService::class.java).apply {
        action = FirewallVpnService.ACTION_STOP
    }
    runCatching { ctx.startService(intent) }
}

@Composable
private fun FirewallRoot(
    activity: ComponentActivity,
    deepLink: androidx.compose.runtime.MutableState<FirewallRoute?> =
        androidx.compose.runtime.mutableStateOf(null),
) {
    var routeName by rememberSaveable { mutableStateOf(FirewallRoute.Main.name) }
    val route = remember(routeName) { FirewallRoute.valueOf(routeName) }
    val setRoute: (FirewallRoute) -> Unit = {
        Diagnostics.log("firewall.Root", "route: $routeName → ${it.name}")
        routeName = it.name
    }
    val backToMain: () -> Unit = { setRoute(FirewallRoute.Main) }

    // Consume a one-shot deep-link route (e.g. a Posture Watch notification
    // tap). Navigate once, then clear so a recomposition/config-change can't
    // yank the user back after they navigate away.
    val pendingDeepLink = deepLink.value
    androidx.compose.runtime.LaunchedEffect(pendingDeepLink) {
        if (pendingDeepLink != null) {
            setRoute(pendingDeepLink)
            deepLink.value = null
        }
    }

    when (route) {
        FirewallRoute.Main -> {
            KeepAliveBackHandler("firewall.Root.Main")
            EgressDashboardScreen(
                onOpen = setRoute,
            )
        }
        FirewallRoute.TunnelPosture -> {
            androidx.activity.compose.BackHandler { backToMain() }
            TunnelPostureScreen(onBack = backToMain)
        }
        FirewallRoute.Audit -> {
            androidx.activity.compose.BackHandler { backToMain() }
            AuditScreen(onBack = backToMain)
        }
        FirewallRoute.Dns -> {
            androidx.activity.compose.BackHandler { backToMain() }
            DnsHardeningScreen(onBack = backToMain)
        }
        FirewallRoute.Traffic -> {
            androidx.activity.compose.BackHandler { backToMain() }
            TrafficScreen(onBack = backToMain)
        }
        FirewallRoute.Restrict -> {
            androidx.activity.compose.BackHandler { backToMain() }
            RestrictScreen(onBack = backToMain)
        }
        FirewallRoute.Canary -> {
            androidx.activity.compose.BackHandler { backToMain() }
            CanaryScreen(onBack = backToMain)
        }
        FirewallRoute.Posture -> {
            androidx.activity.compose.BackHandler { backToMain() }
            PostureScreen(onBack = backToMain)
        }
        FirewallRoute.Limits -> {
            androidx.activity.compose.BackHandler { backToMain() }
            LimitsScreen(onBack = backToMain, onDiagnostics = { setRoute(FirewallRoute.Diagnostics) })
        }
        FirewallRoute.StandaloneHub -> {
            androidx.activity.compose.BackHandler { backToMain() }
            StandaloneHubScreen(activity = activity, onBack = backToMain)
        }
        FirewallRoute.Diagnostics -> {
            androidx.activity.compose.BackHandler { backToMain() }
            DiagnosticsScreen(onBack = backToMain)
        }
        FirewallRoute.PostureWatch -> {
            androidx.activity.compose.BackHandler { backToMain() }
            PostureWatchScreen(onBack = backToMain)
        }
        FirewallRoute.Elevation -> {
            androidx.activity.compose.BackHandler { backToMain() }
            ElevationScreen(onBack = backToMain)
        }
    }
}
