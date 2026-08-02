package com.understory.godwall.ward

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.understory.godwall.apps.DeniedApps
import com.understory.godwall.apps.NetworkChainBackend
import com.understory.godwall.chain.EndpointChain
import com.understory.godwall.core.AppPolicy
import com.understory.godwall.core.EngineState
import com.understory.godwall.dns.BlocklistRepository
import com.understory.godwall.dns.DnsEventLog
import com.understory.godwall.dns.DnsSettings
import com.understory.godwall.mesh.Mesh
import com.understory.godwall.mesh.MeshSettings
import com.understory.security.Tamper

/**
 * One read of everything the WARD screen shows.
 *
 * The donors' home screens are a column of cards, each summarising a subsystem and tapping
 * through to it (RethinkDNS's `HomeScreenFragment`; InviZible's module cards). Reproducing that
 * means six independent reads per refresh — package manager, preferences, the trust store, a
 * privileged probe — so they are gathered **once, off the main thread**, into one immutable
 * snapshot rather than by six separate `produceState` blocks racing each other.
 *
 * Nothing here is derived from what the user last tapped. Every field is read from the engine
 * that owns it, which is the same discipline `EngineState` exists to enforce for the arm state.
 */
object WardStatus {

    data class TunnelCard(
        val state: Mesh.State,
        val detail: String,
        val addresses: List<String>,
        val exitNode: String,
        /** Empty when the device posture check found nothing to say. */
        val postureWarnings: List<String>,
    )

    data class DnsCard(
        val resolver: String,
        val filterEnabled: Boolean,
        val blocklistDomains: Int,
        val leak: DnsLeak.Result,
    )

    data class FirewallCard(
        val blocked: Int,
        val isolated: Int,
        val excluded: Int,
        val refused: Int,
        /** Null when the platform chain can be driven right now. */
        val unavailableReason: String?,
    )

    data class ProxyCard(
        val chainEnabled: Boolean,
        val hops: Int,
        val path: String,
        val gated: List<GatedCapability>,
    )

    data class LogsCard(
        val queries: Long,
        val blocked: Long,
        /** Events recorded in the last minute — the donors' "live rate". */
        val perMinute: Int,
        val blockedPerMinute: Int,
    )

    data class AppsCard(
        val total: Int,
        val withInternet: Int,
        val blocked: Int,
    )

    data class Snapshot(
        val mode: WardMode,
        val phase: EngineState.Phase,
        val engineDetail: String,
        val enforcement: EnforcementSelection,
        val probes: List<BackendProbe>,
        val tunnel: TunnelCard,
        val dns: DnsCard,
        val firewall: FirewallCard,
        val proxy: ProxyCard,
        val logs: LogsCard,
        val apps: AppsCard,
        val alerts: List<HealthCheck.Alert>,
        val killSwitch: KillSwitch.State,
        val childLockConfigured: Boolean,
        val childLockEngaged: Boolean,
    )

    /**
     * Gather everything. **Blocking** — package manager, preferences, the CA store and up to
     * three privileged shell round trips. Call on `Bg.io`.
     */
    fun read(ctx: Context): Snapshot {
        val engine = EngineState.state.value
        val mode = WardModeStore.current(ctx)

        val probes = Enforcement.probe(ctx)
        val selection = Enforcement.select(probes, Enforcement.manual(ctx))

        val meshStatus = Mesh.status(ctx)
        val tamper = Tamper.check(ctx)
        val tunnel = TunnelCard(
            state = meshStatus.state,
            detail = meshStatus.detail,
            addresses = meshStatus.tailnetIps,
            exitNode = MeshSettings.exitNode(ctx),
            postureWarnings = tamper.warnings,
        )

        val leak = DnsLeak.check(ctx)
        val filterOn = BlocklistRepository.isFilterEnabled(ctx)
        val domains = BlocklistRepository.stats().totalDomains
        val dns = DnsCard(
            resolver = DnsSettings.describe(ctx),
            filterEnabled = filterOn,
            blocklistDomains = domains,
            leak = leak,
        )

        val denied = DeniedApps.all(ctx)
        val effective = DeniedApps.effective(ctx)
        val blackholed = AppPolicy.blackholed(ctx)
        val bypassed = AppPolicy.bypassed(ctx)
        val chainBackend = NetworkChainBackend(ctx)
        val firewall = FirewallCard(
            blocked = effective.size,
            isolated = blackholed.size,
            excluded = bypassed.size,
            refused = (denied.size - effective.size).coerceAtLeast(0),
            unavailableReason = chainBackend.unavailableReason(ctx),
        )

        val hops = EndpointChain.hops(ctx)
        val proxy = ProxyCard(
            chainEnabled = EndpointChain.isEnabled(ctx),
            hops = hops.size,
            path = EndpointChain.describe(ctx),
            gated = listOf(
                GatedCapability.TOR,
                GatedCapability.I2P,
                GatedCapability.DNSCRYPT,
            ).filterNot { it.available },
        )

        val recent = DnsEventLog.recent()
        val cutoff = System.currentTimeMillis() - 60_000L
        val lastMinute = recent.filter { it.timestampMillis >= cutoff }
        val logs = LogsCard(
            queries = DnsEventLog.totalQueries(),
            blocked = DnsEventLog.totalBlocked(),
            perMinute = lastMinute.size,
            blockedPerMinute = lastMinute.count { it.blocked },
        )

        val apps = readApps(ctx, effective.size)

        val alerts = HealthCheck.evaluate(
            HealthCheck.Input(
                enginePhase = engine.phase,
                engineDetail = engine.detail,
                mode = mode,
                firewallTierAvailable = chainBackend.isAvailable(),
                tailnetTierAvailable = Mesh.compiledIn,
                otherVpnActive = otherVpnActive(ctx),
                paused = Pause.isPaused(),
                pauseRemainingMs = Pause.remainingMs(),
                lockdown = Lockdown.isEnabled(ctx),
                userCaCount = MitmGuard.scan().userCaCount,
                selfBlockRules = selfBlockRules(ctx, denied, blackholed),
                refusedDenials = (denied.size - effective.size).coerceAtLeast(0),
                filterEnabled = filterOn,
                blocklistDomains = domains,
                leak = leak.verdict,
                childLockEngaged = ChildLock.isEngaged(ctx),
            ),
        )

        return Snapshot(
            mode = mode,
            phase = engine.phase,
            engineDetail = engine.detail,
            enforcement = selection,
            probes = probes,
            tunnel = tunnel,
            dns = dns,
            firewall = firewall,
            proxy = proxy,
            logs = logs,
            apps = apps,
            alerts = alerts,
            killSwitch = KillSwitch.current(),
            childLockConfigured = ChildLock.isConfigured(ctx),
            childLockEngaged = ChildLock.isEngaged(ctx),
        )
    }

    /**
     * Total / with-internet / blocked, in ONE package-manager pass.
     *
     * `AppPolicy.installed` builds labels and sorts, which is the Wardens screen's job and far
     * too much work for a home-screen counter that refreshes on every engine event.
     */
    private fun readApps(ctx: Context, blocked: Int): AppsCard = runCatching {
        val pkgs = ctx.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        var withInternet = 0
        for (p in pkgs) {
            if (p.requestedPermissions?.contains(android.Manifest.permission.INTERNET) == true) {
                withInternet++
            }
        }
        AppsCard(total = pkgs.size, withInternet = withInternet, blocked = blocked)
    }.getOrDefault(AppsCard(0, 0, blocked))

    /**
     * Rules that would cut Godwall off from the network — the donors' "self-block" warning.
     *
     * `UidExemptions` already refuses to apply one, but a rule can be *stored* (imported, or set
     * before an app declared a VPN service), and a stored rule the user believes is in force is
     * exactly the confusion the banner is for.
     */
    private fun selfBlockRules(
        ctx: Context,
        denied: Set<String>,
        blackholed: Set<String>,
    ): Int {
        val self = ctx.packageName
        var n = 0
        if (self in denied) n++
        if (self in blackholed) n++
        return n
    }

    /**
     * True when some network currently in play is a VPN while Godwall is not the one holding it.
     *
     * Deliberately transport-based rather than package-based: Godwall must not enumerate, name or
     * query the apps it replaces, so it asks the platform what is happening instead of asking
     * which app is doing it.
     */
    private fun otherVpnActive(ctx: Context): Boolean = runCatching {
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return false
        // The active network is what apps actually route over, so a VPN transport here means a
        // tunnel is carrying this device's traffic. The caller only treats that as a conflict
        // while Godwall is NOT up, which is when the tunnel can only be someone else's.
        cm.getNetworkCapabilities(cm.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }.getOrDefault(false)
}
