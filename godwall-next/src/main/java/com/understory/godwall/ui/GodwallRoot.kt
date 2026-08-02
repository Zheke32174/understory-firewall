package com.understory.godwall.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Troubleshoot
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.understory.godwall.R
import com.understory.security.DiagnosticsScreen
import com.understory.security.nav.rememberSuiteNav
import com.understory.security.ui.components.SuiteNavShell
import com.understory.security.ui.components.SuiteTab

/**
 * Godwall's destinations.
 *
 * The old app had twenty-five routes, several of which existed only to explain the app's
 * relationship to Tailscale — `TunnelPosture`, `TierOverview`, the "coexistence" surfaces. All
 * of that was downstream of deferring to an app Godwall is supposed to *be*, so it is gone
 * rather than ported. What is left is the set of things Godwall does.
 */
enum class GodwallRoute {
    /** Arm/disarm, and the truth about what is currently filtered. */
    SHIELD,

    /** Per-app blackhole and per-app bypass. */
    APPS,

    /** Encrypted upstream, filter toggle, blocklist, custom rules. */
    DNS,

    /** The multi-hop egress chain. */
    CHAIN,

    /** The tailnet node Godwall runs itself. */
    MESH,

    /** Live per-query log with app attribution. */
    LOG,

    /** Privilege state — from Yojimbo, from nowhere else. */
    PRIVILEGE,

    /** Shared suite diagnostics ring. */
    DIAGNOSTICS,
}

@Composable
fun GodwallRoot() {
    val nav = rememberSuiteNav(home = GodwallRoute.SHIELD, tag = "godwall.nav")

    val tabs = listOf(
        SuiteTab(
            route = GodwallRoute.SHIELD.name,
            label = stringResource(R.string.nav_shield),
            icon = Icons.Filled.Shield,
            contentDescription = stringResource(R.string.cd_nav_shield),
            title = stringResource(R.string.title_shield),
        ),
        SuiteTab(
            route = GodwallRoute.APPS.name,
            label = stringResource(R.string.nav_apps),
            icon = Icons.Filled.Apps,
            contentDescription = stringResource(R.string.cd_nav_apps),
            title = stringResource(R.string.title_apps),
        ),
        SuiteTab(
            route = GodwallRoute.DNS.name,
            label = stringResource(R.string.nav_dns),
            icon = Icons.Filled.Dns,
            contentDescription = stringResource(R.string.cd_nav_dns),
            title = stringResource(R.string.title_dns),
        ),
        SuiteTab(
            route = GodwallRoute.CHAIN.name,
            label = stringResource(R.string.nav_chain),
            icon = Icons.Filled.Link,
            contentDescription = stringResource(R.string.cd_nav_chain),
            title = stringResource(R.string.title_chain),
        ),
        // --- overflow ---
        SuiteTab(
            route = GodwallRoute.MESH.name,
            label = stringResource(R.string.nav_mesh),
            icon = Icons.Filled.Hub,
            contentDescription = stringResource(R.string.cd_nav_mesh),
            title = stringResource(R.string.title_mesh),
        ),
        SuiteTab(
            route = GodwallRoute.LOG.name,
            label = stringResource(R.string.nav_log),
            icon = Icons.AutoMirrored.Filled.ListAlt,
            contentDescription = stringResource(R.string.cd_nav_log),
            title = stringResource(R.string.title_log),
        ),
        SuiteTab(
            route = GodwallRoute.PRIVILEGE.name,
            label = stringResource(R.string.nav_privilege),
            icon = Icons.Filled.Security,
            contentDescription = stringResource(R.string.cd_nav_privilege),
            title = stringResource(R.string.title_privilege),
        ),
        SuiteTab(
            route = GodwallRoute.DIAGNOSTICS.name,
            label = stringResource(R.string.nav_diagnostics),
            icon = Icons.Filled.Troubleshoot,
            contentDescription = stringResource(R.string.cd_nav_diagnostics),
            title = stringResource(R.string.title_diagnostics),
        ),
    )

    SuiteNavShell(nav = nav, tabs = tabs) { current, inner ->
        when (runCatching { GodwallRoute.valueOf(current) }.getOrDefault(GodwallRoute.SHIELD)) {
            GodwallRoute.SHIELD -> ShieldScreen(
                padding = inner,
                onOpenDns = { nav.push(GodwallRoute.DNS) },
                onOpenApps = { nav.push(GodwallRoute.APPS) },
                onOpenMesh = { nav.push(GodwallRoute.MESH) },
                onOpenChain = { nav.push(GodwallRoute.CHAIN) },
                onOpenPrivilege = { nav.push(GodwallRoute.PRIVILEGE) },
            )
            GodwallRoute.APPS -> AppsScreen(padding = inner)
            GodwallRoute.DNS -> DnsScreen(padding = inner, onOpenLog = { nav.push(GodwallRoute.LOG) })
            GodwallRoute.CHAIN -> ChainScreen(padding = inner)
            GodwallRoute.MESH -> MeshScreen(padding = inner)
            GodwallRoute.LOG -> LogScreen(padding = inner)
            GodwallRoute.PRIVILEGE -> PrivilegeScreen(padding = inner)
            // The suite's shared diagnostics surface. onBack is wired to nav.back() so the
            // in-screen arrow and the system gesture stay the same action.
            GodwallRoute.DIAGNOSTICS -> DiagnosticsScreen(onBack = { nav.back() })
        }
    }
}
