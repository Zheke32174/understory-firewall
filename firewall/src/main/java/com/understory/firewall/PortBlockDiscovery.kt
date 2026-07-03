package com.understory.firewall

import android.content.Context
import android.content.pm.PackageManager
import com.understory.security.Diagnostics
import java.io.File

/**
 * Discover which installed apps are using the user's blocked ports
 * RIGHT NOW, by scanning /proc/net/{tcp,tcp6,udp,udp6}.
 *
 * Why this exists:
 *
 *   The firewall VPN drops traffic per-app via VpnService.Builder
 *   .addAllowedApplication(pkg). Per-port blocking across ALL apps
 *   needs userspace TCP/UDP packet forwarding (parse IP+TCP/UDP
 *   headers, drop matching, forward everything else) — that's a
 *   real userspace TCP stack, multi-day work, intentionally
 *   deferred.
 *
 *   In the meantime: this scanner reads /proc/net to find which
 *   apps' UIDs are observably using a blocked port, maps each UID
 *   back to a package name via PackageManager, and feeds those
 *   packages into the existing per-app drop path. The VPN's own
 *   addAllowedApplication then drops their traffic.
 *
 *   Limitations the user should know:
 *
 *   - REACTIVE, not proactive. We catch apps that ALREADY have a
 *     connection on a blocked port. The first connect attempt may
 *     succeed; subsequent ones (after the next scan tick) get
 *     dropped because the package is now in the auto-blocklist.
 *
 *   - REMOTE port match. The block list is interpreted as
 *     "destination port the app is talking TO" — that's the
 *     `rem_address` column, not `local_address`. Blocking 6881
 *     blocks traffic *to* port 6881 (BitTorrent peer), not
 *     traffic from a local port-6881 listener.
 *
 *   - Per-UID, not per-process. Some apps share UIDs (rare but
 *     allowed via `android:sharedUserId`). All packages mapped to
 *     a flagged UID get auto-blocked.
 *
 *   - No /proc/net access on Android 10+ for non-root unless the
 *     app's UID owns the connection. We only see our OWN
 *     connections... unless the app has elevated permissions OR
 *     is system-signed. This means on stock devices the discovery
 *     finds NOTHING. We surface this honestly in the UI: if scans
 *     return zero matches but blocked-ports list is non-empty,
 *     show a banner explaining the OS-level restriction.
 *
 *   The proper long-term fix is the userspace packet forwarder.
 *   This file is the bridge until that lands.
 */
object PortBlockDiscovery {

    /** Single scan: returns the set of installed package names whose
     *  UIDs are connected to any port in [blockedPorts]. */
    fun scan(ctx: Context, blockedPorts: Set<Int>): Set<String> {
        if (blockedPorts.isEmpty()) return emptySet()
        val uids = mutableSetOf<Int>()
        for (file in PROC_NET_FILES) {
            scanFileInto(file, blockedPorts, uids)
        }
        if (uids.isEmpty()) return emptySet()

        val pm = ctx.packageManager
        val pkgs = mutableSetOf<String>()
        for (uid in uids) {
            val names = runCatching { pm.getPackagesForUid(uid) }.getOrNull() ?: continue
            for (n in names) pkgs += n
        }
        Diagnostics.log("firewall.PortBlockDiscovery",
            "scan: ports=${blockedPorts.size} uids=${uids.size} pkgs=${pkgs.size}")
        return pkgs
    }

    /** Friendly verdict for UI surfaces. Distinguishes the three
     *  states the user could be in:
     *  - NoPortsConfigured: nothing to scan for; not an issue.
     *  - Found(n): n packages caught.
     *  - NoMatches: scanned, found nothing — could be a real
     *    no-match OR the OS-level /proc visibility restriction.
     */
    sealed class Verdict {
        object NoPortsConfigured : Verdict()
        data class Found(val packages: Set<String>) : Verdict()
        object NoMatches : Verdict()
    }

    fun verdict(ctx: Context): Verdict {
        val ports = FirewallSettings.getBlockedPorts(ctx)
        if (ports.isEmpty()) return Verdict.NoPortsConfigured
        val pkgs = scan(ctx, ports)
        return if (pkgs.isEmpty()) Verdict.NoMatches else Verdict.Found(pkgs)
    }

    // ---------- /proc/net parsing ----------

    private val PROC_NET_FILES = listOf(
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    )

    private fun scanFileInto(path: String, blockedPorts: Set<Int>, out: MutableSet<Int>) {
        val f = File(path)
        if (!f.canRead()) return
        runCatching {
            f.bufferedReader().use { reader ->
                // First line is the header; skip it.
                reader.readLine()
                while (true) {
                    val line = reader.readLine() ?: break
                    parseLine(line, blockedPorts, out)
                }
            }
        }.onFailure {
            Diagnostics.error("firewall.PortBlockDiscovery",
                "scanFile $path threw: ${it.javaClass.simpleName}: ${it.message}")
        }
    }

    /**
     * /proc/net/{tcp,udp} line format (whitespace-separated):
     *
     *   sl  local_address rem_address st  tx_q:rx_q tr:tm_when retrnsmt   uid
     *
     * Indices we read (after split):
     *   [1] local_address  — "ip:port" hex
     *   [2] rem_address    — "ip:port" hex (destination)
     *   [7] uid            — decimal
     *
     * The IPv6 variant uses 32-hex-char addresses; port format is
     * identical (4 hex chars after the colon).
     */
    private fun parseLine(line: String, blockedPorts: Set<Int>, out: MutableSet<Int>) {
        val parts = line.trim().split(Regex("\\s+"))
        if (parts.size < 8) return

        val remHex = parts[2]
        val colon = remHex.indexOf(':')
        if (colon < 0 || colon + 5 > remHex.length) return
        val portHex = remHex.substring(colon + 1)
        val port = runCatching { portHex.toInt(16) }.getOrElse { return }
        if (port !in blockedPorts) return

        val uid = parts[7].toIntOrNull() ?: return
        // Skip kernel/system UIDs (root=0, system=1000, etc.) — these
        // aren't user apps; flagging them would do nothing useful and
        // could spam the auto-blocklist with system-shared UIDs.
        if (uid < 10_000) return
        out += uid
    }
}
