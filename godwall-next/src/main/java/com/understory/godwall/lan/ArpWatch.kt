package com.understory.godwall.lan

import android.content.Context
import com.understory.godwall.privilege.Privilege
import com.understory.security.Diagnostics

/**
 * ARP anomaly / spoof detection, read from `/proc/net/arp`.
 *
 * ## Why this needs the privileged shell, and why that is honest gating rather than a workaround
 *
 * The ARP cache is the map from LAN IP to hardware (MAC) address. ARP spoofing — the classic
 * on-path attack on a LAN — shows up in that map as the gateway's IP suddenly resolving to the
 * attacker's MAC, or one MAC claiming many IPs. The map lives at `/proc/net/arp`.
 *
 * Since Android 10 an app cannot read `/proc/net/arp` from its own uid: the `proc_net` SELinux
 * domain is closed to app domains as part of the MAC-randomisation privacy hardening, and the file
 * reads back empty or permission-denied. Reporting that empty read as "no anomalies" would be the
 * precise failure this campaign exists to remove — a clean-looking screen that inspected nothing.
 *
 * So the read goes through Yojimbo's privileged shell, which runs at uid 2000 and *can* read
 * `/proc/net/arp`. This is a read, not a netfilter write, so it sits at the low end of the
 * privileged tier — but it still needs the shell, and when no shell is attached the capability
 * reports absent (disabled control + the sentence in [LanDefence]) instead of showing a stale or
 * empty table as clean. The classification itself ([classify]) is pure and testable; only the read
 * is privileged.
 */
object ArpWatch {

    private const val TAG = "godwall.lan.ArpWatch"

    /** `/proc/net/arp` flag value for a complete (resolved) entry; 0x0 is an incomplete probe. */
    private const val FLAG_COMPLETE = "0x2"

    private const val EMPTY_MAC = "00:00:00:00:00:00"

    /** A single resolved ARP entry — one LAN IP bound to one MAC on one interface. */
    data class ArpEntry(val ip: String, val mac: String, val device: String)

    enum class Verdict {
        /** Watch is off. Nothing is being checked. */
        DISABLED,

        /** No privileged shell, so the table could not be read. Never reported as clean. */
        NO_PRIVILEGE,

        /** The table read back empty — no resolved neighbours yet. Not an anomaly, not a pass. */
        EMPTY,

        /** Entries present, no anomaly found. */
        CLEAN,

        /** At least one anomaly — see [Result.findings]. */
        SUSPECT,
    }

    enum class Finding {
        /** The gateway IP resolves to a MAC that also answers for other IPs — on-path candidate. */
        GATEWAY_MAC_SHARED,

        /** The gateway's MAC changed from the learned baseline for this LAN. */
        GATEWAY_MAC_CHANGED,

        /** One MAC claims an implausible number of distinct IPs — ARP-flood / spoofer. */
        MAC_CLAIMS_MANY_IPS,
    }

    data class Result(
        val verdict: Verdict,
        val findings: List<Finding> = emptyList(),
        val entryCount: Int = 0,
        /** The MAC the gateway currently resolves to, for the baseline "trust this" action. */
        val gatewayMac: String? = null,
        /** The IPs implicated in [Finding.MAC_CLAIMS_MANY_IPS] / shared-MAC findings, for detail. */
        val implicatedIps: List<String> = emptyList(),
    )

    /**
     * How many distinct IPs one MAC may legitimately answer for before it is called a flood. A
     * router doing NAT for the LAN is one MAC for one IP; a MAC bound to several IPs is either a
     * misconfiguration or a spoofer, and either is worth surfacing. Kept generous to avoid crying
     * wolf at the odd multi-homed host.
     */
    private const val MAC_IP_FANOUT_LIMIT = 3

    /**
     * The rule, pure so every branch is testable without a device or a privileged shell.
     *
     * @param watching whether the watch is enabled.
     * @param hasShell whether a privileged shell was available to read the table.
     * @param entries the resolved ARP entries (already parsed and filtered).
     * @param gatewayIp the current gateway IP (the anchor for spoof checks), or null.
     * @param learnedGatewayMac the MAC previously trusted for [gatewayIp], or null.
     */
    fun classify(
        watching: Boolean,
        hasShell: Boolean,
        entries: List<ArpEntry>,
        gatewayIp: String?,
        learnedGatewayMac: String?,
    ): Result {
        if (!watching) return Result(Verdict.DISABLED)
        if (!hasShell) return Result(Verdict.NO_PRIVILEGE)
        if (entries.isEmpty()) return Result(Verdict.EMPTY)

        val findings = ArrayList<Finding>(2)
        val implicated = LinkedHashSet<String>()

        // MAC -> the set of IPs it answers for. A spoofer shows up as one MAC over many IPs.
        val ipsByMac = HashMap<String, MutableSet<String>>()
        for (e in entries) {
            ipsByMac.getOrPut(e.mac) { LinkedHashSet() }.add(e.ip)
        }
        ipsByMac.forEach { (mac, ips) ->
            if (ips.size > MAC_IP_FANOUT_LIMIT) {
                findings += Finding.MAC_CLAIMS_MANY_IPS
                implicated += ips
                Diagnostics.warn(TAG, "MAC $mac answers for ${ips.size} IPs")
            }
        }

        val gatewayMac = gatewayIp?.let { gw -> entries.firstOrNull { it.ip == gw }?.mac }
        if (gatewayIp != null && gatewayMac != null) {
            val alsoOnGatewayMac = ipsByMac[gatewayMac].orEmpty().filter { it != gatewayIp }
            if (alsoOnGatewayMac.isNotEmpty()) {
                findings += Finding.GATEWAY_MAC_SHARED
                implicated += alsoOnGatewayMac
                Diagnostics.warn(TAG, "gateway MAC $gatewayMac also on ${alsoOnGatewayMac.joinToString()}")
            }
            if (learnedGatewayMac != null && !learnedGatewayMac.equals(gatewayMac, ignoreCase = true)) {
                findings += Finding.GATEWAY_MAC_CHANGED
                Diagnostics.warn(TAG, "gateway MAC changed: baseline $learnedGatewayMac now $gatewayMac")
            }
        }

        // Distinct, worst-first (spoof of the gateway ranks above a flood).
        val ordered = listOf(
            Finding.GATEWAY_MAC_CHANGED,
            Finding.GATEWAY_MAC_SHARED,
            Finding.MAC_CLAIMS_MANY_IPS,
        ).filter { it in findings }

        return Result(
            verdict = if (ordered.isEmpty()) Verdict.CLEAN else Verdict.SUSPECT,
            findings = ordered,
            entryCount = entries.size,
            gatewayMac = gatewayMac,
            implicatedIps = implicated.toList(),
        )
    }

    /**
     * Parse `/proc/net/arp`. Pure, so the format is pinned by a test rather than by hoping the
     * shell's `cat` produced what was expected.
     *
     * The file's shape (a fixed header line, then whitespace-separated columns):
     * ```
     * IP address       HW type   Flags   HW address          Mask   Device
     * 192.168.1.1      0x1       0x2     aa:bb:cc:dd:ee:ff    *      wlan0
     * ```
     * Only complete entries ([FLAG_COMPLETE]) with a non-zero MAC are kept — an incomplete entry is
     * an in-flight probe, not a resolved neighbour, and treating it as one would invent anomalies.
     */
    fun parse(raw: String): List<ArpEntry> {
        val out = ArrayList<ArpEntry>()
        raw.lineSequence().drop(1).forEach { line ->
            val cols = line.trim().split(Regex("\\s+"))
            if (cols.size < 6) return@forEach
            val ip = cols[0]
            val flags = cols[2]
            val mac = cols[3].lowercase()
            val device = cols[5]
            if (flags != FLAG_COMPLETE) return@forEach
            if (mac == EMPTY_MAC || mac.isBlank()) return@forEach
            out += ArpEntry(ip = ip, mac = mac, device = device)
        }
        return out
    }

    /**
     * Read `/proc/net/arp` through the privileged shell and classify it. Blocking (a binder round
     * trip to Yojimbo); call off the main thread. When no shell is attached this returns
     * [Verdict.NO_PRIVILEGE] without inventing a table.
     *
     * @param gatewayIp the current gateway, supplied by the caller from the DHCP/link read so the
     *   two stay consistent — the ARP check anchors on the same gateway the DHCP watch does.
     */
    fun scan(ctx: Context, gatewayIp: String?): Result {
        if (!LanSettings.arpWatchEnabled(ctx)) return Result(Verdict.DISABLED)
        if (!Privilege.isAvailable()) return Result(Verdict.NO_PRIVILEGE)
        val raw = readArpTable() ?: return Result(Verdict.NO_PRIVILEGE)
        val entries = parse(raw)
        val learned = gatewayIp?.let { LanSettings.learnedGatewayMac(ctx, it) }
        return classify(
            watching = true,
            hasShell = true,
            entries = entries,
            gatewayIp = gatewayIp,
            learnedGatewayMac = learned,
        )
    }

    /**
     * `cat /proc/net/arp` through Yojimbo's shell. Returns null on any failure — a shell that is
     * present but could not read the file is reported as [Verdict.NO_PRIVILEGE], never as an empty
     * table that would read as "clean". The file is not in Godwall's prefix, so this goes straight
     * to [Privilege.exec] rather than through the subsystem installer.
     */
    private fun readArpTable(): String? {
        val r = Privilege.exec(listOf("sh", "-c", "cat /proc/net/arp"), timeoutMs = 10_000L)
        if (!r.ok) {
            Diagnostics.warn(TAG, "arp table read failed: ${r.summary()}")
            return null
        }
        return r.out
    }
}
