package com.understory.godwall.lan

import android.content.Context
import com.understory.godwall.privilege.Privilege

/**
 * The one thing the LAN screen reads: a single blocking pass that gathers network posture, the
 * rogue-DHCP watch, the ARP watch and the deception layer's live state into one snapshot, and the
 * registry of the LAN capabilities this build cannot back — each with the exact sentence the UI
 * shows next to its disabled control.
 *
 * ## Why the gated capabilities are enumerated here rather than inferred at the call site
 *
 * `docs/DONOR-ASSETS.md`: a capability whose payload or privilege is absent reports absent, with a
 * visible sentence naming what is missing — never a control that quietly no-ops. Two of LAN
 * defence's sub-capabilities are structurally out of reach in this tier, and one is reachable only
 * when Yojimbo has attached a shell. Naming them in one place ([GatedCapability]) keeps the screen
 * from having to re-derive "can I do this?" per control, which is exactly where a control that
 * lies creeps back in.
 */
object LanDefence {

    /**
     * The complete LAN state, read once. Everything here is an observation; nothing is derived from
     * what the user last tapped.
     */
    data class Snapshot(
        val posture: NetworkPosture.Posture,
        val dhcp: RogueDhcp.Result,
        val arp: ArpWatch.Result,
        val deception: Deception.Status,
        /** The gateway of the active lease, so the UI can offer per-LAN "trust" actions. */
        val gateway: String?,
    )

    /**
     * A LAN capability that cannot run in this build, and why.
     *
     * @param available whether the capability can actually run. All entries here are false: the two
     *   structural ones need a tier this package does not have, and the ARP-scan privilege is a
     *   runtime fact, tracked separately by [arpReachable] rather than as a constant.
     * @param reason the exact sentence shown to the user beside the disabled control.
     */
    enum class GatedCapability(val available: Boolean, val reason: String) {

        /**
         * Broadcasting a DHCP DISCOVER to enumerate every responding server, rather than reading
         * only the lease the system accepted. Needs a raw broadcast socket.
         */
        ACTIVE_DHCP_SOLICIT(
            available = false,
            reason = "Actively soliciting every DHCP server on the network means broadcasting a " +
                "DHCP DISCOVER from a raw socket, which needs the CAP_NET_RAW capability. Godwall " +
                "runs at uid 2000 through Yojimbo, and uid 2000 does not hold it — so this build " +
                "watches the lease the system already accepted instead of probing for competing " +
                "servers.",
        ),

        /**
         * Presenting decoys on every inbound port (including 22/80/443) by redirecting all traffic
         * to the in-process listener with a netfilter rule. Needs to write the device's tables.
         */
        HOST_WIDE_DECEPTION(
            available = false,
            reason = "Presenting decoys on every port, including privileged ports like 22, 80 and " +
                "443, means redirecting all inbound traffic to the decoy with a netfilter rule " +
                "(iptables/nftables REDIRECT). Writing the device's firewall tables is the " +
                "privileged host tier, not socket space, so this build answers only on the high " +
                "ports Godwall itself binds.",
        ),

        /**
         * Reading the Wi-Fi link's cipher (open vs encrypted) and naming the SSID. Needs the
         * location permission, which this feature deliberately does not take.
         */
        WIFI_LINK_INSPECTION(
            available = false,
            reason = "Naming the Wi-Fi network and grading its encryption needs the fine-location " +
                "permission on Android 10 and later. Godwall's LAN defence does not take location " +
                "just to label a network, so it reports the platform's captive-portal and " +
                "validation signals instead.",
        ),
    }

    /**
     * Whether the ARP scan can run right now. Unlike the [GatedCapability] entries this is a
     * runtime fact — it flips to true the moment Yojimbo attaches a shell — so it is a function,
     * not a constant. The sentence for the disabled case is [arpAbsentReason].
     */
    fun arpReachable(): Boolean = Privilege.isAvailable()

    val arpAbsentReason: String =
        "Reading the ARP table means reading /proc/net/arp, which Android closes to an app's own " +
            "uid since Android 10. Godwall reads it through Yojimbo's privileged shell (uid 2000), " +
            "which can. No privileged shell is attached, so the ARP scan cannot run — it reports " +
            "absent rather than showing an empty table as clean."

    /**
     * Read everything. Blocking (platform reads plus, for ARP, a binder round trip to Yojimbo);
     * call on [com.understory.security.ui.Bg.io].
     *
     * The gateway is read once from the DHCP watch and threaded into the ARP scan so the two anchor
     * on the same network — a rogue-DHCP verdict and an ARP verdict that disagreed about which
     * gateway they were judging would be worse than either alone.
     */
    fun read(ctx: Context): Snapshot {
        val posture = NetworkPosture.read(ctx)
        val dhcp = RogueDhcp.check(ctx)
        val arp = ArpWatch.scan(ctx, dhcp.gateway)
        val deception = Deception.status()
        return Snapshot(
            posture = posture,
            dhcp = dhcp,
            arp = arp,
            deception = deception,
            gateway = dhcp.gateway,
        )
    }
}
