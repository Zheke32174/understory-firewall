package com.understory.godwall.ward

import android.content.Context
import android.os.Build
import com.understory.godwall.chain.EndpointChain
import com.understory.godwall.privilege.Privilege

/**
 * The enforcement badge's engine: which mechanism is actually carrying out per-app denial.
 *
 * ## The donors
 *
 * De1984 and Fyrypt both pick a backend at runtime rather than assuming one. De1984 prefers
 * `iptables` when a root shell exists and falls back to the framework's `NetworkPolicyManager`
 * (`cmd netpolicy add restrict-background-blacklist <uid>`) otherwise; RethinkDNS has no
 * privileged path at all and enforces inside its own tun; InviZible drives `iptables` through a
 * bundled busybox. The badge on the home screen is that choice, made visible.
 *
 * So this object probes, in the donors' order of strength, and reports what it found. It never
 * claims a backend it did not verify: every probe either runs a real command through the Yojimbo
 * shell or checks a platform fact, and an unavailable backend carries the sentence saying why.
 *
 * ## Ordering
 *
 * [PREFERENCE_ORDER] is strongest-first. `iptables` sees packets; the netd firewall chain
 * (`cmd connectivity set-chain3-enabled`, Android 13+) denies a whole uid across every transport;
 * `cmd netpolicy` is the older, metered-network-oriented equivalent; the VPN tier is Godwall's own
 * tun, which is name-based only; the proxy tier is the egress chain, which controls the path
 * rather than the permission.
 */
enum class EnforcementBackend {
    IPTABLES,
    CONNECTIVITY_MANAGER,
    NETWORK_POLICY_MANAGER,
    VPN,
    PROXY,
}

/** One probed backend. [detail] is shown verbatim, so it is always a whole sentence. */
data class BackendProbe(
    val backend: EnforcementBackend,
    val available: Boolean,
    val detail: String,
)

/**
 * The outcome of choosing a backend.
 *
 * [manualOverridden] is true when the user pinned a backend that turned out to be unavailable —
 * the badge then shows the fallback AND says the pin could not be honoured, rather than showing
 * a pin that is not in force.
 */
data class EnforcementSelection(
    val chosen: EnforcementBackend?,
    val manual: EnforcementBackend?,
    val manualOverridden: Boolean,
)

object Enforcement {

    private const val PREF = "godwall_ward"
    private const val KEY_MANUAL = "enforcement_manual"

    /** Strongest first. Auto-select walks this and takes the first available. */
    val PREFERENCE_ORDER = listOf(
        EnforcementBackend.IPTABLES,
        EnforcementBackend.CONNECTIVITY_MANAGER,
        EnforcementBackend.NETWORK_POLICY_MANAGER,
        EnforcementBackend.VPN,
        EnforcementBackend.PROXY,
    )

    // -- selection: pure, unit-tested -------------------------------------------------------

    /**
     * Choose the backend in force.
     *
     * Pure on purpose — the probe results come in as data, so the rule can be tested without a
     * device or a privileged shell.
     */
    fun select(probes: List<BackendProbe>, manual: EnforcementBackend?): EnforcementSelection {
        val available = probes.filter { it.available }.map { it.backend }.toSet()
        if (manual != null && manual in available) {
            return EnforcementSelection(chosen = manual, manual = manual, manualOverridden = false)
        }
        val auto = PREFERENCE_ORDER.firstOrNull { it in available }
        return EnforcementSelection(
            chosen = auto,
            manual = manual,
            manualOverridden = manual != null,
        )
    }

    // -- persistence ------------------------------------------------------------------------

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    /** The pinned backend, or null for auto-select. */
    fun manual(ctx: Context): EnforcementBackend? = runCatching {
        p(ctx).getString(KEY_MANUAL, null)?.let { EnforcementBackend.valueOf(it) }
    }.getOrNull()

    fun setManual(ctx: Context, backend: EnforcementBackend?) {
        p(ctx).edit().apply {
            if (backend == null) remove(KEY_MANUAL) else putString(KEY_MANUAL, backend.name)
        }.apply()
    }

    // -- probes: blocking, privileged where the donor's was ---------------------------------

    /**
     * Probe every backend. **Blocking** — three of these run a command through the Yojimbo
     * shell, so this belongs on `Bg.io` and never on the main thread.
     */
    fun probe(ctx: Context): List<BackendProbe> = listOf(
        probeIptables(ctx),
        probeConnectivity(ctx),
        probeNetPolicy(ctx),
        probeVpn(),
        probeProxy(ctx),
    )

    /**
     * InviZible's mechanism. It is only real if a privileged shell can find the binary, so that
     * is literally what is checked — `command -v iptables` through Yojimbo.
     */
    private fun probeIptables(ctx: Context): BackendProbe {
        if (!Privilege.isAvailable()) {
            return BackendProbe(
                EnforcementBackend.IPTABLES,
                available = false,
                detail = "Needs a privileged shell. " + Privilege.explain(ctx),
            )
        }
        val r = Privilege.exec(
            listOf("sh", "-c", "command -v iptables || command -v /system/bin/iptables"),
            timeoutMs = 5_000L,
        )
        val path = r.out.trim().lineSequence().firstOrNull { it.isNotBlank() }.orEmpty()
        return if (r.ok && path.isNotEmpty()) {
            BackendProbe(EnforcementBackend.IPTABLES, true, "Found at $path, reachable through the privileged shell.")
        } else {
            BackendProbe(
                EnforcementBackend.IPTABLES,
                false,
                "The privileged shell is attached but no iptables binary is on its PATH.",
            )
        }
    }

    /**
     * The Android 13+ netd firewall chain that [com.understory.godwall.apps.NetworkChainBackend]
     * already drives. Probed by asking whether the command exists, not by enabling anything.
     */
    private fun probeConnectivity(ctx: Context): BackendProbe {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return BackendProbe(
                EnforcementBackend.CONNECTIVITY_MANAGER,
                false,
                "Needs Android 13 or newer — this device is API ${Build.VERSION.SDK_INT}.",
            )
        }
        if (!Privilege.isAvailable()) {
            return BackendProbe(
                EnforcementBackend.CONNECTIVITY_MANAGER,
                false,
                "Needs a privileged shell. " + Privilege.explain(ctx),
            )
        }
        val r = Privilege.exec(listOf("cmd", "-l"), timeoutMs = 5_000L)
        val present = r.out.lineSequence().any { it.trim() == "connectivity" }
        return if (present) {
            BackendProbe(
                EnforcementBackend.CONNECTIVITY_MANAGER,
                true,
                "cmd connectivity is reachable — denial covers Wi-Fi, mobile and any VPN, per app.",
            )
        } else {
            BackendProbe(
                EnforcementBackend.CONNECTIVITY_MANAGER,
                false,
                "The privileged shell answered but did not list a connectivity service.",
            )
        }
    }

    /** De1984's fallback: the framework's own per-uid policy, driven by `cmd netpolicy`. */
    private fun probeNetPolicy(ctx: Context): BackendProbe {
        if (!Privilege.isAvailable()) {
            return BackendProbe(
                EnforcementBackend.NETWORK_POLICY_MANAGER,
                false,
                "Needs a privileged shell. " + Privilege.explain(ctx),
            )
        }
        val r = Privilege.exec(listOf("cmd", "-l"), timeoutMs = 5_000L)
        val present = r.out.lineSequence().any { it.trim() == "netpolicy" }
        return if (present) {
            BackendProbe(
                EnforcementBackend.NETWORK_POLICY_MANAGER,
                true,
                "cmd netpolicy is reachable — per-uid restriction, metered networks first.",
            )
        } else {
            BackendProbe(
                EnforcementBackend.NETWORK_POLICY_MANAGER,
                false,
                "The privileged shell answered but did not list a netpolicy service.",
            )
        }
    }

    /** Always available: it is Godwall's own tun. Name-based only, and the sentence says so. */
    private fun probeVpn(): BackendProbe = BackendProbe(
        EnforcementBackend.VPN,
        available = true,
        detail = "Godwall's own tunnel. Denies by name, per app, with no privilege needed — " +
            "an app that already knows an address can still reach it.",
    )

    private fun probeProxy(ctx: Context): BackendProbe {
        val hops = EndpointChain.hops(ctx)
        return if (hops.isEmpty()) {
            BackendProbe(
                EnforcementBackend.PROXY,
                false,
                "No hops configured, so there is no proxy to enforce a path through.",
            )
        } else {
            BackendProbe(
                EnforcementBackend.PROXY,
                true,
                EndpointChain.describe(ctx) + " — controls the path traffic takes, not whether an app may use the network.",
            )
        }
    }
}
