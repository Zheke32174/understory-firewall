package com.understory.godwall.subsystem.tor

import android.content.Context
import com.understory.godwall.subsystem.PrefixInstaller
import com.understory.godwall.subsystem.ServicePhase
import com.understory.godwall.subsystem.ServiceStatus
import com.understory.godwall.subsystem.Supervisor
import com.understory.security.Diagnostics

/**
 * The orchestration for the Anonymity subsystem: it registers the tor and i2pd specs
 * with the [Supervisor], seeds their binaries into the prefix, regenerates their
 * configs from the typed settings, drives start/stop/restart through the Supervisor,
 * and exposes "New Tor identity" and the honest routing-enforcement state.
 *
 * ## What it does NOT own
 *
 * The lifecycle — is it alive, did its port bind, restart-on-death — is the
 * Supervisor's, and this controller never second-guesses it. The privilege path is
 * Yojimbo's, reached only through [PrefixInstaller]. This file is the seam that wires
 * this WP's engine to those foundations; it adds no lifecycle logic of its own.
 *
 * All methods are blocking (privileged binder round trips, socket dials, SharedPreferences
 * reads) and must be called off the main thread — the same contract the Supervisor and
 * PrefixInstaller carry. Callers use `com.understory.security.ui.Bg.io`.
 */
object AnonymityController {

    private const val TAG = "godwall.subsystem.tor.AnonymityController"

    /**
     * Register both daemons with the Supervisor using the current settings, so it can
     * observe them and so a start has a spec to launch. Idempotent — re-registering
     * replaces the spec, which is how a port change in the settings reaches the probe.
     */
    fun register(context: Context) {
        Supervisor.register(AnonymitySpecs.torSpec(TorDaemonStore.snapshot(context)))
        Supervisor.register(AnonymitySpecs.i2pdSpec(I2pdStore.snapshot(context)))
    }

    // ---- Lifecycle: Tor ----------------------------------------------------------

    /**
     * Seed the tor binary into the prefix (if bundled) and start it. Returns the
     * Supervisor's measured status: a build with no tor binary comes back
     * [com.understory.godwall.subsystem.ServicePhase.ABSENT] from the liveness sweep,
     * so this never claims a Tor that isn't there.
     */
    fun startTor(context: Context): ServiceStatus {
        Anonymity.torPresent(context) || return absent(AnonymitySpecs.TOR_ID, context)
        register(context)
        seedIfPresent(context)
        return Supervisor.start(context, AnonymitySpecs.TOR_ID)
    }

    fun stopTor(): ServiceStatus = Supervisor.stop(AnonymitySpecs.TOR_ID)

    fun restartTor(context: Context): ServiceStatus {
        Anonymity.torPresent(context) || return absent(AnonymitySpecs.TOR_ID, context)
        register(context)
        seedIfPresent(context)
        return Supervisor.restart(context, AnonymitySpecs.TOR_ID)
    }

    // ---- Lifecycle: i2pd ---------------------------------------------------------

    fun startI2pd(context: Context): ServiceStatus {
        Anonymity.i2pdPresent(context) || return absent(AnonymitySpecs.I2PD_ID, context)
        register(context)
        seedIfPresent(context)
        return Supervisor.start(context, AnonymitySpecs.I2PD_ID)
    }

    fun stopI2pd(): ServiceStatus = Supervisor.stop(AnonymitySpecs.I2PD_ID)

    fun restartI2pd(context: Context): ServiceStatus {
        Anonymity.i2pdPresent(context) || return absent(AnonymitySpecs.I2PD_ID, context)
        register(context)
        seedIfPresent(context)
        return Supervisor.restart(context, AnonymitySpecs.I2PD_ID)
    }

    /** Best-effort binary seeding; a failure is logged, and the Supervisor then reports ABSENT honestly. */
    private fun seedIfPresent(context: Context) {
        val result = Anonymity.installBinaries(context)
        if (!result.ok) Diagnostics.warn(TAG, "binary seed skipped/failed: ${result.message}")
    }

    /**
     * The status a start returns when the daemon's binary is not in this build: a clean
     * [ServicePhase.ABSENT] carrying the exact missing-payload sentence, rather than
     * launching a nonexistent binary and reporting a confusing FAILED.
     */
    private fun absent(id: String, context: Context): ServiceStatus =
        ServiceStatus(id = id, phase = ServicePhase.ABSENT, detail = Anonymity.explain(context))

    // ---- Config regeneration -----------------------------------------------------

    /**
     * Render `torrc` from the current [TorDaemonSettings] plus the active bridge set
     * and write it into the prefix (overwriting the previous generated/seeded file).
     * Call this when a Tor preference changes — it also re-registers the spec so the
     * health probes follow any changed port. Blocking.
     *
     * Bridge lines are included only for a transport whose PT binary is actually
     * present (see [TorBridges]); a selected-but-absent transport yields no bridge
     * lines, so tor is never told to exec a transport that is not in this build.
     */
    fun regenerateTorrc(context: Context): PrefixInstaller.Report {
        val settings = TorDaemonStore.snapshot(context)
        val policy = TorRoutingStore.snapshot(context)
        val bridgeLines = TorBridges.renderTorrcLines(
            transport = policy.bridgeTransport,
            ownLines = policy.ownBridgeLines,
            presence = Anonymity.bridgePresence(context),
            prefix = PrefixInstaller.PREFIX,
        )
        val torrc = settings.renderTorrc(bridgeLines)
        val report = PrefixInstaller.writeText(AnonymitySpecs.TORRC_DEST, torrc)
        if (report.ok) {
            Supervisor.register(AnonymitySpecs.torSpec(settings))
            Diagnostics.log(TAG, "torrc regenerated (${torrc.length} bytes, bridges=${policy.bridgeTransport})")
        }
        return report
    }

    /** Render `i2pd.conf` from the current [I2pdSettings] and write it into the prefix. Blocking. */
    fun regenerateI2pdConf(context: Context): PrefixInstaller.Report {
        val settings = I2pdStore.snapshot(context)
        val conf = settings.renderI2pdConf()
        val report = PrefixInstaller.writeText(AnonymitySpecs.I2PD_CONF_DEST, conf)
        if (report.ok) {
            Supervisor.register(AnonymitySpecs.i2pdSpec(settings))
            Diagnostics.log(TAG, "i2pd.conf regenerated (${conf.length} bytes)")
        }
        return report
    }

    // ---- New Tor identity --------------------------------------------------------

    /** "New Tor identity" — a NEWNYM on tor's control port. Honest failure when tor is down. Blocking. */
    fun newIdentity(context: Context): TorControl.Result = TorControl.newIdentity(context)

    // ---- Honest routing-enforcement state ----------------------------------------

    /**
     * Whether the [TorRoutingPolicy] is actually carried out or merely stored. The
     * per-app / per-site selection needs a FULL-TRAFFIC tun datapath to steer flows
     * into tor's ports, and Godwall's tun captures DNS only today (see
     * core/GodwallVpnService.kt); firestack's tun2socks data plane is built but not
     * wired (docs/DONOR-ASSETS.md). So this reports STORED_NO_DATAPATH until that
     * lands, rather than letting a routing toggle imply traffic it cannot move.
     */
    fun routingEnforcement(context: Context): TorRoutingPolicy.Enforcement {
        val policy = TorRoutingStore.snapshot(context)
        val torRunning = Supervisor.status(AnonymitySpecs.TOR_ID).healthy
        return policy.enforcement(torRunning = torRunning, datapathPresent = fullTrafficDatapathPresent())
    }

    /**
     * True only when a full-traffic tun2socks datapath is wired to carry app/site
     * traffic into Tor. It is not in this build: the tun is DNS-only and firestack is
     * not linked. A single, honest source for the fact the routing surface gates on;
     * flip it here — not in a dozen screens — when the datapath lands.
     */
    fun fullTrafficDatapathPresent(): Boolean = false
}
