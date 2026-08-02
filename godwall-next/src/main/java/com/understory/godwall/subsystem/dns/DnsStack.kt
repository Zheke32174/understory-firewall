package com.understory.godwall.subsystem.dns

import android.content.Context
import com.understory.godwall.subsystem.PrefixInstaller
import com.understory.godwall.subsystem.ServicePhase
import com.understory.godwall.subsystem.ServiceStatus
import com.understory.godwall.subsystem.Supervisor
import com.understory.security.Diagnostics

/**
 * The DNS stack's front door: it registers its two daemons with the [Supervisor], drives their
 * lifecycle, and resolves the honest capability report a surface renders.
 *
 * ## What it is, and what it deliberately is not
 *
 * It is a thin facade. All lifecycle, liveness and health logic lives once in the [Supervisor]
 * (WP-2); duplicating any of it here is how a second, disagreeing opinion about "is DNS up?"
 * would creep in. So this object only: (a) makes the specs known, (b) forwards start/stop, and
 * (c) maps each service's already-honest [ServiceStatus] onto the DNS capabilities that share
 * its fate. It holds no state of its own beyond a once-only registration latch.
 *
 * It is NOT a UI. WP-9 owns the subsystem surfaces; this returns a [DnsReport] of plain data
 * and string sentences for that surface to draw. It defines no Compose, no navigation, no theme.
 *
 * ## Why every entry point is blocking
 *
 * Reading the prefix means talking to Yojimbo's privileged shell, which is a binder round trip.
 * Every method here that observes or acts is therefore blocking and must be called off the main
 * thread (`com.understory.security.ui.Bg.io`), exactly like the Supervisor it delegates to.
 */
internal object DnsStack {

    private const val TAG = "godwall.subsystem.dns.DnsStack"

    @Volatile
    private var registered = false

    /**
     * Register both daemon specs with the Supervisor. Idempotent and cheap — safe to call on
     * every entry point. Registration needs no privilege and no prefix; it only makes the specs
     * known so their status can be observed and they can be started later.
     */
    fun ensureRegistered() {
        if (registered) return
        synchronized(this) {
            if (registered) return
            var ok = true
            for (spec in DnsServices.all) ok = Supervisor.register(spec) && ok
            if (ok) {
                registered = true
                Diagnostics.log(TAG, "registered ${DnsServices.all.size} DNS services")
            } else {
                // A spec that fails validation is a programming error in this package, not a
                // runtime condition; leave the latch unset so a fixed build re-attempts rather
                // than caching a half-registered state.
                Diagnostics.error(TAG, "one or more DNS specs were refused by the Supervisor")
            }
        }
    }

    // ---- Lifecycle ---------------------------------------------------------------------

    /**
     * Start the encrypted upstream, then the front-end that forwards to it. Blocking.
     *
     * Order matters only for the first health tick — dnsmasq forwards to dnscrypt-proxy, so
     * starting the upstream first means the front-end has somewhere to send its first query. It
     * is not a hard dependency: each is supervised independently and either can be (re)started
     * alone. Returns the pair of resulting statuses in the same order as [DnsServices.all].
     */
    fun startAll(context: Context): List<ServiceStatus> {
        ensureRegistered()
        return DnsServices.all.map { Supervisor.start(context, it.id) }
    }

    /** Stop both daemons. Blocking. */
    fun stopAll(): List<ServiceStatus> {
        ensureRegistered()
        // Front-end first, then upstream: stop taking queries before removing what answers them.
        return DnsServices.all.reversed().map { Supervisor.stop(it.id) }
    }

    /** Start one named DNS service. Blocking. Ignores ids this package does not own. */
    fun start(context: Context, serviceId: String): ServiceStatus {
        ensureRegistered()
        require(ownsService(serviceId)) { "DnsStack does not own service '$serviceId'" }
        return Supervisor.start(context, serviceId)
    }

    /** Stop one named DNS service. Blocking. */
    fun stop(serviceId: String): ServiceStatus {
        ensureRegistered()
        require(ownsService(serviceId)) { "DnsStack does not own service '$serviceId'" }
        return Supervisor.stop(serviceId)
    }

    /** Restart one named DNS service. Blocking. */
    fun restart(context: Context, serviceId: String): ServiceStatus {
        ensureRegistered()
        require(ownsService(serviceId)) { "DnsStack does not own service '$serviceId'" }
        return Supervisor.restart(context, serviceId)
    }

    fun ownsService(serviceId: String): Boolean = DnsServices.all.any { it.id == serviceId }

    // ---- Reporting ---------------------------------------------------------------------

    /**
     * Observe the world and build the honest capability report. Blocking.
     *
     * Re-observes through the Supervisor so the report is a fresh measurement rather than a
     * cached intention — the same observation a watchdog tick performs, which only ever acts on
     * services the user already asked to run, so reading here advances no state the user did not
     * request. Callers that keep a screen live should also run [startWatchdog] instead of
     * polling this in a tight loop.
     */
    fun report(context: Context): DnsReport {
        ensureRegistered()
        val substrate = Supervisor.substrate(context)
        val observed = Supervisor.observe(context)
        val services = DnsServices.all.map { spec ->
            observed[spec.id] ?: Supervisor.status(spec.id)
        }
        val statusById = services.associateBy { it.id }
        val capabilities = DnsCapabilities.all.map { resolve(context, it, statusById) }
        return DnsReport(
            substrate = substrate,
            substrateExplanation = Supervisor.explain(context),
            services = services,
            capabilities = capabilities,
        )
    }

    /** Just the capability list, for a surface that already has the substrate context. Blocking. */
    fun capabilities(context: Context): List<DnsCapabilityState> = report(context).capabilities

    /**
     * Resolve one capability against the observed service statuses.
     *
     * A service-backed capability's status IS its daemon's status, and its detail IS the
     * Supervisor's own sentence for that phase — that sentence already names the ABSENT binary,
     * the failed probe, or the missing shell precisely, so there is nothing to add and nothing
     * to soften. A gated capability is always [DnsCapabilityStatus.GATED] with its fixed sentence.
     */
    private fun resolve(
        context: Context,
        capability: DnsCapability,
        statusById: Map<String, ServiceStatus>,
    ): DnsCapabilityState = when (val backing = capability.backing) {
        is DnsBacking.Service -> {
            val serviceStatus = statusById[backing.serviceId]
                ?: Supervisor.status(backing.serviceId)
            DnsCapabilityState(
                capability = capability,
                status = statusFor(serviceStatus.phase),
                detail = serviceStatus.detail.ifBlank { context.getString(capability.reachRes) },
            )
        }

        is DnsBacking.Gated -> DnsCapabilityState(
            capability = capability,
            status = DnsCapabilityStatus.GATED,
            detail = context.getString(backing.sentenceRes),
        )
    }

    /**
     * Map a supervised [ServicePhase] onto the coarse capability status. STARTING and the
     * various stopped/exited phases all collapse to READY because to the surface they mean the
     * same thing — the backend exists, so the control is enabled; the exact phase is carried in
     * the detail sentence. ABSENT and UNKNOWN stay distinct because they DISABLE the control,
     * and for opposite reasons that the user must be able to tell apart.
     */
    private fun statusFor(phase: ServicePhase): DnsCapabilityStatus = when (phase) {
        ServicePhase.RUNNING -> DnsCapabilityStatus.LIVE
        ServicePhase.UNHEALTHY -> DnsCapabilityStatus.DEGRADED
        ServicePhase.ABSENT -> DnsCapabilityStatus.ABSENT
        ServicePhase.UNKNOWN -> DnsCapabilityStatus.UNKNOWN
        ServicePhase.STARTING,
        ServicePhase.STOPPED,
        ServicePhase.EXITED,
        ServicePhase.FAILED,
        ServicePhase.GAVE_UP,
        -> DnsCapabilityStatus.READY
    }

    // ---- Watchdog passthrough ----------------------------------------------------------

    /** Begin periodic re-observation of the DNS services (and everything else registered). */
    fun startWatchdog(context: Context) {
        ensureRegistered()
        Supervisor.startWatchdog(context)
    }

    /** Stop periodic re-observation. */
    fun stopWatchdog() = Supervisor.stopWatchdog()

    /**
     * The last lines a DNS daemon wrote, or null when the prefix is unreadable (no shell). Used
     * by a surface's "show log" affordance. Blocking.
     */
    fun logTail(serviceId: String, lines: Int = 100): List<String>? {
        require(ownsService(serviceId)) { "DnsStack does not own service '$serviceId'" }
        return Supervisor.logTail(serviceId, lines)
    }
}

/**
 * The whole DNS surface as data. Nothing here is derived from what the user last tapped — every
 * field is an observation or a fixed sentence.
 *
 * @param substrate the prefix's installed state, which is why a daemon is or is not runnable.
 * @param substrateExplanation the one sentence explaining that state (from the Supervisor).
 * @param services the raw, per-daemon status the Supervisor reported.
 * @param capabilities the DNS capabilities resolved against those statuses — the honest,
 *   enabled-or-disabled-with-a-reason list a surface renders.
 */
internal data class DnsReport(
    val substrate: PrefixInstaller.State,
    val substrateExplanation: String,
    val services: List<ServiceStatus>,
    val capabilities: List<DnsCapabilityState>,
)
