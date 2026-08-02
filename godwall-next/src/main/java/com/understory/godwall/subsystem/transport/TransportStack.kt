package com.understory.godwall.subsystem.transport

import android.content.Context
import com.understory.godwall.chain.EndpointChain
import com.understory.godwall.chain.ProxyHop
import com.understory.godwall.subsystem.PrefixInstaller
import com.understory.godwall.subsystem.ServicePhase
import com.understory.godwall.subsystem.ServiceStatus
import com.understory.godwall.subsystem.Supervisor
import com.understory.security.Diagnostics

/**
 * The transport stack's front door: it registers its daemons with the [Supervisor], drives their
 * lifecycle, resolves the honest capability report a surface renders, and — the seam that makes
 * these backends "real hop types rather than a parallel mechanism" — materialises a running/present
 * transport as a [ProxyHop.Socks5] for the existing egress chain.
 *
 * ## What it is, and what it deliberately is not
 *
 * It is a thin facade, exactly like WP-3's DnsStack. All lifecycle, liveness and health logic lives
 * once in the [Supervisor] (WP-2); duplicating any of it here is how a second, disagreeing opinion
 * about "is the transport up?" would creep in. So this object only: (a) makes the specs known,
 * (b) forwards start/stop, (c) maps each service's already-honest [ServiceStatus] onto the transport
 * capabilities, and (d) exposes the chain-hop bridge. It holds no state of its own beyond a
 * once-only registration latch.
 *
 * ## Why the chain bridge is not a new hop type
 *
 * The task says extend the chain so these become real hop types. It does that by REUSE, not by a new
 * mechanism: a transport hop is a plain [ProxyHop.Socks5] pointing at the daemon's loopback inbound,
 * carried by the same [com.understory.godwall.chain.ChainDialer] that already dials SOCKS5 and HTTP
 * CONNECT hops. So this package touches none of the chain sources — it feeds them. A hop is offered
 * only when its backing daemon's binary is actually present ([backingPresent]); offering a hop to an
 * ABSENT daemon would be the dead control this campaign removes. If the daemon is present but not
 * running when the hop is used, the ChainDialer fails closed and reports it — it never bypasses.
 *
 * ## Why every entry point is blocking
 *
 * Reading the prefix means talking to Yojimbo's privileged shell, which is a binder round trip. Every
 * method here that observes or acts is therefore blocking and must be called off the main thread
 * (`com.understory.security.ui.Bg.io`), exactly like the Supervisor it delegates to.
 */
internal object TransportStack {

    private const val TAG = "godwall.subsystem.transport.TransportStack"

    @Volatile
    private var registered = false

    /**
     * Register both daemon specs with the Supervisor. Idempotent and cheap — safe to call on every
     * entry point. Registration needs no privilege and no prefix; it only makes the specs known so
     * their status can be observed and they can be started later.
     */
    fun ensureRegistered() {
        if (registered) return
        synchronized(this) {
            if (registered) return
            var ok = true
            for (spec in TransportServices.all) ok = Supervisor.register(spec) && ok
            if (ok) {
                registered = true
                Diagnostics.log(TAG, "registered ${TransportServices.all.size} transport services")
            } else {
                // A spec that fails validation is a programming error in this package, not a runtime
                // condition; leave the latch unset so a fixed build re-attempts rather than caching a
                // half-registered state.
                Diagnostics.error(TAG, "one or more transport specs were refused by the Supervisor")
            }
        }
    }

    // ---- Lifecycle ---------------------------------------------------------------------

    /** Start every transport daemon. Blocking. Returns the statuses in [TransportServices.all] order. */
    fun startAll(context: Context): List<ServiceStatus> {
        ensureRegistered()
        return TransportServices.all.map { Supervisor.start(context, it.id) }
    }

    /** Stop every transport daemon. Blocking. */
    fun stopAll(): List<ServiceStatus> {
        ensureRegistered()
        return TransportServices.all.reversed().map { Supervisor.stop(it.id) }
    }

    /** Start one named transport service. Blocking. */
    fun start(context: Context, serviceId: String): ServiceStatus {
        ensureRegistered()
        require(ownsService(serviceId)) { "TransportStack does not own service '$serviceId'" }
        return Supervisor.start(context, serviceId)
    }

    /** Stop one named transport service. Blocking. */
    fun stop(serviceId: String): ServiceStatus {
        ensureRegistered()
        require(ownsService(serviceId)) { "TransportStack does not own service '$serviceId'" }
        return Supervisor.stop(serviceId)
    }

    /** Restart one named transport service. Blocking. */
    fun restart(context: Context, serviceId: String): ServiceStatus {
        ensureRegistered()
        require(ownsService(serviceId)) { "TransportStack does not own service '$serviceId'" }
        return Supervisor.restart(context, serviceId)
    }

    fun ownsService(serviceId: String): Boolean = TransportServices.all.any { it.id == serviceId }

    // ---- Reporting ---------------------------------------------------------------------

    /**
     * Observe the world and build the honest capability report. Blocking.
     *
     * Re-observes through the Supervisor so the report is a fresh measurement rather than a cached
     * intention — the same observation a watchdog tick performs, which only ever acts on services the
     * user already asked to run, so reading here advances no state the user did not request. Callers
     * that keep a screen live should also run [startWatchdog] instead of polling this in a tight loop.
     */
    fun report(context: Context): TransportReport {
        ensureRegistered()
        val substrate = Supervisor.substrate(context)
        val observed = Supervisor.observe(context)
        val services = TransportServices.all.map { spec ->
            observed[spec.id] ?: Supervisor.status(spec.id)
        }
        val statusById = services.associateBy { it.id }
        val capabilities = TransportCapabilities.all.map { resolve(context, it, statusById) }
        val hops = TransportServices.all.mapNotNull { spec ->
            val port = TransportServices.inboundPort(spec.id) ?: return@mapNotNull null
            val status = statusById[spec.id] ?: return@mapNotNull null
            if (!backingPresent(status.phase)) return@mapNotNull null
            TransportChainHop(
                serviceId = spec.id,
                label = spec.label,
                port = port,
                live = status.phase == ServicePhase.RUNNING,
            )
        }
        return TransportReport(
            substrate = substrate,
            substrateExplanation = Supervisor.explain(context),
            services = services,
            capabilities = capabilities,
            chainHops = hops,
        )
    }

    /** Just the capability list, for a surface that already has the substrate context. Blocking. */
    fun capabilities(context: Context): List<TransportCapabilityState> = report(context).capabilities

    /**
     * Resolve one capability against the observed service statuses.
     *
     * A service-backed capability's status IS its daemon's status, and its detail IS the Supervisor's
     * own sentence for that phase — that sentence already names the ABSENT binary, the failed probe,
     * or the missing shell precisely, so there is nothing to add and nothing to soften. A gated
     * capability is always [TransportCapabilityStatus.GATED] with its fixed sentence.
     */
    private fun resolve(
        context: Context,
        capability: TransportCapability,
        statusById: Map<String, ServiceStatus>,
    ): TransportCapabilityState = when (val backing = capability.backing) {
        is TransportBacking.Service -> {
            val serviceStatus = statusById[backing.serviceId]
                ?: Supervisor.status(backing.serviceId)
            TransportCapabilityState(
                capability = capability,
                status = statusFor(serviceStatus.phase),
                detail = serviceStatus.detail.ifBlank { context.getString(capability.reachRes) },
            )
        }

        is TransportBacking.Gated -> TransportCapabilityState(
            capability = capability,
            status = TransportCapabilityStatus.GATED,
            detail = context.getString(backing.sentenceRes),
        )
    }

    /**
     * Map a supervised [ServicePhase] onto the coarse capability status. STARTING and the various
     * stopped/exited phases all collapse to READY because to the surface they mean the same thing —
     * the backend exists, so the control is enabled; the exact phase is carried in the detail
     * sentence. ABSENT and UNKNOWN stay distinct because they DISABLE the control, and for opposite
     * reasons the user must be able to tell apart.
     */
    private fun statusFor(phase: ServicePhase): TransportCapabilityStatus = when (phase) {
        ServicePhase.RUNNING -> TransportCapabilityStatus.LIVE
        ServicePhase.UNHEALTHY -> TransportCapabilityStatus.DEGRADED
        ServicePhase.ABSENT -> TransportCapabilityStatus.ABSENT
        ServicePhase.UNKNOWN -> TransportCapabilityStatus.UNKNOWN
        ServicePhase.STARTING,
        ServicePhase.STOPPED,
        ServicePhase.EXITED,
        ServicePhase.FAILED,
        ServicePhase.GAVE_UP,
        -> TransportCapabilityStatus.READY
    }

    /** A daemon's binary is present unless the Supervisor could not find it or could not see. */
    private fun backingPresent(phase: ServicePhase): Boolean =
        phase != ServicePhase.ABSENT && phase != ServicePhase.UNKNOWN

    // ---- Chain bridge ------------------------------------------------------------------

    /**
     * A fresh [ProxyHop.Socks5] for a transport service, to add to the [EndpointChain], or null when
     * this build does not own that service or its backing daemon's binary is absent. Blocking — it
     * observes the Supervisor to decide presence, so a hop is never handed back for a daemon that
     * cannot exist here.
     *
     * The hop targets 127.0.0.1:<inbound>. If the daemon is present but stopped when the chain is
     * dialled, ChainDialer's connect to that port fails and the chain reports Unavailable — it fails
     * closed, never falling through to a direct connection.
     */
    fun chainHop(context: Context, serviceId: String): ProxyHop.Socks5? {
        if (!ownsService(serviceId)) return null
        val port = TransportServices.inboundPort(serviceId) ?: return null
        ensureRegistered()
        val status = Supervisor.observe(context)[serviceId] ?: Supervisor.status(serviceId)
        if (!backingPresent(status.phase)) return null
        return ProxyHop.Socks5(
            id = EndpointChain.newId(),
            host = "127.0.0.1",
            port = port,
        )
    }

    // ---- Watchdog passthrough ----------------------------------------------------------

    /** Begin periodic re-observation of the transport services (and everything else registered). */
    fun startWatchdog(context: Context) {
        ensureRegistered()
        Supervisor.startWatchdog(context)
    }

    /** Stop periodic re-observation. */
    fun stopWatchdog() = Supervisor.stopWatchdog()

    /**
     * The last lines a transport daemon wrote, or null when the prefix is unreadable (no shell). Used
     * by a surface's "show log" affordance. Blocking.
     */
    fun logTail(serviceId: String, lines: Int = 100): List<String>? {
        require(ownsService(serviceId)) { "TransportStack does not own service '$serviceId'" }
        return Supervisor.logTail(serviceId, lines)
    }
}

/**
 * A transport daemon offered as an egress-chain hop. Plain data the surface turns into a
 * [ProxyHop.Socks5] via [TransportStack.chainHop]; it is only ever produced for a daemon whose binary
 * is present, so a surface can list it as a real "add hop" choice.
 *
 * @param serviceId the backing daemon's id.
 * @param label the daemon's human label.
 * @param port the loopback SOCKS inbound the hop dials.
 * @param live true when the daemon is confirmed running now — a hop added while true carries traffic
 *   immediately; a hop added while false is real but fails closed until the daemon is started.
 */
internal data class TransportChainHop(
    val serviceId: String,
    val label: String,
    val port: Int,
    val live: Boolean,
)

/**
 * The whole transport surface as data. Nothing here is derived from what the user last tapped — every
 * field is an observation or a fixed sentence.
 *
 * @param substrate the prefix's installed state, which is why a daemon is or is not runnable.
 * @param substrateExplanation the one sentence explaining that state (from the Supervisor).
 * @param services the raw, per-daemon status the Supervisor reported.
 * @param capabilities the transport capabilities resolved against those statuses — the honest,
 *   enabled-or-disabled-with-a-reason list a surface renders.
 * @param chainHops the transports currently backable as egress-chain hops (binary present).
 */
internal data class TransportReport(
    val substrate: PrefixInstaller.State,
    val substrateExplanation: String,
    val services: List<ServiceStatus>,
    val capabilities: List<TransportCapabilityState>,
    val chainHops: List<TransportChainHop>,
)
