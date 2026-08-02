package com.understory.godwall.ward

import android.content.Context
import com.understory.godwall.chain.ChainDialer
import com.understory.godwall.chain.EndpointChain
import com.understory.godwall.core.EngineState
import com.understory.godwall.dns.BlocklistRepository
import com.understory.godwall.dns.DnsProbe
import com.understory.godwall.dns.DnsSettings
import com.understory.security.Diagnostics

/**
 * The canary run — "prove it, don't claim it".
 *
 * Everything else on the WARD screen reports configuration. A canary sends real traffic and
 * reports what came back, which is the only way to tell "encrypted DNS is configured" from
 * "encrypted DNS works". Each check below either performs an operation or is explicitly SKIPPED;
 * none of them infers a pass from a setting.
 *
 * The set is the one the donors verify at start-up, made explicit and user-runnable:
 *  - the slot (RethinkDNS refuses to claim protection without it),
 *  - the upstream (InviZible's dnscrypt "check server" action),
 *  - the filter (a domain that is on the loaded list must come back blocked),
 *  - the leak check (see [DnsLeak]),
 *  - the egress chain (dialled for real, when one is configured),
 *  - the enforcement backend (probed, not assumed).
 *
 * A canary that cannot run says SKIPPED with the reason. It never reports PASS by default.
 */
object Canary {

    private const val TAG = "godwall.ward.Canary"

    /**
     * A domain that is in the bundled seed list, so a correctly-loaded filter must block it —
     * and it is a *subdomain*, which also proves the parent-domain subtree match is working.
     */
    private const val PROBE_BLOCKED_NAME = "ads.doubleclick.net"

    enum class Check { SLOT, UPSTREAM, FILTER, LEAK, CHAIN, ENFORCEMENT }

    enum class Status { PASS, FAIL, SKIPPED }

    data class Result(val check: Check, val status: Status, val detail: String)

    /**
     * Run every check in order. **Blocking network I/O** — call on `Bg.io`.
     *
     * Ordered cheapest-first so a failure that explains the later ones shows up first in the
     * list the user reads.
     */
    fun run(ctx: Context): List<Result> {
        val out = ArrayList<Result>(Check.entries.size)
        out += slot()
        out += filter(ctx)
        out += upstream(ctx)
        out += leak(ctx)
        out += chain(ctx)
        out += enforcement(ctx)
        Diagnostics.log(TAG, "canary run: " + out.joinToString(", ") { "${it.check}=${it.status}" })
        return out
    }

    private fun slot(): Result {
        val s = EngineState.state.value
        return when (s.phase) {
            EngineState.Phase.UP -> Result(
                Check.SLOT,
                Status.PASS,
                "Godwall holds the VPN slot; the tun is established.",
            )
            EngineState.Phase.STARTING -> Result(
                Check.SLOT,
                Status.SKIPPED,
                "The engine is still starting — run this again in a moment.",
            )
            EngineState.Phase.FAILED -> Result(
                Check.SLOT,
                Status.FAIL,
                "The engine failed to start: ${s.detail}",
            )
            EngineState.Phase.DOWN -> Result(
                Check.SLOT,
                Status.FAIL,
                "Godwall is not holding the VPN slot, so nothing on this device is being filtered.",
            )
        }
    }

    /**
     * Load the list if it is not loaded, then assert a known member is blocked and a name that is
     * not on any list is not. Both halves matter: a filter that blocks everything would pass the
     * first check alone, and that is a worse failure than blocking nothing.
     */
    private fun filter(ctx: Context): Result {
        if (!BlocklistRepository.isFilterEnabled(ctx)) {
            return Result(Check.FILTER, Status.SKIPPED, "The name filter is switched off.")
        }
        runCatching {
            if (BlocklistRepository.current.size == 0) BlocklistRepository.reload(ctx)
        }.onFailure {
            return Result(Check.FILTER, Status.FAIL, "The blocklist could not be loaded: ${it.javaClass.simpleName}")
        }
        val list = BlocklistRepository.current
        if (list.size == 0) {
            return Result(Check.FILTER, Status.FAIL, "The filter is on but no domains are loaded.")
        }
        val blocksListed = list.isBlocked(PROBE_BLOCKED_NAME)
        val allowsUnlisted = !list.isBlocked("example.com")
        return when {
            blocksListed && allowsUnlisted -> Result(
                Check.FILTER,
                Status.PASS,
                "${list.size} domains loaded. $PROBE_BLOCKED_NAME is blocked by its parent domain; example.com is not.",
            )
            !blocksListed -> Result(
                Check.FILTER,
                Status.FAIL,
                "$PROBE_BLOCKED_NAME is on the loaded list but did not match — subtree matching is not working.",
            )
            else -> Result(
                Check.FILTER,
                Status.FAIL,
                "example.com is being blocked, so the filter is matching far more than the list.",
            )
        }
    }

    /** The real upstream test, through the configured transport and the configured chain. */
    private fun upstream(ctx: Context): Result {
        val r = runCatching { DnsProbe.run(ctx) }.getOrElse {
            return Result(Check.UPSTREAM, Status.FAIL, "The probe threw ${it.javaClass.simpleName}.")
        }
        return Result(Check.UPSTREAM, if (r.ok) Status.PASS else Status.FAIL, r.line)
    }

    private fun leak(ctx: Context): Result {
        val r = DnsLeak.check(ctx)
        val status = when (r.verdict) {
            DnsLeak.Verdict.OK -> Status.PASS
            DnsLeak.Verdict.LEAK -> Status.FAIL
            DnsLeak.Verdict.NOT_ARMED, DnsLeak.Verdict.UNKNOWN -> Status.SKIPPED
        }
        return Result(Check.LEAK, status, r.detail)
    }

    /**
     * Dial the chain for real, to the configured resolver's own address and port, outside the tun
     * (`service = null`) — the same thing the chain screen's test does, so the two can never
     * disagree.
     */
    private fun chain(ctx: Context): Result {
        val hops = EndpointChain.hops(ctx)
        if (hops.isEmpty()) {
            return Result(Check.CHAIN, Status.SKIPPED, "No hops configured — egress is direct.")
        }
        if (!EndpointChain.isEnabled(ctx)) {
            return Result(
                Check.CHAIN,
                Status.SKIPPED,
                "${hops.size} hop(s) are configured but routing through the chain is switched off.",
            )
        }
        val resolver = DnsSettings.ip(ctx)
        val port = when (DnsSettings.mode(ctx)) {
            com.understory.godwall.dns.UpstreamResolver.Mode.DOT -> 853
            com.understory.godwall.dns.UpstreamResolver.Mode.DOH -> 443
            com.understory.godwall.dns.UpstreamResolver.Mode.PLAINTEXT -> 53
        }
        return when (val r = ChainDialer.dial(null, hops, resolver, port, 10_000)) {
            is ChainDialer.Result.Connected -> {
                runCatching { r.socket.close() }
                Result(Check.CHAIN, Status.PASS, "Established: ${r.path}")
            }
            is ChainDialer.Result.Unavailable -> Result(Check.CHAIN, Status.FAIL, r.reason)
        }
    }

    private fun enforcement(ctx: Context): Result {
        val probes = Enforcement.probe(ctx)
        val selection = Enforcement.select(probes, Enforcement.manual(ctx))
        val chosen = selection.chosen
            ?: return Result(Check.ENFORCEMENT, Status.FAIL, "No enforcement backend is available.")
        val detail = probes.first { it.backend == chosen }.detail
        return Result(Check.ENFORCEMENT, Status.PASS, detail)
    }
}
