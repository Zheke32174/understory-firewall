package com.understory.firewall.chain

import android.content.Context
import com.understory.elevation.Elevation
import com.understory.security.Diagnostics

/**
 * Measures — rather than assumes — what the privileged and container transport tiers
 * can actually do on THIS device.
 *
 * The chain's higher tiers ([ProxyHop.Transport.KERNEL], [ProxyHop.Transport.CONTAINER])
 * depend on things Godwall cannot know statically: whether the Shizuku/Yojimbo shell is
 * granted, and which routing or container tooling exists in the environment. Hardcoding
 * "PENDING — needs a container server" is true but useless; probing tells the user WHICH
 * piece is missing, which is the difference between a dead end and a next step.
 *
 * IMPORTANT HONESTY BOUNDARY, stated here because it is easy to get wrong: a successful
 * probe does NOT mean a hop works. Finding `docker` on the device proves a container
 * runtime exists — it does not mean Godwall can forward traffic into a relay inside it,
 * because that relay plumbing is not implemented yet. So probes enrich the *explanation*
 * of a PENDING backend; they never promote it to LINKED. Only an implemented data plane
 * does that (today: SOCKS5 and HTTP CONNECT).
 *
 * Probing runs a shell command, so it is suspending and explicitly refreshed
 * ([refresh]) rather than run implicitly on every UI recomposition. Readers get the
 * last cached [snapshot]; before any probe it honestly reports "not probed yet".
 */
object TransportCapability {

    private const val TAG = "firewall.chain.TransportCapability"
    private const val PROBE_TIMEOUT_MS = 4_000L

    /** Routing tools that would let a hop be armed at kernel level. */
    private val KERNEL_TOOLS = listOf("ip", "nft", "iptables")

    /** Container runtimes / launchers that could host a relay. */
    private val CONTAINER_TOOLS = listOf("docker", "podman", "machinectl", "systemd-nspawn", "proot", "chroot")

    data class Snapshot(
        /** False until [refresh] has actually run once. */
        val probed: Boolean = false,
        val shellGranted: Boolean = false,
        /** Subset of [KERNEL_TOOLS] found on PATH. */
        val kernelTools: List<String> = emptyList(),
        /** Subset of [CONTAINER_TOOLS] found on PATH. */
        val containerTools: List<String> = emptyList(),
        /** Set when the probe itself failed (shell error), so we do not claim "absent". */
        val probeError: String = "",
    ) {
        /**
         * Kernel routing is *reachable* — a privileged shell plus at least one packet-filter
         * tool and `ip`. Reachable, note, not implemented: see the class doc.
         */
        val kernelReachable: Boolean
            get() = shellGranted && kernelTools.contains("ip") &&
                (kernelTools.contains("nft") || kernelTools.contains("iptables"))

        /** A container runtime is present and we have a shell to drive it. */
        val containerReachable: Boolean
            get() = shellGranted && containerTools.isNotEmpty()

        /** Human line for the KERNEL tier. Never overstates. */
        fun kernelDetail(): String = when {
            !probed -> "not probed yet"
            probeError.isNotEmpty() -> "probe failed: $probeError"
            !shellGranted -> "no privileged shell (grant Shizuku/Yojimbo in Elevation)"
            kernelTools.isEmpty() -> "shell granted, but no routing tools found (ip/nft/iptables)"
            !kernelReachable -> "shell granted; found ${kernelTools.joinToString(", ")} — need ip plus nft or iptables"
            else -> "reachable: shell + ${kernelTools.joinToString(", ")} (relay plumbing still to build)"
        }

        /** Human line for the CONTAINER tier. Never overstates. */
        fun containerDetail(): String = when {
            !probed -> "not probed yet"
            probeError.isNotEmpty() -> "probe failed: $probeError"
            !shellGranted -> "no privileged shell (grant Shizuku/Yojimbo in Elevation)"
            containerTools.isEmpty() -> "shell granted, but no container runtime found"
            else -> "runtime present: ${containerTools.joinToString(", ")} (relay plumbing still to build)"
        }
    }

    @Volatile
    private var cached = Snapshot()

    /** Last probe result. Cheap, non-suspending, safe to read from composition. */
    fun snapshot(): Snapshot = cached

    /**
     * Re-probe the device. Runs ONE shell command that reports which of the tools we care
     * about are on PATH, so a refresh costs a single round trip rather than one per binary.
     */
    suspend fun refresh(ctx: Context): Snapshot {
        if (!Elevation.canRunShell(ctx)) {
            cached = Snapshot(probed = true, shellGranted = false)
            return cached
        }
        val wanted = KERNEL_TOOLS + CONTAINER_TOOLS
        // `command -v` is the portable presence test and exists in Android's mksh.
        val script = wanted.joinToString("; ") { "command -v $it >/dev/null 2>&1 && echo $it" }
        val result = runCatching {
            Elevation.runShell(ctx, listOf("sh", "-c", script), PROBE_TIMEOUT_MS)
        }.getOrElse { t ->
            val why = "${t.javaClass.simpleName}: ${t.message}"
            Diagnostics.error(TAG, "transport probe failed — $why")
            cached = Snapshot(probed = true, shellGranted = true, probeError = why)
            return cached
        }

        val present = result.out.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        cached = Snapshot(
            probed = true,
            shellGranted = true,
            kernelTools = KERNEL_TOOLS.filter { it in present },
            containerTools = CONTAINER_TOOLS.filter { it in present },
        )
        Diagnostics.log(
            TAG,
            "transport probe: kernel=${cached.kernelTools} container=${cached.containerTools}",
        )
        return cached
    }
}
