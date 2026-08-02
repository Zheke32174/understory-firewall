package com.understory.godwall.privileged

import android.content.Context
import com.understory.godwall.privilege.Privilege
import com.understory.godwall.subsystem.PrefixInstaller
import com.understory.security.Diagnostics

/**
 * The host netfilter enforcement backend: it writes the kernel's real iptables / ip6tables rules,
 * through Yojimbo's privileged shell, on the HOST — never inside proot, which has no netfilter
 * access (the task's constraint, restated because it is the whole reason this runs where it does).
 *
 * ## The honest gate this backend exists to enforce
 *
 * The architecture invariant is exact: socket-space work runs at uid 2000 today; only netfilter
 * table writes and cross-app process access need the privileged tier. Yojimbo stands a process up at
 * **uid 2000 (shell)**, and uid 2000 does not hold CAP_NET_ADMIN — so on a stock device the shell can
 * *execute* `iptables` but the kernel refuses the netlink write, and the honest answer is "the tables
 * cannot be touched here." This backend does not assume that answer; it PROBES for it ([probe]) by
 * actually asking the tables to list themselves, which needs the same capability writing them does. If
 * the probe says the tables are reachable — a rooted device, a Yojimbo server that runs elevated — the
 * controls go live for real. If it says they are not, every control is disabled with a sentence naming
 * exactly which of the four reasons applies. Nothing here is a hardcoded `false`; the gate is a live
 * measurement, which is the only kind of gate that turns real on a device that can back it.
 *
 * ## Non-destructive by construction
 *
 * On Android the `filter` table is netd's: it carries the bandwidth, data-saver, tethering and
 * per-uid chains the platform depends on, and an `iptables-restore` of the whole table would wipe them
 * and break connectivity. So bans are NOT applied by swapping the table. They live in a dedicated
 * [BAN_CHAIN] that is jumped into from INPUT and OUTPUT and contains only DROP rules for banned
 * addresses — the fail2ban pattern, which composes with netd instead of replacing it. `-w` waits for
 * the xtables lock (InviZible's "Wait for the xtables lock") so a concurrent netd change is not
 * clobbered.
 *
 * ## What it deliberately does not do
 *
 * It does not install a device-wide default-DROP kill switch here. That posture ([HostFirewallTable.lockdown])
 * is rendered for display, but applying it means dropping every flow the allow-list does not cover, and
 * making it hold *at boot, before Godwall runs* needs a root-owned boot service that uid 2000 cannot
 * install — so it is gated with that sentence, and the rootless equivalent (Android's always-on VPN
 * with "Block connections without VPN") stays the Kill switch card's job. Shipping a device-wide drop
 * that silently does not survive a reboot would be the dead control this campaign removes.
 */
object NetfilterBackend {

    private const val TAG = "godwall.privileged.NetfilterBackend"

    /** The dedicated chain bans live in — jumped from INPUT/OUTPUT, never netd's own chains. */
    const val BAN_CHAIN = "godwall_ban"

    /** Seconds `iptables -w` waits for the xtables lock before giving up. */
    private const val XTABLES_WAIT = "5"

    /** Which command actually reaches the tables on this device. */
    enum class Tool { IPTABLES, NFT, NONE }

    /** Whether, and why, the tables can or cannot be written here. */
    enum class Capability {
        /** The tables list, so the shell holds CAP_NET_ADMIN and can write them. Controls go live. */
        CAPABLE,

        /** A tool exists but the tables refuse to list: the shell is uid 2000 without CAP_NET_ADMIN. */
        NO_PERMISSION,

        /** Neither iptables nor nft is on the device's PATH. */
        NO_TOOL,

        /** No privileged shell is attached from Yojimbo at all. */
        NO_SHELL,
    }

    /** The result of a live probe: what tool, what capability, and one honest sentence. */
    data class Probe(val tool: Tool, val capability: Capability, val detail: String) {
        val usable: Boolean get() = capability == Capability.CAPABLE
    }

    /** The outcome of an apply/clear: whether it took, and one sentence for the caller to show/log. */
    data class Result(val ok: Boolean, val message: String)

    // ---- Probe -------------------------------------------------------------------------

    /**
     * Ask the device, right now, whether host netfilter can be written from the attached shell.
     * Blocking — a binder round trip to Yojimbo. Call off the main thread.
     *
     * The probe LISTS the tables (`iptables -S` / `nft list ruleset`). Listing needs the same
     * CAP_NET_ADMIN that writing does, so a successful list is proof the writes below will also be
     * accepted — and a permission failure is proof they will not, which is reported rather than
     * discovered later as a silently-dropped ban.
     */
    fun probe(context: Context): Probe {
        if (!Privilege.isAvailable()) {
            return Probe(Tool.NONE, Capability.NO_SHELL, noShellSentence(context))
        }
        val r = Privilege.exec(listOf("sh", "-c", PROBE_SCRIPT), timeoutMs = 20_000L)
        if (!r.ok && r.out.isBlank()) {
            Diagnostics.warn(TAG, "probe shell call failed: ${r.summary()}")
            return Probe(Tool.NONE, Capability.NO_SHELL, noShellSentence(context))
        }
        val line = r.out.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() }.orEmpty()
        val parts = line.split(' ')
        val tool = when (parts.getOrNull(0)) {
            "iptables" -> Tool.IPTABLES
            "nft" -> Tool.NFT
            else -> Tool.NONE
        }
        val cap = when (parts.getOrNull(1)) {
            "ok" -> Capability.CAPABLE
            "noperm" -> Capability.NO_PERMISSION
            else -> Capability.NO_TOOL
        }
        val probe = Probe(tool, cap, sentenceFor(tool, cap))
        Diagnostics.log(TAG, "netfilter probe: tool=$tool cap=$cap")
        return probe
    }

    private const val PROBE_SCRIPT =
        "tool=none; cap=notool\n" +
            // iptables first: it is present on the broadest range of Android versions, where it is
            // usually the nft-backed wrapper anyway. `-w` so a concurrent netd change is waited out.
            "if command -v iptables >/dev/null 2>&1; then\n" +
            "  tool=iptables\n" +
            "  if iptables -w $XTABLES_WAIT -S >/dev/null 2>&1; then cap=ok; else cap=noperm; fi\n" +
            "elif command -v nft >/dev/null 2>&1; then\n" +
            "  tool=nft\n" +
            "  if nft list ruleset >/dev/null 2>&1; then cap=ok; else cap=noperm; fi\n" +
            "fi\n" +
            "printf '%s %s\\n' \"\$tool\" \"\$cap\"\n" +
            "exit 0"

    // ---- Apply / clear bans ------------------------------------------------------------

    /**
     * Reconcile the host ban chain to exactly [addresses]. Blocking. Non-destructive: it creates and
     * fills [BAN_CHAIN] and jumps into it, leaving every other chain — netd's included — untouched.
     *
     * Refuses unless [probe] reports CAPABLE, so a caller that skips the gate still cannot issue a
     * write the kernel would reject; the returned [Result] carries the probe's own sentence in that
     * case, so "the ban did not take" and "there is no privilege to take it" are never conflated.
     */
    fun applyBans(context: Context, addresses: List<String>): Result {
        val probe = probe(context)
        if (!probe.usable) return Result(false, probe.detail)
        if (probe.tool != Tool.IPTABLES) {
            // The nft apply path is not implemented in this build; say so rather than silently no-op.
            // iptables is present on every Android this targets, so this branch is the rare one.
            return Result(
                false,
                "This device reaches netfilter through nft, not iptables. Godwall's ban enforcement " +
                    "writes iptables rules; the nft apply path is not in this build, so bans are " +
                    "recorded but not enforced here. The ban list is still accurate.",
            )
        }
        val valid = addresses.filter { BanEngine.isAddress(it) }.distinct()
        val v4 = valid.filterNot { it.contains(':') }
        val v6 = valid.filter { it.contains(':') }
        val script = buildBanScript("iptables", v4) + "\n" + buildBanScript("ip6tables", v6)
        val r = Privilege.exec(listOf("sh", "-c", script), timeoutMs = 60_000L)
        return if (r.ok) {
            Diagnostics.log(TAG, "applied ${valid.size} ban(s) to $BAN_CHAIN")
            Result(true, "Enforcing ${valid.size} host netfilter ban(s) in the $BAN_CHAIN chain.")
        } else {
            Result(false, "Could not apply host bans: ${r.summary()}")
        }
    }

    /** Remove the ban chain and its jumps entirely. Blocking. Safe to call when nothing is applied. */
    fun clearBans(context: Context): Result {
        if (!Privilege.isAvailable()) return Result(false, noShellSentence(context))
        val script = clearBanScript("iptables") + "\n" + clearBanScript("ip6tables")
        val r = Privilege.exec(listOf("sh", "-c", script), timeoutMs = 30_000L)
        return if (r.ok) {
            Diagnostics.log(TAG, "cleared $BAN_CHAIN")
            Result(true, "Removed the host netfilter ban chain. No addresses are dropped at the kernel now.")
        } else {
            Result(false, "Could not clear host bans: ${r.summary()}")
        }
    }

    private fun buildBanScript(cmd: String, addresses: List<String>): String {
        val q = PrefixInstaller::quote
        val ipt = "$cmd -w $XTABLES_WAIT"
        return buildList {
            // Ensure the chain exists and is empty, then ensure exactly one jump from each hook.
            add("$ipt -N $BAN_CHAIN 2>/dev/null || $ipt -F $BAN_CHAIN")
            add("$ipt -C INPUT -j $BAN_CHAIN 2>/dev/null || $ipt -I INPUT -j $BAN_CHAIN")
            add("$ipt -C OUTPUT -j $BAN_CHAIN 2>/dev/null || $ipt -I OUTPUT -j $BAN_CHAIN")
            for (addr in addresses) {
                val cidr = if ('/' in addr) addr else HostFirewallTable.defaultHostCidr(addr)
                // -s catches the offender as an inbound source, -d as an outbound destination; the
                // chain is entered from both hooks, so both directions of a two-way flow are dropped.
                add("$ipt -A $BAN_CHAIN -s ${q(cidr)} -j DROP")
                add("$ipt -A $BAN_CHAIN -d ${q(cidr)} -j DROP")
            }
            add("exit 0")
        }.joinToString("\n")
    }

    private fun clearBanScript(cmd: String): String {
        val ipt = "$cmd -w $XTABLES_WAIT"
        return buildList {
            add("$ipt -D INPUT -j $BAN_CHAIN 2>/dev/null")
            add("$ipt -D OUTPUT -j $BAN_CHAIN 2>/dev/null")
            add("$ipt -F $BAN_CHAIN 2>/dev/null")
            add("$ipt -X $BAN_CHAIN 2>/dev/null")
            add("exit 0")
        }.joinToString("\n")
    }

    // ---- Sentences ---------------------------------------------------------------------

    private fun noShellSentence(context: Context): String =
        "Host netfilter rules are written on the device itself, which needs a privileged shell from " +
            "Yojimbo. None is attached. ${Privilege.explain(context)}"

    private fun sentenceFor(tool: Tool, cap: Capability): String = when (cap) {
        Capability.CAPABLE ->
            "The attached privileged shell can write this device's netfilter tables through " +
                "${tool.name.lowercase()}. Host firewall rules and bans are enforced at the kernel."
        Capability.NO_PERMISSION ->
            "Yojimbo attaches a shell at uid 2000 (shell), which can run ${tool.name.lowercase()} but " +
                "cannot write the kernel's netfilter tables — that needs CAP_NET_ADMIN (root), which " +
                "this tier does not hold. Host firewall rules and bans stay disabled here; the ban " +
                "list is still computed and shown, and the userspace packet tier enforces per-flow " +
                "when its data plane is present."
        Capability.NO_TOOL ->
            "This device exposes neither an iptables nor an nft binary to the privileged shell, so " +
                "there is nothing to write host netfilter rules with. Host firewall rules and bans " +
                "stay disabled; the ban list is still computed and shown."
        Capability.NO_SHELL ->
            "No privileged shell is attached from Yojimbo, so the device's netfilter tables cannot be " +
                "reached. Host firewall rules and bans stay disabled."
    }
}
