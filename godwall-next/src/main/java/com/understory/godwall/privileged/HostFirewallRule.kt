package com.understory.godwall.privileged

/**
 * One host netfilter rule, described as data with no knowledge of how it is applied.
 *
 * ## Why a model and not a string
 *
 * The privileged tier's whole job is to write the kernel's real iptables / nftables tables — the
 * netfilter space the architecture invariant reserves for the tier that "genuinely needs root"
 * (docs/DONOR-ASSETS.md; the task's socket-space-vs-netfilter-space boundary). A rule is the same
 * fact whether it is expressed as an `iptables -A` line or an `nft add rule`, so it is held here as
 * structured data and rendered to either dialect on demand ([toIptables], [toNft]). That keeps the
 * two backends from drifting: there is one description of "drop packets to 1.2.3.4", and the
 * renderer — not a hand-written command somewhere — decides how it reaches the kernel.
 *
 * ## Why this is pure, and testable off-device
 *
 * Nothing here touches a shell, a socket, or a device. A rule renders to a deterministic string, so
 * "does the ban we computed become the iptables line we intended?" is answerable on the JVM without
 * root, without Yojimbo, and without a device — which matters because on a normal device the tier
 * that WOULD apply these is honestly gated (uid 2000 has no CAP_NET_ADMIN), and an engine you can
 * only exercise when root is present is an engine that never gets exercised.
 *
 * ## The injection surface, closed here
 *
 * A CIDR or interface name eventually reaches `sh -c` inside the privileged shell. The fields below
 * are validated against tight patterns at construction ([validate]) so a malformed value fails loudly
 * as a programming error rather than arriving at the shell as an argument that could break out of the
 * rule. The renderers additionally emit only the tokens a validated rule can produce.
 */
data class HostFirewallRule(
    /** Which built-in chain the rule is appended to. */
    val chain: Chain,
    /** ACCEPT / DROP / REJECT — what happens to a matching packet. */
    val verdict: Verdict,
    /** Layer-4 protocol to match, or [Protocol.ALL] for any. A port requires TCP or UDP. */
    val protocol: Protocol = Protocol.ALL,
    /** Source address as an IPv4/IPv6 CIDR (e.g. `1.2.3.4/32`, `10.0.0.0/8`), or null for any. */
    val source: String? = null,
    /** Destination address as a CIDR, or null for any. */
    val destination: String? = null,
    /** Destination port or port range, or null for any. Only valid with TCP/UDP. */
    val dport: PortSpec? = null,
    /** Connection-tracking states to match (e.g. ESTABLISHED, RELATED), or empty for any. */
    val ctState: Set<ConnState> = emptySet(),
    /** Interface constraint, or null for any. IN is valid on INPUT/FORWARD, OUT on OUTPUT/FORWARD. */
    val iface: IfaceMatch? = null,
    /** Free-text note carried into the rule as an iptables `--comment` / nft `comment`. */
    val comment: String? = null,
) {

    init {
        val problem = validate()
        require(problem == null) { "invalid HostFirewallRule: $problem" }
    }

    /** The netfilter built-in chains this tier writes. */
    enum class Chain(val iptables: String, val nft: String) {
        INPUT("INPUT", "input"),
        OUTPUT("OUTPUT", "output"),
        FORWARD("FORWARD", "forward"),
    }

    /** What a matching packet gets. REJECT sends an error back; DROP is silent. */
    enum class Verdict(val iptables: String, val nft: String) {
        ACCEPT("ACCEPT", "accept"),
        DROP("DROP", "drop"),
        REJECT("REJECT", "reject"),
    }

    /** Layer-4 protocol selector. [ALL] emits no `-p`, matching everything. */
    enum class Protocol(val token: String?) {
        ALL(null),
        TCP("tcp"),
        UDP("udp"),
        ICMP("icmp"),
    }

    /** conntrack states, spelled the same in both dialects. */
    enum class ConnState { NEW, ESTABLISHED, RELATED, INVALID }

    /** Which side an interface constraint binds. */
    enum class Direction { IN, OUT }

    /** A single destination port, or an inclusive range. */
    data class PortSpec(val from: Int, val to: Int = from) {
        init {
            require(from in 1..65535 && to in 1..65535 && from <= to) {
                "port spec $from:$to out of range"
            }
        }

        /** `22` for a single port, `9000:9100` for a range. Both dialects accept this form. */
        fun render(): String = if (from == to) "$from" else "$from:$to"
    }

    /** An interface match: `-i eth0` / `iif "eth0"` (IN) or `-o wlan0` / `oif "wlan0"` (OUT). */
    data class IfaceMatch(val direction: Direction, val name: String)

    /** The problem with this rule, or null when it is well formed. Pure; safe to call anywhere. */
    fun validate(): String? = when {
        dport != null && protocol != Protocol.TCP && protocol != Protocol.UDP ->
            "a destination port needs protocol TCP or UDP, not $protocol"
        source != null && !isCidr(source) -> "source '$source' is not a valid CIDR"
        destination != null && !isCidr(destination) -> "destination '$destination' is not a valid CIDR"
        iface != null && !IFACE_PATTERN.matches(iface.name) ->
            "interface '${iface.name}' is not a valid interface name"
        iface?.direction == Direction.IN && chain == Chain.OUTPUT ->
            "an input-interface match is not valid on the OUTPUT chain"
        iface?.direction == Direction.OUT && chain == Chain.INPUT ->
            "an output-interface match is not valid on the INPUT chain"
        comment != null && !COMMENT_PATTERN.matches(comment) ->
            "comment contains characters that are not allowed in a rule comment"
        else -> null
    }

    /**
     * The rule as an `iptables`/`ip6tables` append argument line, e.g.
     * `-A OUTPUT -d 1.2.3.4/32 -p tcp --dport 443 -j DROP`.
     *
     * Emitted without the leading `iptables` so the same line drops into an `iptables-restore`
     * `*filter` block or follows an `iptables -w` invocation unchanged.
     */
    fun toIptables(): String = buildList {
        add("-A"); add(chain.iptables)
        iface?.let {
            add(if (it.direction == Direction.IN) "-i" else "-o"); add(it.name)
        }
        source?.let { add("-s"); add(it) }
        destination?.let { add("-d"); add(it) }
        protocol.token?.let { add("-p"); add(it) }
        dport?.let { add("--dport"); add(it.render()) }
        if (ctState.isNotEmpty()) {
            add("-m"); add("conntrack"); add("--ctstate"); add(ctState.joinToString(",") { it.name })
        }
        comment?.let { add("-m"); add("comment"); add("--comment"); add("\"$it\"") }
        add("-j"); add(verdict.iptables)
    }.joinToString(" ")

    /**
     * The rule as an `nft add rule` body for the `inet` table below, e.g.
     * `ip daddr 1.2.3.4/32 tcp dport 443 drop`.
     *
     * IPv6 sources/destinations use `ip6 saddr`; the family prefix is chosen from the literal so a
     * single rule model renders correctly into an `inet` (dual-stack) table.
     */
    fun toNft(): String = buildList {
        iface?.let {
            add(if (it.direction == Direction.IN) "iif" else "oif"); add("\"${it.name}\"")
        }
        source?.let { add(nftAddrKeyword(it, "saddr")); add(it) }
        destination?.let { add(nftAddrKeyword(it, "daddr")); add(it) }
        protocol.token?.let { proto ->
            if (dport != null) {
                add(proto); add("dport"); add(dport.render())
            } else {
                add("meta"); add("l4proto"); add(proto)
            }
        }
        if (ctState.isNotEmpty()) {
            add("ct"); add("state"); add(ctState.joinToString(",") { it.name.lowercase() })
        }
        add(verdict.nft)
        comment?.let { add("comment"); add("\"$it\"") }
    }.joinToString(" ")

    private fun nftAddrKeyword(cidr: String, side: String): String =
        if (cidr.contains(':')) "ip6 $side" else "ip $side"

    companion object {
        private val IFACE_PATTERN = Regex("[A-Za-z0-9._+-]{1,15}")

        // Comments become a quoted token inside the rule; keep them to characters that cannot
        // close the quote or introduce a shell metacharacter once the whole rule reaches sh -c.
        private val COMMENT_PATTERN = Regex("[A-Za-z0-9 ._:/#()-]{0,120}")

        /**
         * A permissive CIDR check: a dotted-quad or a bracket-free IPv6 literal, optionally with a
         * `/prefix`. Deliberately not a full IP parser — it exists to refuse shell-metacharacters and
         * obvious nonsense before a value reaches the privileged shell, not to validate routing.
         */
        fun isCidr(value: String): Boolean {
            val slash = value.indexOf('/')
            val addr = if (slash >= 0) value.substring(0, slash) else value
            val prefix = if (slash >= 0) value.substring(slash + 1) else null
            if (prefix != null) {
                val p = prefix.toIntOrNull() ?: return false
                val max = if (addr.contains(':')) 128 else 32
                if (p !in 0..max) return false
            }
            return if (addr.contains(':')) isIpv6(addr) else isIpv4(addr)
        }

        private fun isIpv4(addr: String): Boolean {
            val parts = addr.split('.')
            if (parts.size != 4) return false
            return parts.all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }
        }

        private fun isIpv6(addr: String): Boolean {
            // A single "::" is permitted; every other group must be 1..4 hex digits. This accepts the
            // literals a ban set produces (full and compressed) and rejects anything with a character
            // that has no business in an IPv6 address.
            if (addr == "::") return true
            if (addr.count { it == ':' } > 7) return false
            if ("::" in addr && addr.indexOf("::") != addr.lastIndexOf("::")) return false
            val groups = addr.split(':')
            return groups.all { g -> g.isEmpty() || (g.length in 1..4 && g.all { it.isHexDigit() }) }
        }

        private fun Char.isHexDigit(): Boolean =
            this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'
    }
}

/**
 * A whole netfilter table: the default policy for each chain plus the ordered rules, rendered as a
 * complete `iptables-restore` block or a complete `nft` table definition.
 *
 * ## Why default policy is first-class
 *
 * The task's "boot-time DROP" is exactly a default policy of DROP on OUTPUT (and INPUT/FORWARD) with
 * a small allow-list ahead of it. That posture is the difference between a firewall and a list of
 * bans: bans deny named offenders; a default-DROP denies everything not explicitly allowed. Both are
 * expressible here, and [lockdown] builds the second.
 *
 * ## Applied atomically, or not at all
 *
 * [toIptablesRestore] is what a backend pipes into `iptables-restore`, which swaps the whole table in
 * one syscall — there is never a window where the default policy is DROP but the loopback allow has
 * not landed yet, which a rule-at-a-time apply would open and which, on the OUTPUT chain, would drop
 * the very shell applying the rules. That atomicity is the reason the model renders a table rather
 * than a list of `-A` commands.
 */
data class HostFirewallTable(
    val name: String,
    val policies: Map<HostFirewallRule.Chain, HostFirewallRule.Verdict>,
    val rules: List<HostFirewallRule>,
) {

    /**
     * The `iptables-restore` document for this table. `-restore` requires every chain it references
     * to have a policy line, so chains without an explicit policy default to ACCEPT (the netfilter
     * built-in default) rather than being omitted, which `-restore` would reject.
     */
    fun toIptablesRestore(): String = buildString {
        appendLine("*filter")
        for (chain in HostFirewallRule.Chain.entries) {
            val policy = policies[chain] ?: HostFirewallRule.Verdict.ACCEPT
            appendLine(":${chain.iptables} ${policy.iptables} [0:0]")
        }
        for (rule in rules) appendLine(rule.toIptables())
        appendLine("COMMIT")
    }

    /**
     * The `nft` document for this table, in the dual-stack `inet` family. Each chain is a base chain
     * hooked at its natural point with the table's policy; an nft base chain carries its policy in its
     * declaration, so the two dialects express the same default-DROP posture.
     */
    fun toNft(): String = buildString {
        appendLine("table inet $name {")
        for (chain in HostFirewallRule.Chain.entries) {
            val policy = policies[chain] ?: HostFirewallRule.Verdict.ACCEPT
            val hook = when (chain) {
                HostFirewallRule.Chain.INPUT -> "input"
                HostFirewallRule.Chain.OUTPUT -> "output"
                HostFirewallRule.Chain.FORWARD -> "forward"
            }
            appendLine("  chain ${chain.nft} {")
            appendLine("    type filter hook $hook priority 0; policy ${policy.nft};")
            for (rule in rules.filter { it.chain == chain }) appendLine("    ${rule.toNft()}")
            appendLine("  }")
        }
        appendLine("}")
    }

    companion object {
        /** The table name both backends write; short, so `nft delete table inet godwall` is exact. */
        const val NAME = "godwall"

        /**
         * The pre-configured boot-time-DROP posture (charter rule C: ship a working default).
         *
         * A default-DROP kill switch that keeps a device usable needs four allows ahead of the drop,
         * and every one of them is here rather than left to the user: loopback (or the device talks to
         * nothing, including its own resolver), established/related (or every reply to a connection the
         * user opened is dropped), DNS to the loopback resolver Godwall advertises, and the DHCP/RA
         * exchange the interface needs to stay addressed. Everything else on OUTPUT is dropped.
         *
         * This is the same intent as InviZible's root kill switch ("Block internet connection when Tor,
         * DNSCrypt and Purple I2P are stopped") and NetGuard's "Lockdown traffic", expressed as real
         * netfilter rather than described — but it is applied ONLY when the netfilter tier is live,
         * i.e. when the privileged shell actually holds CAP_NET_ADMIN. Rendered here regardless, so the
         * Advanced surface can show exactly what WOULD be applied.
         *
         * @param resolver the loopback resolver address Godwall advertises, allowed on OUTPUT so name
         *   resolution survives the lockdown. Defaults to Godwall's documentation-space resolver.
         */
        fun lockdown(resolver: String = "203.0.113.53"): HostFirewallTable {
            val loopback = "127.0.0.0/8"
            val established = setOf(HostFirewallRule.ConnState.ESTABLISHED, HostFirewallRule.ConnState.RELATED)
            return HostFirewallTable(
                name = NAME,
                policies = mapOf(
                    HostFirewallRule.Chain.INPUT to HostFirewallRule.Verdict.DROP,
                    HostFirewallRule.Chain.OUTPUT to HostFirewallRule.Verdict.DROP,
                    HostFirewallRule.Chain.FORWARD to HostFirewallRule.Verdict.DROP,
                ),
                rules = listOf(
                    // Loopback both directions — the resolver, and every in-device socket, ride it.
                    HostFirewallRule(
                        chain = HostFirewallRule.Chain.OUTPUT,
                        verdict = HostFirewallRule.Verdict.ACCEPT,
                        iface = HostFirewallRule.IfaceMatch(HostFirewallRule.Direction.OUT, "lo"),
                        comment = "loopback",
                    ),
                    HostFirewallRule(
                        chain = HostFirewallRule.Chain.INPUT,
                        verdict = HostFirewallRule.Verdict.ACCEPT,
                        iface = HostFirewallRule.IfaceMatch(HostFirewallRule.Direction.IN, "lo"),
                        comment = "loopback",
                    ),
                    // Replies to connections the user already opened.
                    HostFirewallRule(
                        chain = HostFirewallRule.Chain.OUTPUT,
                        verdict = HostFirewallRule.Verdict.ACCEPT,
                        ctState = established,
                        comment = "established",
                    ),
                    HostFirewallRule(
                        chain = HostFirewallRule.Chain.INPUT,
                        verdict = HostFirewallRule.Verdict.ACCEPT,
                        ctState = established,
                        comment = "established",
                    ),
                    // Name resolution to Godwall's own resolver, so a locked-down device still resolves.
                    HostFirewallRule(
                        chain = HostFirewallRule.Chain.OUTPUT,
                        verdict = HostFirewallRule.Verdict.ACCEPT,
                        protocol = HostFirewallRule.Protocol.UDP,
                        destination = "$resolver/32",
                        dport = HostFirewallRule.PortSpec(53),
                        comment = "dns to resolver",
                    ),
                    // DHCP client, so the interface keeps its address under the lockdown.
                    HostFirewallRule(
                        chain = HostFirewallRule.Chain.OUTPUT,
                        verdict = HostFirewallRule.Verdict.ACCEPT,
                        protocol = HostFirewallRule.Protocol.UDP,
                        dport = HostFirewallRule.PortSpec(67, 68),
                        comment = "dhcp",
                    ),
                ),
            )
        }

        /**
         * A table whose only rules DROP traffic to and from each banned address, over a default-ACCEPT
         * policy. This is the fail2ban enforcement shape: it denies named offenders and touches nothing
         * else, so it composes with, rather than replaces, whatever else is on the device.
         *
         * OUTPUT `-d ban` and INPUT `-s ban` cover both directions of a two-way flow; a single-side
         * ban would let the offender keep talking to the device on the return path.
         */
        fun bans(addresses: List<String>): HostFirewallTable {
            val rules = addresses.flatMap { addr ->
                val cidr = if ('/' in addr) addr else defaultHostCidr(addr)
                listOf(
                    HostFirewallRule(
                        chain = HostFirewallRule.Chain.OUTPUT,
                        verdict = HostFirewallRule.Verdict.DROP,
                        destination = cidr,
                        comment = "ban",
                    ),
                    HostFirewallRule(
                        chain = HostFirewallRule.Chain.INPUT,
                        verdict = HostFirewallRule.Verdict.DROP,
                        source = cidr,
                        comment = "ban",
                    ),
                )
            }
            return HostFirewallTable(
                name = NAME,
                policies = emptyMap(), // default-ACCEPT: bans deny offenders, they do not lock the device down
                rules = rules,
            )
        }

        /** `/32` for a bare IPv4, `/128` for a bare IPv6 — a single-host CIDR for a bare address. */
        fun defaultHostCidr(addr: String): String = if (addr.contains(':')) "$addr/128" else "$addr/32"
    }
}
