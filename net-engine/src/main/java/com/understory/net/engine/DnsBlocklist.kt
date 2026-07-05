package com.understory.net.engine

/**
 * On-device DNS blocklist — the "is this domain an ad/tracker/malware host?"
 * oracle for the opt-in adblock-DNS tunnel (S6). PURE JVM, total, thread-safe
 * for reads after [build].
 *
 * DATA STRUCTURE (clean-room; behaviorally equivalent to the domain-suffix
 * match every hosts-based blocker does — RethinkDNS's compressed trie answers
 * the same question with far more entries, credited in NOTICE):
 *
 *   A single [HashSet]<String> of blocked labels-joined domains. A lookup for
 *   "a.b.example.com" tests the full name and each parent suffix
 *   ("b.example.com", "example.com", "com") — so a blocklist entry of
 *   "example.com" blocks the whole subtree, which is exactly how a hosts /
 *   domain blocklist is meant to behave. At most (label-count) hash probes per
 *   query; for a typical 3–4 label name that is 3–4 O(1) probes. No per-entry
 *   allocation on the query path beyond the substring views.
 *
 * We deliberately do NOT ship a bespoke compressed trie: a HashSet of a few
 * hundred-thousand short strings is a few MB of heap, loads lazily off the UI
 * thread, and is trivially correct. If the bundled list ever needs to be far
 * larger we can swap the internals behind [isBlocked] without touching callers.
 *
 * HONESTY: this blocks by DOMAIN NAME only. It cannot block a connection made
 * to a raw IP address (no DNS lookup happens), and it cannot see inside
 * encrypted DNS an app makes to its OWN DoH resolver that bypasses the system
 * resolver. Those boundaries are stated in the UI.
 */
class DnsBlocklist private constructor(
    private val blocked: HashSet<String>,
    /** Domains the user explicitly allow-listed; win over [blocked]. */
    private val allow: HashSet<String>,
) {

    /** Number of blocked domains loaded. */
    val size: Int get() = blocked.size

    /**
     * True iff [host] (a lowercased, dot-joined domain with no trailing dot)
     * is blocked: the full name or any parent domain is in the blocked set AND
     * no equal-or-more-specific parent is in the allow set. Empty host ⇒ false.
     *
     * The allow check is evaluated at the SAME suffix granularity, so
     * allow-listing "example.com" un-blocks "ads.example.com" even if the
     * blocklist contains the parent.
     */
    fun isBlocked(host: String): Boolean {
        if (host.isEmpty()) return false
        val h = if (host.endsWith('.')) host.dropLast(1) else host
        var start = 0
        // Walk suffixes from the full name up to the TLD.
        while (true) {
            val suffix = if (start == 0) h else h.substring(start)
            if (suffix in allow) return false        // explicit allow wins
            if (suffix in blocked) {
                // Blocked at this level — but a more-specific allow could still
                // have un-blocked it; we already checked those on prior iterations
                // (more specific = shorter start), so this is a genuine block.
                return true
            }
            val dot = h.indexOf('.', start)
            if (dot < 0) return false
            start = dot + 1
        }
    }

    companion object {
        /**
         * Build a blocklist from raw hosts/domain lines. Accepts the common
         * formats found in public lists:
         *   - "0.0.0.0 ads.example.com" / "127.0.0.1 ads.example.com" (hosts)
         *   - "ads.example.com" (bare domain, one per line)
         *   - "||ads.example.com^" (AdBlock-style — the domain is extracted)
         *   - comments starting with '#' or '!' are ignored; blank lines skipped
         *   - a bare "0.0.0.0"/"localhost"/"broadcasthost" with no domain is skipped
         *
         * [allowLines] is the user's allow-list (bare domains). Parsing is
         * total: a malformed line is skipped, never thrown.
         */
        fun build(blockedLines: Sequence<String>, allowLines: Sequence<String> = emptySequence()): DnsBlocklist {
            val blocked = HashSet<String>(1 shl 16)
            for (line in blockedLines) {
                extractDomain(line)?.let { blocked += it }
            }
            val allow = HashSet<String>()
            for (line in allowLines) {
                extractDomain(line)?.let { allow += it }
            }
            return DnsBlocklist(blocked, allow)
        }

        /** An empty blocklist (blocks nothing) — the safe default before a load. */
        fun empty(): DnsBlocklist = DnsBlocklist(HashSet(), HashSet())

        // Hostnames that appear in hosts files but are not block targets.
        private val NON_TARGETS = setOf(
            "localhost", "localhost.localdomain", "local", "broadcasthost",
            "ip6-localhost", "ip6-loopback", "0.0.0.0",
        )

        /**
         * Extract a normalized (lowercased, trailing-dot-stripped) domain from a
         * single blocklist line, or null if the line carries no usable domain.
         */
        fun extractDomain(rawLine: String): String? {
            var line = rawLine.trim()
            if (line.isEmpty()) return null
            if (line.startsWith('#') || line.startsWith('!')) return null

            // Strip inline comments.
            val hash = line.indexOf('#')
            if (hash >= 0) line = line.substring(0, hash).trim()
            if (line.isEmpty()) return null

            // AdBlock-style "||domain^" → domain.
            if (line.startsWith("||")) {
                line = line.removePrefix("||")
                val caret = line.indexOf('^')
                if (caret >= 0) line = line.substring(0, caret)
            }

            // Hosts format "IP domain [domain...]" → take the FIRST hostname token.
            val tokens = line.split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (tokens.isEmpty()) return null
            var domain = when {
                // First token looks like an IP → the domain is the second token.
                tokens.size >= 2 && looksLikeIp(tokens[0]) -> tokens[1]
                else -> tokens[0]
            }

            domain = domain.lowercase().trimEnd('.')
            if (domain.isEmpty()) return null
            if (domain in NON_TARGETS) return null
            // Must contain a dot (a TLD-only or bare word is not a block target)
            // and only host-legal characters.
            if (!domain.contains('.')) return null
            if (!domain.all { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' }) return null
            return domain
        }

        private fun looksLikeIp(s: String): Boolean =
            s == "0.0.0.0" || s == "127.0.0.1" || s == "::1" || s == "::" ||
                s.matches(Regex("\\d{1,3}(\\.\\d{1,3}){3}"))
    }
}
