package com.understory.godwall.privileged

import com.understory.security.Diagnostics
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * A fail2ban-class banning engine, driven from Godwall's OWN logs.
 *
 * ## What it is
 *
 * fail2ban watches a service's log, counts failures from an address inside a sliding window, and
 * bans the address for a while once the count crosses a threshold. This is that, in-process and
 * rootless: a [Jail] holds the policy (how many failures, over what window, for how long, and a
 * regex that lifts the offending address out of a log line), [feed] runs a log line past the jails,
 * and a crossing produces a [BanEntry] with an expiry. The set of currently-active bans is a
 * [StateFlow] a surface can render and a backend can enforce.
 *
 * The log lines are Godwall's own — WP-7's LAN-defence detections (ARP anomaly, rogue DHCP, port
 * scans), the supervisor's daemon output, the DNS event log's rebinding hits. Nothing here reads a
 * system log it has no right to; a caller feeds it lines it already holds. That is the honest reach:
 * this bans on evidence Godwall itself produced.
 *
 * ## What it does NOT do by itself
 *
 * Computing a ban and ENFORCING it are different privileges. The ban set here is real and
 * observable — you can see who is banned, by which jail, until when, and why. Turning a ban into a
 * dropped packet needs an enforcement backend: the host netfilter tier ([NetfilterBackend], which
 * needs root and is honestly gated), or the userspace packet data plane over the tun
 * ([PacketFilterBridge], gated on firestack). So this engine is the DETECTION half, always real; the
 * ENFORCEMENT half reports its own state and never claims a drop it cannot make. A ban list that
 * silently enforces nothing while looking armed is the dead control this campaign removes, so the
 * two halves are kept visibly distinct.
 *
 * ## Purity where it counts
 *
 * The window/threshold decision ([Jail.wouldBan]) is a pure function of a timestamp list, so it is
 * testable off-device with a synthetic clock. The engine holds the mutable history and ban map
 * behind a lock and takes its clock as an injectable lambda, so a test drives time forward without
 * sleeping and production passes `System::currentTimeMillis`.
 */
class BanEngine(
    private val clock: () -> Long = System::currentTimeMillis,
) {

    companion object {
        private const val TAG = "godwall.privileged.BanEngine"

        /** A history longer than this per jail+address is pruned to the window on every touch. */
        private const val MAX_HISTORY_PER_KEY = 64

        /** The jail name a manual or caller-supplied ban is attributed to. */
        const val MANUAL_JAIL = "manual"

        /** A very permissive address check, matching what [HostFirewallRule] renders into a rule. */
        fun isAddress(value: String): Boolean {
            val bare = value.substringBefore('/')
            return HostFirewallRule.isCidr(HostFirewallTable.defaultHostCidr(bare)) || HostFirewallRule.isCidr(value)
        }
    }

    /** Guards [jails], [history] and [active]; every mutation is a short in-memory critical section. */
    private val lock = Any()

    /** Configured jails, by name. */
    private val jails = LinkedHashMap<String, Jail>()

    /** Failure timestamps per "<jail>|<address>", trimmed to each jail's findTime on touch. */
    private val history = HashMap<String, ArrayDeque<Long>>()

    /** Active bans by address; the newest ban for an address supersedes an older, shorter one. */
    private val active = HashMap<String, BanEntry>()

    private val _bans = MutableStateFlow<List<BanEntry>>(emptyList())

    /** The currently-active bans, newest first. Written only from observations, never from intent. */
    val bans: StateFlow<List<BanEntry>> = _bans

    // ---- Configuration -----------------------------------------------------------------

    /**
     * Replace the jail set. Idempotent; re-configuring with the same jails keeps existing history and
     * bans, so editing one jail's threshold does not pardon everyone already banned.
     */
    fun configure(newJails: List<Jail>) {
        synchronized(lock) {
            jails.clear()
            for (j in newJails) jails[j.name] = j
            Diagnostics.log(TAG, "configured ${jails.size} jail(s): ${jails.keys.joinToString()}")
        }
    }

    fun jails(): List<Jail> = synchronized(lock) { jails.values.toList() }

    // ---- Detection ---------------------------------------------------------------------

    /**
     * Run one log line past a named jail. Returns the [BanEntry] if this line pushed the address over
     * the threshold, or null otherwise (no match, or not yet enough failures). Pure of I/O; it only
     * touches in-memory state. Blocking on nothing.
     *
     * The address is extracted by the jail's pattern; a line that does not match contributes nothing,
     * which is how a jail ignores log noise it is not watching for.
     */
    fun feed(jailName: String, line: String): BanEntry? {
        val now = clock()
        synchronized(lock) {
            val jail = jails[jailName] ?: return null
            val address = jail.extractAddress(line) ?: return null
            if (address in active) {
                // Already banned; refresh nothing here — a re-offence inside a ban does not extend it,
                // matching fail2ban's default. Expiry is honoured in [sweep].
                return null
            }
            val key = "$jailName|$address"
            val deque = history.getOrPut(key) { ArrayDeque() }
            deque.addLast(now)
            trim(deque, now - jail.findTimeMs)
            if (deque.size > MAX_HISTORY_PER_KEY) {
                while (deque.size > MAX_HISTORY_PER_KEY) deque.removeFirst()
            }
            if (deque.size < jail.maxRetry) return null

            val entry = BanEntry(
                address = address,
                jail = jailName,
                bannedAtMs = now,
                expiresAtMs = now + jail.banTimeMs,
                reason = "$jailName: ${deque.size} failure(s) within ${jail.findTimeMs / 1000}s",
            )
            active[address] = entry
            history.remove(key) // a banned address starts its next window clean
            Diagnostics.log(TAG, "ban ${entry.address} by $jailName until ${entry.expiresAtMs}")
            publishLocked(now)
            return entry
        }
    }

    /**
     * Ban an address directly, bypassing the jails — used for a manual block from the UI, or for a
     * detection a caller has already made. [reason] is shown verbatim, so it should name why.
     */
    fun ban(address: String, banTimeMs: Long, reason: String): BanEntry? {
        if (!isAddress(address)) {
            Diagnostics.warn(TAG, "refused manual ban of non-address '$address'")
            return null
        }
        val now = clock()
        synchronized(lock) {
            val entry = BanEntry(
                address = address,
                jail = MANUAL_JAIL,
                bannedAtMs = now,
                expiresAtMs = now + banTimeMs.coerceAtLeast(0L),
                reason = reason,
            )
            active[address] = entry
            publishLocked(now)
            return entry
        }
    }

    /** Lift a ban early. Returns true if the address was banned. */
    fun pardon(address: String): Boolean {
        synchronized(lock) {
            val removed = active.remove(address) != null
            if (removed) {
                Diagnostics.log(TAG, "pardoned $address")
                publishLocked(clock())
            }
            return removed
        }
    }

    /** Drop every ban. For an enforcement teardown, so a stale ban set does not outlive the tier. */
    fun clear() {
        synchronized(lock) {
            active.clear()
            history.clear()
            publishLocked(clock())
        }
    }

    // ---- Observation -------------------------------------------------------------------

    /**
     * Remove expired bans and republish. Idempotent — a caller ticks this on a timer so bans lift on
     * their own. Returns the addresses whose bans just expired, so an enforcement backend can remove
     * exactly those rules rather than rebuilding the whole set.
     */
    fun sweep(): List<String> {
        val now = clock()
        synchronized(lock) {
            val expired = active.filterValues { it.expiresAtMs <= now }.keys.toList()
            if (expired.isNotEmpty()) {
                expired.forEach { active.remove(it) }
                Diagnostics.log(TAG, "swept ${expired.size} expired ban(s)")
                publishLocked(now)
            }
            return expired
        }
    }

    /** A snapshot of the active bans, newest first. Blocking on nothing. */
    fun snapshot(): List<BanEntry> = synchronized(lock) { activeSortedLocked(clock()) }

    /** The addresses to enforce right now, as bare address strings. */
    fun bannedAddresses(): List<String> = synchronized(lock) {
        val now = clock()
        active.values.filter { it.expiresAtMs > now }.map { it.address }
    }

    private fun activeSortedLocked(now: Long): List<BanEntry> =
        active.values.filter { it.expiresAtMs > now }.sortedByDescending { it.bannedAtMs }

    private fun publishLocked(now: Long) {
        _bans.value = activeSortedLocked(now)
    }

    private fun trim(deque: ArrayDeque<Long>, cutoff: Long) {
        while (deque.isNotEmpty() && deque.first() < cutoff) deque.removeFirst()
    }
}

/**
 * One fail2ban jail: the policy for turning repeated failures from an address into a ban.
 *
 * @param name stable identity, also the attribution shown in a ban's reason.
 * @param maxRetry failures within [findTimeMs] that trigger a ban.
 * @param findTimeMs the sliding window, in milliseconds.
 * @param banTimeMs how long a ban lasts, in milliseconds.
 * @param pattern a regex whose FIRST capturing group is the offending address. Held as a compiled
 *   [Regex]; a jail with a pattern that has no capturing group can never ban and is refused at
 *   construction, because a jail that cannot extract an address is a jail that silently does nothing.
 */
data class Jail(
    val name: String,
    val maxRetry: Int,
    val findTimeMs: Long,
    val banTimeMs: Long,
    val pattern: Regex,
) {

    init {
        require(name.isNotBlank()) { "jail name is blank" }
        require(maxRetry >= 1) { "jail '$name' maxRetry must be >= 1" }
        require(findTimeMs > 0) { "jail '$name' findTime must be > 0" }
        require(banTimeMs > 0) { "jail '$name' banTime must be > 0" }
        // A jail whose pattern captures nothing can match lines forever and never produce an address:
        // the exact silent no-op the campaign forbids. Refuse it at construction.
        require(pattern.toPattern().matcher("").groupCount() >= 1) {
            "jail '$name' pattern has no capturing group for the address"
        }
    }

    /**
     * The offending address in [line], or null when the line does not match. The captured group is
     * validated as an address so a mis-written pattern that captures a hostname or a word cannot inject
     * junk into a rule; a non-address capture is treated as no match.
     */
    fun extractAddress(line: String): String? {
        val m = pattern.find(line) ?: return null
        val captured = m.groupValues.getOrNull(1)?.trim().orEmpty()
        if (captured.isEmpty()) return null
        return if (BanEngine.isAddress(captured)) captured else null
    }

    /**
     * Pure predicate: would [failureTimestamps] trip this jail, evaluated at [now]? Counts the
     * timestamps inside the window and compares to [maxRetry]. Extracted so the threshold logic is
     * testable without the engine's state.
     */
    fun wouldBan(failureTimestamps: List<Long>, now: Long): Boolean =
        failureTimestamps.count { it >= now - findTimeMs } >= maxRetry
}

/**
 * One active ban. Every field is an observation: who, by which jail, when it started, when it lifts,
 * and one sentence naming why. Rendered by a surface and enforced by a backend; carries no UI state.
 */
data class BanEntry(
    val address: String,
    val jail: String,
    val bannedAtMs: Long,
    val expiresAtMs: Long,
    val reason: String,
) {
    /** Milliseconds remaining at [now], never negative. */
    fun remainingMs(now: Long): Long = (expiresAtMs - now).coerceAtLeast(0L)
}
