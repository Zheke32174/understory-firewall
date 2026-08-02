package com.understory.godwall.privileged

import com.understory.security.Diagnostics

/**
 * Parses the shipped `fail2ban.jails` asset — an INI-shaped jail definition, the same shape fail2ban
 * itself uses — into [Jail]s the [BanEngine] runs, and carries the built-in defaults.
 *
 * ## Why a config file and not hard-coded jails
 *
 * Charter rule C: every backend ships with a working default, and the user does not have to configure
 * it. So [DEFAULT_JAILS_ASSET] is a real, pre-written set of jails covering the log sources Godwall
 * itself produces, and [defaults] is the same set as code for when the asset cannot be read. The
 * Advanced surface (WP-9) can hand this parser the edited asset text; the engine takes whatever parses
 * and reports what did not, rather than failing the whole file on one bad line.
 *
 * ## The honesty in the pattern field
 *
 * A jail bans on evidence, and the evidence is a log line's shape. The patterns here match Godwall's
 * OWN log formats as they stand; a donor's fail2ban filter is written against that donor's daemon
 * output, and ours is written against ours. Where a sibling package's log format is not yet fixed, the
 * jail is shipped disabled-by-omission from the enforcement path — it parses, it is visible, and it
 * bans nothing until its pattern matches real lines, which is stated in the asset rather than hidden.
 */
object JailConfig {

    private const val TAG = "godwall.privileged.JailConfig"

    /** Where the shipped default jails live in the APK. Read by [com.understory.godwall.privileged]. */
    const val ASSET = "subsystem/fail2ban.jails"

    /**
     * Parse INI-shaped jail text. Unknown keys are ignored, a malformed jail is skipped with a log
     * line rather than aborting the file, and a jail missing a required field is skipped — so a
     * hand-edited file with one mistake still yields every jail that is well formed.
     */
    fun parse(text: String): List<Jail> {
        val jails = ArrayList<Jail>()
        var name: String? = null
        val fields = HashMap<String, String>()

        fun flush() {
            val jailName = name ?: return
            val jail = build(jailName, fields)
            if (jail != null) jails.add(jail)
            fields.clear()
        }

        for (raw in text.lineSequence()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue
            if (line.startsWith('[') && line.endsWith(']')) {
                flush()
                name = line.substring(1, line.length - 1).trim()
                continue
            }
            val eq = line.indexOf('=')
            if (eq <= 0) continue
            val key = line.substring(0, eq).trim().lowercase()
            val value = line.substring(eq + 1).trim()
            fields[key] = value
        }
        flush()
        Diagnostics.log(TAG, "parsed ${jails.size} jail(s)")
        return jails
    }

    private fun build(name: String, fields: Map<String, String>): Jail? {
        val maxRetry = fields["maxretry"]?.toIntOrNull()
        val findTime = fields["findtime"]?.toLongOrNull()
        val banTime = fields["bantime"]?.toLongOrNull()
        val pattern = fields["pattern"]
        if (maxRetry == null || findTime == null || banTime == null || pattern.isNullOrBlank()) {
            Diagnostics.warn(TAG, "jail '$name' is missing a required field; skipped")
            return null
        }
        return try {
            Jail(
                name = name,
                maxRetry = maxRetry,
                // findtime/bantime are in SECONDS in the file, as in fail2ban; the engine wants millis.
                findTimeMs = findTime * 1000L,
                banTimeMs = banTime * 1000L,
                pattern = Regex(pattern),
            )
        } catch (e: Exception) {
            // A bad regex, a zero threshold, or a pattern with no capturing group all land here as a
            // construction failure; skip the one jail and keep the rest rather than lose the file.
            Diagnostics.warn(TAG, "jail '$name' rejected: ${e.message}")
            null
        }
    }

    /**
     * The built-in default jails, identical to [DEFAULT_JAILS_ASSET]. Used when the asset cannot be
     * read (no such asset in this build, or an I/O error), so the ban engine is never left jail-less
     * for a reason the user cannot see.
     */
    fun defaults(): List<Jail> = parse(DEFAULT_JAILS_ASSET)

    /**
     * The shipped default jail set as text, kept beside the asset so the two cannot silently diverge:
     * `assets/subsystem/fail2ban.jails` is written from this string. A capturing group `(...)` lifts
     * the offending IP out of each line; every findtime/bantime is in seconds.
     */
    val DEFAULT_JAILS_ASSET: String = """
        # Godwall fail2ban-class jails — banning driven from Godwall's OWN logs.
        #
        # Each jail: maxretry failures matching `pattern` within findtime (seconds) bans the captured
        # address for bantime (seconds). The FIRST (capturing group) must be the offending IP.
        #
        # These patterns match Godwall's own log formats. Enforcement of a ban needs the host netfilter
        # tier (root) or the userspace packet data plane (firestack) — the ban set is computed either
        # way and shown; whether it drops packets depends on which backend is live.

        # DNS rebinding hits from the DNS event log (Godwall's resolver blocked a rebinding answer).
        [dns-rebind]
        maxretry = 1
        findtime = 600
        bantime  = 3600
        pattern  = rebinding.*answer ([0-9]{1,3}(?:\.[0-9]{1,3}){3})

        # Rogue DHCP servers flagged by LAN defence.
        [dhcp-rogue]
        maxretry = 1
        findtime = 300
        bantime  = 7200
        pattern  = rogue DHCP.*server ([0-9]{1,3}(?:\.[0-9]{1,3}){3})

        # Port-scan sources caught by the LAN port-deception listener.
        [port-scan]
        maxretry = 3
        findtime = 120
        bantime  = 1800
        pattern  = port scan.*from ([0-9]{1,3}(?:\.[0-9]{1,3}){3})

        # Repeated connection failures against a supervised daemon's loopback listener.
        [daemon-abuse]
        maxretry = 5
        findtime = 300
        bantime  = 600
        pattern  = auth fail.*from ([0-9]{1,3}(?:\.[0-9]{1,3}){3})
    """.trimIndent()
}
