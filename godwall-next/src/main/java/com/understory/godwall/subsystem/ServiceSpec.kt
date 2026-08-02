package com.understory.godwall.subsystem

/**
 * What one supervised process IS, declared as data — with no knowledge of what it does.
 *
 * ## Why a spec and not a class per daemon
 *
 * tor, i2pd, dnscrypt-proxy, dnsmasq, sing-box, v2ray and shadowsocks are the same shape:
 * an ELF in our prefix, a config file, a foreground process, and a localhost port that
 * something dials into. They differ in argv and in which port they answer on, and in
 * nothing else the supervisor cares about. Writing seven near-identical controller classes
 * would put seven copies of the "did it actually start?" question in the tree, and six of
 * them would eventually answer it wrong. So the lifecycle lives once, in [Supervisor], and
 * each service contributes only the facts that distinguish it.
 *
 * ## A spec is source code, not user input
 *
 * Every field here is written by the work package that owns the service, never by the user
 * and never by a config file. That matters because [Supervisor] launches through `sh -c`
 * (it has to: the privileged channel runs one argv to completion, so backgrounding a daemon
 * needs a shell), and a shell is an injection surface. Two defences, both required:
 * the supervisor quotes every interpolated value, and [validate] rejects ids and paths that
 * could escape the prefix. A malformed spec fails loudly at construction rather than
 * producing a service that half-works.
 *
 * ## The daemon MUST run in the foreground
 *
 * The supervisor records the pid the shell reports and supervises exactly that pid. A daemon
 * that double-forks (tor's `RunAsDaemon 1`, dnsmasq's default, dnscrypt-proxy's `-service`)
 * detaches from that pid immediately: the recorded process exits, the supervisor honestly
 * reports EXITED, and the real daemon is left running with nothing tracking it. That is the
 * worst of both worlds, so the rule is a contract, not a preference — put the daemon's
 * foreground flag in [args] or its no-daemonise setting in the config file.
 *
 * @param id stable, filename-safe identity. Becomes `run/<id>.pid` and `logs/<id>.log`.
 * @param label the name a user sees.
 * @param binary executable path relative to the prefix root, e.g. `usr/bin/tor`.
 * @param args argv after the binary. [PREFIX_TOKEN] and friends are expanded by [resolvedArgs].
 * @param env extra environment on top of the prefix environment the supervisor always sets.
 * @param workingDir working directory relative to the prefix root.
 * @param configs files that must exist in the prefix before this can start.
 * @param health what "running" means for this service beyond "the process is alive".
 * @param restart what to do when it exits on its own.
 * @param reach one sentence stating what this service actually reaches — shown verbatim in
 *   the UI. House rule: a security control states its boundary, so "routes DNS" is wrong
 *   where "answers name lookups on 127.0.0.1:5353 for traffic Godwall's tun carries" is
 *   right.
 */
data class ServiceSpec(
    val id: String,
    val label: String,
    val binary: String,
    val args: List<String> = emptyList(),
    val env: Map<String, String> = emptyMap(),
    val workingDir: String = "home",
    val configs: List<ServiceConfigFile> = emptyList(),
    val health: List<ServiceHealthProbe> = emptyList(),
    val restart: ServiceRestartPolicy = ServiceRestartPolicy.ON_FAILURE,
    val reach: String,
) {

    init {
        val problem = validate()
        require(problem == null) { "invalid ServiceSpec '$id': $problem" }
    }

    /** Prefix-relative path of the file holding this service's launched pid. */
    val pidPath: String get() = "run/$id.pid"

    /** Prefix-relative path of this service's combined stdout+stderr capture. */
    val logPath: String get() = "logs/$id.log"

    /**
     * [args] with the prefix tokens expanded against [prefixRoot].
     *
     * Tokens rather than shell variables because the supervisor single-quotes every argv
     * element before handing it to `sh -c` — a literal `$PREFIX` would arrive at the daemon
     * unexpanded, and un-quoting it to make the shell expand it would reopen the injection
     * surface the quoting exists to close. Expanding in Kotlin keeps both properties.
     */
    fun resolvedArgs(prefixRoot: String): List<String> = args.map { expand(it, prefixRoot) }

    /** [env] with the same token expansion applied to values. */
    fun resolvedEnv(prefixRoot: String): Map<String, String> =
        env.mapValues { (_, v) -> expand(v, prefixRoot) }

    /**
     * The problem with this spec, or null when it is well formed. Public because
     * [Supervisor.register] reports it rather than letting a bad spec reach the shell, and
     * because it is a pure function that can be exercised without a device.
     */
    fun validate(): String? = when {
        !ID_PATTERN.matches(id) ->
            "id must match ${ID_PATTERN.pattern} — it becomes a pid and log filename"
        label.isBlank() -> "label is blank"
        reach.isBlank() -> "reach is blank; every control must state what it reaches"
        !isSafeRelPath(binary) -> "binary '$binary' must be a prefix-relative path with no '..'"
        !isSafeRelPath(workingDir) -> "workingDir '$workingDir' must be prefix-relative, no '..'"
        env.keys.any { !ENV_NAME_PATTERN.matches(it) } ->
            "environment names must match ${ENV_NAME_PATTERN.pattern}"
        configs.firstOrNull { !isSafeRelPath(it.destination) } != null ->
            "config destination must be a prefix-relative path with no '..'"
        health.filterIsInstance<ServiceHealthProbe.PrefixFile>()
            .any { !isSafeRelPath(it.relPath) } ->
            "health file probe must name a prefix-relative path with no '..'"
        health.filterIsInstance<ServiceHealthProbe.LocalPort>()
            .any { it.port !in 1..65535 } -> "health port must be in 1..65535"
        else -> null
    }

    companion object {
        /** Expands to the prefix root, `/data/local/tmp/godwall`. */
        const val PREFIX_TOKEN = "{PREFIX}"

        /** Expands to the Termux-style `usr` tree inside the prefix. */
        const val USR_TOKEN = "{USR}"

        /** Expands to the prefix's home directory — services run with `HOME` set to it. */
        const val HOME_TOKEN = "{HOME}"

        /** Expands to the prefix's scratch directory — services run with `TMPDIR` set to it. */
        const val TMP_TOKEN = "{TMP}"

        private val ID_PATTERN = Regex("[a-z0-9][a-z0-9._-]{0,63}")
        private val ENV_NAME_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]{0,63}")

        private fun expand(value: String, prefixRoot: String): String = value
            .replace(USR_TOKEN, "$prefixRoot/usr")
            .replace(HOME_TOKEN, "$prefixRoot/home")
            .replace(TMP_TOKEN, "$prefixRoot/tmp")
            .replace(PREFIX_TOKEN, prefixRoot)

        /**
         * A path is usable inside the prefix only when it stays inside the prefix. Absolute
         * paths and `..` segments are refused outright rather than normalised, because the
         * supervisor would otherwise happily chmod +x or truncate something in `/system`.
         */
        fun isSafeRelPath(path: String): Boolean {
            if (path.isBlank() || path.startsWith('/')) return false
            val parts = path.split('/')
            return parts.none { it.isEmpty() || it == "." || it == ".." }
        }
    }
}

/**
 * A pre-configured file this service needs, shipped as an app asset.
 *
 * Rule C of the charter — every backend ships with working defaults — lives here. The
 * service's real torrc / dnscrypt-proxy.toml / sing-box.json is an asset in the APK, and the
 * installer copies it into the prefix on first start.
 *
 * @param asset path inside the APK's `assets/`, e.g. `subsystem/torrc`.
 * @param destination prefix-relative destination, e.g. `usr/etc/tor/torrc`.
 * @param overwrite false (the default) means an existing file is left alone. This is what
 *   makes an Advanced surface's raw edit survive a restart: the shipped default seeds the
 *   file once, and after that the file on disk is authoritative.
 */
data class ServiceConfigFile(
    val asset: String,
    val destination: String,
    val overwrite: Boolean = false,
)

/**
 * An observation that must hold before a live process is reported as RUNNING.
 *
 * "The process is alive" is checked for every service and is not expressible here — it is
 * the floor, not a probe. These are the additional facts that distinguish "tor is running"
 * from "tor is sitting in a restart loop with its SOCKS port closed".
 */
sealed interface ServiceHealthProbe {

    /**
     * A TCP connect to `127.0.0.1:[port]` succeeds.
     *
     * Checked by Godwall's own process, with no privileged shell involved: loopback is
     * shared across uids on Android, which is the same property that lets the tun handler
     * dial these daemons in the first place. A socket dialer needs no elevation — that is
     * the load-bearing insight of the whole subsystem, and this probe is its cheapest proof.
     *
     * @param note what answers on that port, for the status line.
     */
    data class LocalPort(val port: Int, val note: String) : ServiceHealthProbe

    /** A path exists inside the prefix — a unix socket, a control cookie, a state file. */
    data class PrefixFile(val relPath: String) : ServiceHealthProbe

    /**
     * A fixed string appears in the service's captured output. Matched with `grep -F`, so
     * [text] is a literal, never a pattern — a spec author should not have to think about
     * which regex dialect Android's grep speaks.
     */
    data class LogContains(val text: String) : ServiceHealthProbe
}

/**
 * What to do when a service exits without being asked to.
 *
 * The cap exists so a service that cannot start — a missing library, a config the daemon
 * rejects, a port already bound — ends in a state the user can read, rather than an
 * invisible loop that burns battery and keeps claiming STARTING. Exhausting the budget is
 * itself a reported state ([ServicePhase.GAVE_UP]), not a silent stop.
 */
data class ServiceRestartPolicy(
    val maxConsecutiveRestarts: Int,
    val initialBackoffMs: Long = 2_000L,
    val maxBackoffMs: Long = 60_000L,
) {

    val enabled: Boolean get() = maxConsecutiveRestarts > 0

    /**
     * Delay before restart number [attempt] (1-based). Doubles each time and clamps at
     * [maxBackoffMs]. Pure, so the escalation can be checked without waiting for it.
     */
    fun backoffMs(attempt: Int): Long {
        if (attempt <= 1) return initialBackoffMs
        // Shift, not pow: 1L shl 40 would overflow the useful range long before the clamp
        // is reached, so the exponent is bounded before it is applied.
        val steps = (attempt - 1).coerceAtMost(20)
        val scaled = initialBackoffMs shl steps
        return if (scaled <= 0L || scaled > maxBackoffMs) maxBackoffMs else scaled
    }

    companion object {
        /** Never restart. For anything a user starts deliberately and expects to stay stopped. */
        val NEVER = ServiceRestartPolicy(maxConsecutiveRestarts = 0)

        /** The default: five consecutive restarts, then report GAVE_UP with the last log lines. */
        val ON_FAILURE = ServiceRestartPolicy(maxConsecutiveRestarts = 5)
    }
}

/**
 * The states a supervised service can be in. Kept deliberately wide, because collapsing them
 * is how a subsystem starts lying: "alive but its port is closed" and "alive and answering"
 * are different facts and the user is entitled to both.
 */
enum class ServicePhase {

    /**
     * The service cannot exist here — the prefix is not installed, or the prefix is
     * installed and does not contain this binary. Its control renders disabled.
     */
    ABSENT,

    /** Not running, and not meant to be. */
    STOPPED,

    /** Launched, pid recorded, health not yet confirmed. Never reported as working. */
    STARTING,

    /** Process alive, identity confirmed against /proc, and every health probe passed. */
    RUNNING,

    /**
     * Process alive but a health probe failed — it is up and not doing its job. Distinct
     * from RUNNING on purpose; a proxy whose listener never bound would otherwise show green.
     */
    UNHEALTHY,

    /** It was running and the process is gone. Awaiting restart, or final if the policy says so. */
    EXITED,

    /** The launch itself failed. [ServiceStatus.detail] carries the reason and the log tail. */
    FAILED,

    /** Restarted up to the policy's cap and kept dying. Terminal until a user starts it again. */
    GAVE_UP,

    /**
     * State is genuinely unobservable — no privileged shell is attached, so nothing in
     * `/data/local/tmp/godwall` can be read. Not "stopped": we do not know, and saying
     * "stopped" would be a claim we cannot support.
     */
    UNKNOWN,
}

/**
 * The reported state of one service. Every field is an observation or a count of
 * observations; nothing here is derived from what the user last tapped.
 */
data class ServiceStatus(
    val id: String,
    val phase: ServicePhase,
    /** The pid being supervised, or 0 when there is none. */
    val pid: Int = 0,
    /** One honest sentence: why it is in this phase, including the daemon's own last words. */
    val detail: String = "",
    /** Wall-clock millis when this phase began; 0 when it has never left its initial phase. */
    val sinceMs: Long = 0L,
    /** Consecutive unrequested restarts since it was last confirmed healthy. */
    val restarts: Int = 0,
) {
    /** True only for [ServicePhase.RUNNING] — the single place "it works" is decided. */
    val healthy: Boolean get() = phase == ServicePhase.RUNNING

    /** True while a process exists, healthy or not. */
    val hasProcess: Boolean get() =
        phase == ServicePhase.RUNNING || phase == ServicePhase.UNHEALTHY ||
            phase == ServicePhase.STARTING
}
