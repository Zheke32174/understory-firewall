package com.understory.godwall.subsystem

import android.content.Context
import com.understory.godwall.privilege.Privilege
import com.understory.security.Diagnostics
import com.understory.security.ui.Bg
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * Per-service lifecycle for everything that runs out of Godwall's prefix: start, stop, health,
 * output capture, restart-on-death, and — the part that matters — a reported state that is an
 * observation rather than an intention.
 *
 * ## What this is not
 *
 * There is no service logic here. The supervisor does not know what a resolver is, what a SOCKS
 * port is for, or which of its processes is Tor. It takes [ServiceSpec]s from the work packages
 * that own those daemons and runs them. That separation is the reason it can be strict: every
 * question it answers ("is it alive?", "did its port bind?") is answerable without knowing what
 * the daemon does, so there is no place for a special case that quietly assumes success.
 *
 * ## Why launching needs a shell, and what stops that being an injection surface
 *
 * `IPrivilegedShell.exec` runs one argv **to completion** and hands back its output. That is
 * the right shape for `cmd connectivity set-package-networking-enabled`; it is the wrong shape
 * for a daemon, which would simply hold the binder call open until the timeout. So a daemon is
 * launched by `sh -c` that backgrounds it, records `$!` and returns — the daemon is orphaned to
 * init and keeps running after the shell exits.
 *
 * Reintroducing a shell reintroduces command injection, so every interpolated value goes
 * through [PrefixInstaller.quote], and [ServiceSpec] refuses ids and paths that could escape
 * the prefix. Nothing a user types ever reaches this script: argv comes from a spec, which is
 * source code. The user-editable surface is the daemon's *config file*, which the daemon
 * parses, not the shell.
 *
 * ## Why the pid is checked against /proc/<pid>/cmdline
 *
 * A recorded pid is only meaningful while it still belongs to the process we launched. Linux
 * reuses pids, and a supervisor that only asks "does this pid exist?" will eventually report a
 * dead daemon as RUNNING because some unrelated process inherited its number. Every liveness
 * check therefore reads the process's own cmdline and confirms our binary path is in it. A
 * mismatch is treated exactly like death.
 *
 * ## What the supervisor cannot do, stated rather than hidden
 *
 * - It supervises exactly the pid the shell reported. A daemon that double-forks detaches from
 *   that pid; the spec's contract is that daemons run in the foreground (see [ServiceSpec]).
 * - It kills that pid only, never a process group: the group id of a shell spawned by Yojimbo
 *   is not ours to signal, and a group kill aimed at the wrong group takes Yojimbo's server
 *   with it.
 * - With no privileged shell attached it reports [ServicePhase.UNKNOWN], not "stopped". A
 *   subsystem that says "stopped" when it cannot see is the same failure as one that says
 *   "running" when it cannot see.
 */
object Supervisor {

    private const val TAG = "godwall.subsystem.Supervisor"

    /** How often the watchdog re-observes every service. */
    private const val TICK_MS = 5_000L

    /** Ceiling on [logTail] so a runaway log cannot be pulled through the binder in one call. */
    private const val MAX_LOG_LINES = 500

    /** Connect timeout for a [ServiceHealthProbe.LocalPort] probe. Loopback, so this is generous. */
    private const val PORT_PROBE_TIMEOUT_MS = 750

    private val specs = ConcurrentHashMap<String, ServiceSpec>()
    private val tracks = ConcurrentHashMap<String, Track>()

    /** All supervisor mutations serialise here: they are blocking calls, so this costs nothing. */
    private val lock = Any()

    private val _statuses = MutableStateFlow<Map<String, ServiceStatus>>(emptyMap())

    /** Live state of every registered service. Written only from observations. */
    val statuses: StateFlow<Map<String, ServiceStatus>> = _statuses

    private val scope = CoroutineScope(Bg.io + SupervisorJob())

    @Volatile
    private var watchdog: Job? = null

    /** Mutable bookkeeping for one service. Guarded by [lock]. */
    private class Track {
        /** True when the user (or an engine) asked for this to be running. */
        var desired = false
        var phase = ServicePhase.STOPPED
        var pid = 0
        var detail = ""
        var sinceMs = 0L
        var restarts = 0
        var nextRestartAtMs = 0L
    }

    // ---- Registration ------------------------------------------------------------------

    /**
     * Make [spec] known to the supervisor. Returns false and logs when the spec is malformed,
     * rather than letting a bad path reach the privileged shell.
     *
     * Re-registering the same id replaces the spec — which is how a service whose argv depends
     * on user configuration (a chosen port, a chosen bridge) is updated. The running process is
     * not touched; the new spec applies at the next start.
     */
    fun register(spec: ServiceSpec): Boolean {
        val problem = spec.validate()
        if (problem != null) {
            Diagnostics.error(TAG, "refused spec '${spec.id}': $problem")
            return false
        }
        synchronized(lock) {
            specs[spec.id] = spec
            tracks.getOrPut(spec.id) { Track() }
            publish()
        }
        Diagnostics.log(TAG, "registered service '${spec.id}'")
        return true
    }

    /** Forget a service. Does not stop it — call [stop] first if that is what you meant. */
    fun unregister(id: String) {
        synchronized(lock) {
            specs.remove(id)
            tracks.remove(id)
            publish()
        }
    }

    fun specs(): List<ServiceSpec> = specs.values.sortedBy { it.id }

    fun spec(id: String): ServiceSpec? = specs[id]

    /** Last observed status for [id]; UNKNOWN when nothing has been observed yet. */
    fun status(id: String): ServiceStatus =
        _statuses.value[id] ?: ServiceStatus(id, ServicePhase.UNKNOWN)

    // ---- Availability ------------------------------------------------------------------

    /**
     * Whether the substrate these services need exists at all. Blocking — call off the main
     * thread. Delegates to [PrefixInstaller] rather than keeping a second opinion about it.
     */
    fun substrate(context: Context): PrefixInstaller.State = PrefixInstaller.state(context)

    /** True only when a service could actually be started right now. Blocking. */
    fun ready(context: Context): Boolean = substrate(context) == PrefixInstaller.State.INSTALLED

    /**
     * The sentence a disabled subsystem control shows. Blocking.
     *
     * A stale prefix gets its own refusal: its binaries are a previous build's, and starting
     * them would put the user in a state where the version on screen is not the version
     * running.
     */
    fun explain(context: Context): String = explainFor(context, substrate(context))

    /** [explain] for a substrate state already in hand, so callers do not re-probe for it. */
    private fun explainFor(context: Context, state: PrefixInstaller.State): String {
        val base = PrefixInstaller.explain(context, state)
        return when (state) {
            PrefixInstaller.State.INSTALLED -> base
            PrefixInstaller.State.STALE -> "$base No subsystem service will be started from it."
            else -> "$base No subsystem service can be started."
        }
    }

    // ---- Lifecycle ---------------------------------------------------------------------

    /**
     * Start one service. Blocking — call off the main thread.
     *
     * Installs the spec's shipped default configs first (existing files are left alone, so an
     * edited config survives), launches the daemon, then immediately re-observes so the
     * returned status is a measurement and not an assumption. A daemon that exits inside the
     * settle window comes back as [ServicePhase.FAILED] carrying its own last output.
     */
    fun start(context: Context, id: String): ServiceStatus =
        synchronized(lock) { startLocked(context, id) }

    private fun startLocked(context: Context, id: String): ServiceStatus {
        val spec = specs[id]
            ?: return ServiceStatus(id, ServicePhase.UNKNOWN, detail = "No service '$id' is registered.")
        val track = tracks.getOrPut(id) { Track() }

        val substrate = substrate(context)
        if (substrate != PrefixInstaller.State.INSTALLED) {
            return set(track, spec, phaseFor(substrate), 0, explainFor(context, substrate))
        }

        for (config in spec.configs) {
            val report = PrefixInstaller.installConfig(context, config)
            if (!report.ok) {
                return set(track, spec, ServicePhase.FAILED, 0, report.message)
            }
        }

        track.desired = true
        track.restarts = 0
        track.nextRestartAtMs = 0L
        val launched = launch(spec)
        if (!launched.ok) {
            return set(track, spec, ServicePhase.FAILED, 0, launched.detail)
        }
        set(track, spec, ServicePhase.STARTING, launched.pid, "Launched as pid ${launched.pid}; confirming.")
        // Resolve STARTING into a real phase before returning: a caller that gets STARTING back
        // has to poll, and every caller polling differently is how "it says starting forever"
        // bugs happen.
        observeLocked(context)
        return status(id)
    }

    /**
     * Stop one service and stop wanting it. Blocking.
     *
     * SIGTERM, five seconds of grace, then SIGKILL. The grace matters: tor writes its state
     * file on shutdown, and killing it outright loses the guard set it had chosen.
     */
    fun stop(id: String): ServiceStatus = synchronized(lock) { stopLocked(id) }

    private fun stopLocked(id: String): ServiceStatus {
        val spec = specs[id]
            ?: return ServiceStatus(id, ServicePhase.UNKNOWN, detail = "No service '$id' is registered.")
        val track = tracks.getOrPut(id) { Track() }
        track.desired = false
        track.nextRestartAtMs = 0L
        track.restarts = 0

        if (!Privilege.isAvailable()) {
            return set(track, spec, ServicePhase.UNKNOWN, 0, NO_SHELL_DETAIL)
        }
        val r = PrefixInstaller.exec(stopScript(spec), timeoutMs = 30_000L)
        val line = r.out.lineSequence().firstOrNull { it.isNotBlank() }?.trim().orEmpty()
        return when {
            !r.ok -> set(track, spec, ServicePhase.UNKNOWN, track.pid, "Could not signal ${spec.label}: ${r.summary()}")
            line.startsWith("ALIVE") -> set(
                track, spec, ServicePhase.UNHEALTHY, track.pid,
                "${spec.label} did not exit after SIGTERM and SIGKILL. It is still running.",
            )
            else -> set(track, spec, ServicePhase.STOPPED, 0, "${spec.label} is stopped.")
        }
    }

    /** Stop, then start. Blocking. Resets the restart budget, because the user asked for this. */
    fun restart(context: Context, id: String): ServiceStatus = synchronized(lock) {
        stopLocked(id)
        startLocked(context, id)
    }

    /** Stop every service that is meant to be running. Blocking. For engine teardown. */
    fun stopAll() {
        synchronized(lock) {
            for (id in specs.keys.sorted()) stopLocked(id)
        }
    }

    // ---- Observation -------------------------------------------------------------------

    /**
     * One supervision pass: re-observe every registered service, publish the result, and act on
     * the restart policy. Blocking — call off the main thread.
     *
     * This is the only place a service is promoted to [ServicePhase.RUNNING], and it does that
     * only after the process was found alive, its identity confirmed, and every health probe
     * passed.
     */
    fun observe(context: Context): Map<String, ServiceStatus> =
        synchronized(lock) { observeLocked(context) }

    private fun observeLocked(context: Context): Map<String, ServiceStatus> {
        val all = specs.values.sortedBy { it.id }
        if (all.isEmpty()) {
            publish()
            return _statuses.value
        }
        if (!Privilege.isAvailable()) {
            for (spec in all) {
                val track = tracks.getOrPut(spec.id) { Track() }
                set(track, spec, ServicePhase.UNKNOWN, 0, NO_SHELL_DETAIL, publish = false)
            }
            publish()
            return _statuses.value
        }

        val liveness = readLiveness(all)
        val shellProbes = readShellProbes(all)
        val now = System.currentTimeMillis()

        for (spec in all) {
            val track = tracks.getOrPut(spec.id) { Track() }
            when (val live = liveness[spec.id]) {
                null -> set(
                    track, spec, ServicePhase.UNKNOWN, 0,
                    "The privileged shell did not report on ${spec.label}.", publish = false,
                )

                is Live.NoBinary -> {
                    track.desired = false
                    set(
                        track, spec, ServicePhase.ABSENT, 0,
                        "${spec.binary} is not in the installed userland, so ${spec.label} " +
                            "cannot run. Its control stays disabled.",
                        publish = false,
                    )
                }

                is Live.Running -> {
                    val failed = failedProbes(spec, live.pid, shellProbes)
                    if (failed.isEmpty()) {
                        track.restarts = 0
                        track.nextRestartAtMs = 0L
                        set(track, spec, ServicePhase.RUNNING, live.pid, runningDetail(spec, live.pid), publish = false)
                    } else {
                        set(
                            track, spec, ServicePhase.UNHEALTHY, live.pid,
                            "${spec.label} is running as pid ${live.pid} but ${failed.joinToString("; ")}. " +
                                "It is not doing its job, so it is not reported as working.",
                            publish = false,
                        )
                    }
                }

                is Live.Gone -> handleGone(context, spec, track, live, now)
            }
        }
        publish()
        return _statuses.value
    }

    /**
     * A service that should be running is not. Apply the restart policy, and report the
     * decision — including the daemon's own last words, which is usually the actual reason.
     */
    private fun handleGone(context: Context, spec: ServiceSpec, track: Track, live: Live.Gone, now: Long) {
        if (!track.desired) {
            set(track, spec, ServicePhase.STOPPED, 0, "${spec.label} is stopped.", publish = false)
            return
        }
        val lastWords = lastLogLine(spec)
        val why = if (live.reused) {
            "pid ${live.pid} now belongs to another process, so ${spec.label} is gone"
        } else {
            "${spec.label} exited on its own"
        }

        if (!spec.restart.enabled || track.restarts >= spec.restart.maxConsecutiveRestarts) {
            track.desired = false
            set(
                track, spec, ServicePhase.GAVE_UP, 0,
                "$why. It was restarted ${track.restarts} time(s) and kept exiting, so " +
                    "Godwall stopped restarting it.$lastWords",
                publish = false,
            )
            return
        }

        if (track.nextRestartAtMs == 0L) {
            track.restarts += 1
            track.nextRestartAtMs = now + spec.restart.backoffMs(track.restarts)
            val inSeconds = ((track.nextRestartAtMs - now) / 1000L).coerceAtLeast(1L)
            set(
                track, spec, ServicePhase.EXITED, 0,
                "$why. Restart ${track.restarts} of ${spec.restart.maxConsecutiveRestarts} " +
                    "in ${inSeconds}s.$lastWords",
                publish = false,
            )
            return
        }

        if (now < track.nextRestartAtMs) {
            val inSeconds = ((track.nextRestartAtMs - now) / 1000L).coerceAtLeast(1L)
            set(
                track, spec, ServicePhase.EXITED, 0,
                "$why. Restart ${track.restarts} of ${spec.restart.maxConsecutiveRestarts} " +
                    "in ${inSeconds}s.$lastWords",
                publish = false,
            )
            return
        }

        track.nextRestartAtMs = 0L
        // Re-seed configs on a restart too: a daemon that died because its config was removed
        // would otherwise loop until the budget ran out for a reason nobody could see.
        for (config in spec.configs) {
            val report = PrefixInstaller.installConfig(context, config)
            if (!report.ok) {
                set(track, spec, ServicePhase.FAILED, 0, report.message, publish = false)
                return
            }
        }
        val launched = launch(spec)
        if (launched.ok) {
            set(
                track, spec, ServicePhase.STARTING, launched.pid,
                "Restarted as pid ${launched.pid} (attempt ${track.restarts}); confirming.",
                publish = false,
            )
        } else {
            set(track, spec, ServicePhase.FAILED, 0, launched.detail, publish = false)
        }
    }

    private fun runningDetail(spec: ServiceSpec, pid: Int): String {
        val ports = spec.health.filterIsInstance<ServiceHealthProbe.LocalPort>()
        val portNote = if (ports.isEmpty()) {
            ""
        } else {
            " Answering on " + ports.joinToString(", ") { "127.0.0.1:${it.port} (${it.note})" } + "."
        }
        return "${spec.label} is running as pid $pid at uid 2000.$portNote ${spec.reach}"
    }

    // ---- Watchdog ----------------------------------------------------------------------

    /**
     * Begin re-observing every [TICK_MS]. Idempotent.
     *
     * Runs on [Bg.io] because every tick is a blocking binder round trip to Yojimbo. Start it
     * when the engine comes up; [stopWatchdog] when it goes down, so a backgrounded app is not
     * waking a privileged process every five seconds for nothing.
     */
    fun startWatchdog(context: Context) {
        if (watchdog?.isActive == true) return
        val appContext = context.applicationContext
        watchdog = scope.launch {
            Diagnostics.log(TAG, "watchdog started")
            while (isActive) {
                runCatching { observe(appContext) }
                    .onFailure { Diagnostics.error(TAG, "watchdog tick failed: ${it.javaClass.simpleName}") }
                delay(TICK_MS)
            }
        }
    }

    fun stopWatchdog() {
        watchdog?.cancel()
        watchdog = null
        Diagnostics.log(TAG, "watchdog stopped")
    }

    // ---- Output ------------------------------------------------------------------------

    /**
     * The last [lines] lines a service wrote. Blocking.
     *
     * Returns null when there is no privileged shell — the prefix is unreadable to Godwall's
     * own uid, so "no log" and "cannot read the log" are different answers and the caller must
     * be able to tell them apart.
     */
    fun logTail(id: String, lines: Int = 100): List<String>? {
        val spec = specs[id] ?: return null
        if (!Privilege.isAvailable()) return null
        val n = lines.coerceIn(1, MAX_LOG_LINES)
        val log = PrefixInstaller.resolve(spec.logPath)
        val r = PrefixInstaller.exec(
            "[ -f " + PrefixInstaller.quote(log) + " ] || exit 3\n" +
                "tail -n $n " + PrefixInstaller.quote(log),
        )
        if (!r.ok) return null
        return r.out.lines().dropLastWhile { it.isBlank() }
    }

    private fun lastLogLine(spec: ServiceSpec): String {
        val tail = logTail(spec.id, 1)?.lastOrNull { it.isNotBlank() } ?: return ""
        return " Its last output was: $tail"
    }

    // ---- Privileged plumbing -------------------------------------------------------------

    private data class Launched(val ok: Boolean, val pid: Int, val detail: String)

    /**
     * Background the daemon and confirm it is still alive a moment later.
     *
     * The settle wait happens inside the script rather than in Kotlin so the whole
     * launch-and-confirm is a single binder round trip, and so a daemon that dies on a bad
     * config line is reported with that line instead of a bare exit code.
     */
    private fun launch(spec: ServiceSpec): Launched {
        val r = PrefixInstaller.exec(launchScript(spec), timeoutMs = 60_000L)
        if (!r.ok) {
            return Launched(false, 0, "Could not launch ${spec.label}: ${r.summary()}")
        }
        val lines = r.out.lines()
        val head = lines.firstOrNull { it.isNotBlank() }?.trim().orEmpty()
        val pid = head.substringAfter(' ', "").trim().toIntOrNull() ?: 0
        if (head.startsWith("ALIVE") && pid > 0) {
            Diagnostics.log(TAG, "${spec.id} launched as pid $pid")
            return Launched(true, pid, "Launched as pid $pid.")
        }
        val output = lines.drop(1).filter { it.isNotBlank() }.takeLast(6).joinToString(" | ")
        val why = if (output.isBlank()) {
            "It wrote nothing before exiting."
        } else {
            "Its output was: $output"
        }
        Diagnostics.error(TAG, "${spec.id} exited immediately after launch")
        return Launched(false, 0, "${spec.label} exited immediately after starting. $why")
    }

    private fun launchScript(spec: ServiceSpec): String {
        val q = PrefixInstaller::quote
        val bin = PrefixInstaller.resolve(spec.binary)
        val wd = PrefixInstaller.resolve(spec.workingDir)
        val log = PrefixInstaller.resolve(spec.logPath)
        val pidFile = PrefixInstaller.resolve(spec.pidPath)
        val argv = (listOf(bin) + spec.resolvedArgs(PrefixInstaller.PREFIX)).joinToString(" ") { q(it) }

        // PATH and LD_LIBRARY_PATH point into the prefix first. The ELF repatcher already
        // rewrote DT_RUNPATH, so LD_LIBRARY_PATH is belt-and-braces for the handful of
        // packages that dlopen() a sibling by bare name at runtime rather than linking it.
        val env = buildList {
            add("HOME" to PrefixInstaller.HOME)
            add("PREFIX" to PrefixInstaller.USR)
            add("TMPDIR" to PrefixInstaller.TMP)
            add("PATH" to "${PrefixInstaller.USR}/bin:${PrefixInstaller.USR}/bin/applets:/system/bin:/system/xbin")
            add("LD_LIBRARY_PATH" to "${PrefixInstaller.USR}/lib")
            add("LANG" to "C.UTF-8")
            // Spec env last, so a service can override any of the above deliberately.
            spec.resolvedEnv(PrefixInstaller.PREFIX).forEach { (k, v) -> add(k to v) }
        }

        return buildList {
            add("set -e")
            add("mkdir -p " + listOf(PrefixInstaller.RUN, PrefixInstaller.LOGS, PrefixInstaller.TMP, wd).joinToString(" ") { q(it) })
            add("cd " + q(wd))
            // Truncate: the log is this run's, so the tail shown after a failure is never a
            // previous run's error text presented as the current one.
            add(": > " + q(log))
            env.forEach { (k, v) -> add("$k=" + q(v) + "; export $k") }
            // `cmd &` in a non-interactive shell forks once and execs, so $! is the daemon's
            // own pid — no setsid, which would fork again and make the recorded pid wrong.
            add("$argv >> " + q(log) + " 2>&1 &")
            add("pid=\$!")
            add("printf '%s\\n' \"\$pid\" > " + q(pidFile))
            add("sleep 0.4")
            add("if kill -0 \"\$pid\" 2>/dev/null; then")
            add("  printf 'ALIVE %s\\n' \"\$pid\"")
            add("else")
            add("  printf 'DEAD %s\\n' \"\$pid\"")
            add("  tail -n 20 " + q(log) + " 2>/dev/null")
            add("fi")
            add("exit 0")
        }.joinToString("\n")
    }

    private fun stopScript(spec: ServiceSpec): String {
        val q = PrefixInstaller::quote
        val pidFile = PrefixInstaller.resolve(spec.pidPath)
        return buildList {
            // Same zombie caveat as the liveness sweep: a signalled process that has not been
            // reaped yet still answers kill -0, so liveness is "signal reaches it AND it still
            // has an argv". Without that, every stop would burn the full grace period and then
            // report the service as refusing to die.
            add("alive() {")
            add("  kill -0 \"\$1\" 2>/dev/null || return 1")
            add("  c=\$(tr '\\0' ' ' < \"/proc/\$1/cmdline\" 2>/dev/null)")
            add("  [ -n \"\$c\" ] || return 1")
            add("  return 0")
            add("}")
            add("pid=\$(cat " + q(pidFile) + " 2>/dev/null)")
            add("if [ -z \"\$pid\" ]; then rm -f " + q(pidFile) + "; printf 'NOPID\\n'; exit 0; fi")
            add("kill \"\$pid\" 2>/dev/null")
            add("i=0")
            add("while [ \$i -lt 25 ]; do")
            add("  alive \"\$pid\" || break")
            add("  sleep 0.2")
            add("  i=\$((i+1))")
            add("done")
            add("if alive \"\$pid\"; then kill -9 \"\$pid\" 2>/dev/null; sleep 0.3; fi")
            add("if alive \"\$pid\"; then printf 'ALIVE %s\\n' \"\$pid\"; else printf 'STOPPED %s\\n' \"\$pid\"; fi")
            add("rm -f " + q(pidFile))
            add("exit 0")
        }.joinToString("\n")
    }

    /** What the privileged shell saw of one service's process. */
    private sealed interface Live {
        /** The spec's binary is not in the prefix. */
        object NoBinary : Live

        data class Running(val pid: Int) : Live

        /** No pid recorded, the process is gone, or the pid was reused by something else. */
        data class Gone(val pid: Int, val reused: Boolean) : Live
    }

    /**
     * One privileged call for every service's liveness, not one per service. A shell function
     * is defined once and invoked per spec, so a subsystem with seven daemons costs one binder
     * round trip per tick rather than seven.
     */
    private fun readLiveness(all: List<ServiceSpec>): Map<String, Live> {
        val q = PrefixInstaller::quote
        val script = buildList {
            add("svc() {")
            add("  id=\$1; pf=\$2; bin=\$3")
            add("  if [ ! -x \"\$bin\" ]; then printf '%s NOBIN\\n' \"\$id\"; return 0; fi")
            add("  pid=\$(cat \"\$pf\" 2>/dev/null)")
            add("  if [ -z \"\$pid\" ]; then printf '%s NOPID\\n' \"\$id\"; return 0; fi")
            add("  if ! kill -0 \"\$pid\" 2>/dev/null; then printf '%s DEAD %s\\n' \"\$id\" \"\$pid\"; return 0; fi")
            add("  cl=\$(tr '\\0' ' ' < \"/proc/\$pid/cmdline\" 2>/dev/null)")
            // An exited-but-unreaped process still answers kill -0 and has an empty cmdline.
            // Reporting that as REUSED would put "pid N belongs to another process now" in
            // front of the user, which is a claim we cannot support — it is simply dead.
            add("  if [ -z \"\$cl\" ]; then printf '%s DEAD %s\\n' \"\$id\" \"\$pid\"; return 0; fi")
            add("  case \"\$cl\" in")
            add("    *\"\$bin\"*) printf '%s ALIVE %s\\n' \"\$id\" \"\$pid\" ;;")
            add("    *) printf '%s REUSED %s\\n' \"\$id\" \"\$pid\" ;;")
            add("  esac")
            add("}")
            all.forEach { spec ->
                add(
                    "svc " + q(spec.id) + " " + q(PrefixInstaller.resolve(spec.pidPath)) + " " +
                        q(PrefixInstaller.resolve(spec.binary)),
                )
            }
            add("exit 0")
        }.joinToString("\n")

        val r = PrefixInstaller.exec(script, timeoutMs = 30_000L)
        if (!r.ok) {
            Diagnostics.warn(TAG, "liveness sweep failed: ${r.summary()}")
            return emptyMap()
        }
        val out = HashMap<String, Live>(all.size)
        for (line in r.out.lines()) {
            val parts = line.trim().split(' ')
            if (parts.size < 2) continue
            val id = parts[0]
            val pid = parts.getOrNull(2)?.toIntOrNull() ?: 0
            out[id] = when (parts[1]) {
                "NOBIN" -> Live.NoBinary
                "ALIVE" -> if (pid > 0) Live.Running(pid) else Live.Gone(0, reused = false)
                "REUSED" -> Live.Gone(pid, reused = true)
                else -> Live.Gone(pid, reused = false)
            }
        }
        return out
    }

    /**
     * The health probes that need the shell — file existence and log contents — batched the
     * same way. Keyed `"<id>:<probe index>"` so a service with several probes stays legible.
     */
    private fun readShellProbes(all: List<ServiceSpec>): Map<String, Boolean> {
        val q = PrefixInstaller::quote
        val calls = ArrayList<String>()
        for (spec in all) {
            spec.health.forEachIndexed { index, probe ->
                val key = "${spec.id}:$index"
                when (probe) {
                    is ServiceHealthProbe.PrefixFile ->
                        calls += "f " + q(key) + " " + q(PrefixInstaller.resolve(probe.relPath))
                    is ServiceHealthProbe.LogContains ->
                        calls += "g " + q(key) + " " + q(probe.text) + " " +
                            q(PrefixInstaller.resolve(spec.logPath))
                    is ServiceHealthProbe.LocalPort -> Unit // dialled from this process instead
                }
            }
        }
        if (calls.isEmpty()) return emptyMap()

        val script = buildList {
            add("f() { if [ -e \"\$2\" ]; then printf '%s OK\\n' \"\$1\"; else printf '%s MISS\\n' \"\$1\"; fi; }")
            add("g() { if grep -qF -- \"\$2\" \"\$3\" 2>/dev/null; then printf '%s OK\\n' \"\$1\"; else printf '%s MISS\\n' \"\$1\"; fi; }")
            addAll(calls)
            add("exit 0")
        }.joinToString("\n")

        val r = PrefixInstaller.exec(script, timeoutMs = 30_000L)
        if (!r.ok) {
            Diagnostics.warn(TAG, "probe sweep failed: ${r.summary()}")
            return emptyMap()
        }
        val out = HashMap<String, Boolean>(calls.size)
        for (line in r.out.lines()) {
            val parts = line.trim().split(' ')
            if (parts.size < 2) continue
            out[parts[0]] = parts[1] == "OK"
        }
        return out
    }

    /**
     * Which of [spec]'s probes did not pass, phrased for a status line.
     *
     * A shell probe with no result is treated as failed rather than passed: an unanswered
     * question is not a yes, and defaulting it to yes is precisely how a supervisor starts
     * reporting a state it never observed.
     */
    private fun failedProbes(spec: ServiceSpec, pid: Int, shellProbes: Map<String, Boolean>): List<String> {
        val failures = ArrayList<String>(2)
        spec.health.forEachIndexed { index, probe ->
            val key = "${spec.id}:$index"
            when (probe) {
                is ServiceHealthProbe.LocalPort ->
                    if (!portOpen(probe.port)) {
                        failures += "nothing is listening on 127.0.0.1:${probe.port} (${probe.note})"
                    }

                is ServiceHealthProbe.PrefixFile ->
                    if (shellProbes[key] != true) {
                        failures += "${probe.relPath} does not exist in the prefix"
                    }

                is ServiceHealthProbe.LogContains ->
                    if (shellProbes[key] != true) {
                        failures += "its log has not reported \"${probe.text}\""
                    }
            }
        }
        if (failures.isNotEmpty()) {
            Diagnostics.warn(TAG, "${spec.id} pid $pid unhealthy: ${failures.joinToString("; ")}")
        }
        return failures
    }

    /**
     * Dial a loopback port from Godwall's own process — no privileged shell involved.
     *
     * This is the whole socket-space argument in three lines: loopback is shared across uids,
     * so a daemon at uid 2000 that binds 127.0.0.1 is reachable by this app directly. It is
     * also how the tun handler will hand traffic to these daemons, which makes this probe a
     * genuine test of the path the data will take rather than a proxy for it.
     */
    private fun portOpen(port: Int): Boolean = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress("127.0.0.1", port), PORT_PROBE_TIMEOUT_MS)
            true
        }
    } catch (e: IOException) {
        false
    } catch (e: SecurityException) {
        Diagnostics.warn(TAG, "loopback probe on $port refused: ${e.javaClass.simpleName}")
        false
    }

    // ---- State publication ----------------------------------------------------------------

    private val NO_SHELL_DETAIL =
        "No privileged shell is attached, and Godwall's own uid cannot read " +
            "${PrefixInstaller.PREFIX}. Whether this service is running is unknown — not " +
            "stopped, unknown."

    private fun phaseFor(state: PrefixInstaller.State): ServicePhase = when (state) {
        PrefixInstaller.State.NO_PRIVILEGE -> ServicePhase.UNKNOWN
        else -> ServicePhase.ABSENT
    }

    /** Record a phase transition. Only [observe], [start] and [stop] reach this. */
    private fun set(
        track: Track,
        spec: ServiceSpec,
        phase: ServicePhase,
        pid: Int,
        detail: String,
        publish: Boolean = true,
    ): ServiceStatus {
        if (track.phase != phase) {
            track.sinceMs = System.currentTimeMillis()
            Diagnostics.log(TAG, "${spec.id}: ${track.phase} -> $phase")
        }
        track.phase = phase
        track.pid = pid
        track.detail = detail
        if (publish) publish()
        return snapshot(spec.id, track)
    }

    private fun snapshot(id: String, track: Track) = ServiceStatus(
        id = id,
        phase = track.phase,
        pid = track.pid,
        detail = track.detail,
        sinceMs = track.sinceMs,
        restarts = track.restarts,
    )

    private fun publish() {
        _statuses.value = specs.keys.sorted().associateWith { id ->
            snapshot(id, tracks.getOrPut(id) { Track() })
        }
    }
}
