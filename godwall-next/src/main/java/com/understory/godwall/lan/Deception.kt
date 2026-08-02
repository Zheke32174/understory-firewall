package com.understory.godwall.lan

import com.understory.security.Diagnostics
import com.understory.security.ui.Bg
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.atomic.AtomicInteger

/**
 * Portspoof-style deception — applied to Godwall's OWN listeners, which is the version of this
 * that is real and unprivileged.
 *
 * ## What portspoof does, and which half of it this is
 *
 * The `portspoof` tool answers a port scan with fabricated service banners so the scanner's
 * fingerprinting is poisoned and every port looks open and busy. It does that in two pieces:
 *
 *  1. it binds one listener and speaks the fake banners, and
 *  2. it installs a netfilter rule (`iptables -t nat -A PREROUTING -p tcp --dport 1:65535 -j
 *     REDIRECT --to-ports <listener>`) so that *every* inbound port, including 22/80/443, is
 *     funnelled into that one listener.
 *
 * Piece 1 is socket space: binding a `ServerSocket` and writing bytes to whoever connects needs no
 * privilege, and Godwall does it here, in its own process. Piece 2 is netfilter space: rewriting
 * the device's PREROUTING table is the privileged host tier (see WP-8 / [LanDefence]), and this
 * build does not do it — so the decoys answer only on the high ports Godwall actually binds, and
 * host-wide redirection reports absent rather than pretending the whole port range is covered.
 *
 * That split is the honest boundary. A scanner that hits one of the bound decoy ports gets a
 * fabricated banner and then a tarpit (a slow, capped drip that wastes the scanner's time); a
 * scanner that probes port 22 sees nothing from this, because covering 22 would need the netfilter
 * redirect this tier cannot perform.
 *
 * ## Why it defaults off and lives only while the process does
 *
 * Opening listening sockets is an attack-surface decision, so deception ships off ([LanSettings])
 * and the user turns it on deliberately. And because these are in-process sockets, they exist only
 * while Godwall's process is alive — this is not an OS service that survives a swipe-away. Both
 * facts are stated in the UI rather than left for the user to discover; a decoy layer the user
 * believes is running after the app was killed would be a false sense of coverage.
 */
object Deception {

    private const val TAG = "godwall.lan.Deception"

    /** Lowest port an unprivileged process may bind. Below this needs privilege we do not take. */
    const val MIN_PORT = 1024

    const val MAX_PORT = 65535

    /**
     * Ports Godwall's subsystem daemons are expected to bind (resolvers, SOCKS, proxy inbounds).
     * Refused as decoy ports so the deception layer never fights a real service for a port. A bind
     * clash is also reported honestly at start, but refusing the known ones up front keeps the
     * decoy set from being configured into a collision in the first place.
     */
    private val RESERVED_PORTS = setOf(53, 443, 853, 1053, 1080, 4444, 5353, 8853, 9050, 9051, 10808, 10809)

    /** Total time one decoy connection is held in the tarpit before it is dropped. */
    private const val MAX_HOLD_MS = 20_000L

    /** Gap between tarpit drip reads — long enough to waste a scanner, short enough to stay responsive to stop. */
    private const val DRIP_MS = 500L

    /** Ceiling on concurrently-held decoy connections, so a connection flood cannot exhaust the process. */
    private const val MAX_CONCURRENT = 64

    /** Read timeout on a held connection, so a silent peer does not pin a thread past the hold cap. */
    private const val SO_TIMEOUT_MS = 2_000

    /**
     * A fabricated service a decoy presents. The banner is the greeting a real service of that kind
     * sends on connect; nothing here emulates the protocol past the greeting — this is deception by
     * plausible banner plus tarpit, not a full service emulator, and it does not claim to be.
     */
    enum class Profile(val banner: String) {
        SSH("SSH-2.0-OpenSSH_8.9p1\r\n"),
        FTP("220 (vsFTPd 3.0.5)\r\n"),
        SMTP("220 mail.localdomain ESMTP Postfix\r\n"),
        HTTP("HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nConnection: close\r\n\r\n"),
        TELNET("\r\nlogin: "),
        GENERIC("\r\n"),
    }

    /** The pre-configured decoy set: a handful of scanner-bait ports mapped to plausible banners. */
    val DEFAULT_PORTS: List<Int> = listOf(2222, 2121, 2525, 8888, 8023)

    private val DEFAULT_PROFILES: Map<Int, Profile> = mapOf(
        2222 to Profile.SSH,
        2121 to Profile.FTP,
        2525 to Profile.SMTP,
        8888 to Profile.HTTP,
        8023 to Profile.TELNET,
    )

    /** Why a requested decoy port was refused before any bind was attempted. */
    data class PortRejection(val port: Int, val reason: Rejection)

    enum class Rejection { OUT_OF_RANGE, RESERVED, DUPLICATE }

    /** A port that passed validation but could not be bound, with the OS reason. */
    data class BindFailure(val port: Int, val reason: String)

    data class Status(
        val running: Boolean,
        val bound: List<Int>,
        val bindFailures: List<BindFailure>,
        val rejected: List<PortRejection>,
        val activeConnections: Int,
    )

    /** Whether host-wide port deception (the netfilter redirect) is possible in this build. */
    const val HOST_WIDE_AVAILABLE = false

    private val lock = Any()

    @Volatile
    private var scope: CoroutineScope? = null

    private val sockets = ArrayList<ServerSocket>()

    @Volatile
    private var bound: List<Int> = emptyList()

    @Volatile
    private var bindFailures: List<BindFailure> = emptyList()

    @Volatile
    private var rejected: List<PortRejection> = emptyList()

    private val active = AtomicInteger(0)

    /**
     * Validate a requested decoy-port list into the ports that will be bound and the ones refused,
     * with the reason for each refusal. Pure, so the policy is testable without opening a socket.
     * De-duplicates while preserving order; the first occurrence wins and later repeats are
     * reported as [Rejection.DUPLICATE] rather than silently collapsed.
     */
    fun validate(ports: List<Int>): Pair<List<Int>, List<PortRejection>> {
        val accepted = ArrayList<Int>()
        val refused = ArrayList<PortRejection>()
        val seen = HashSet<Int>()
        for (p in ports) {
            when {
                p < MIN_PORT || p > MAX_PORT -> refused += PortRejection(p, Rejection.OUT_OF_RANGE)
                p in RESERVED_PORTS -> refused += PortRejection(p, Rejection.RESERVED)
                !seen.add(p) -> refused += PortRejection(p, Rejection.DUPLICATE)
                else -> accepted += p
            }
        }
        return accepted to refused
    }

    /** The profile a decoy port presents; unknown ports get [Profile.GENERIC]. */
    fun profileFor(port: Int): Profile = DEFAULT_PROFILES[port] ?: Profile.GENERIC

    fun isRunning(): Boolean = scope?.isActive == true

    fun status(): Status = synchronized(lock) {
        Status(
            running = isRunning(),
            bound = bound,
            bindFailures = bindFailures,
            rejected = rejected,
            activeConnections = active.get(),
        )
    }

    /**
     * Bind the validated decoy ports and start answering. Idempotent: an already-running engine is
     * stopped and re-bound, so a settings change takes effect without leaking the old sockets.
     * Blocking (binds sockets); call off the main thread.
     *
     * Returns the resulting [Status] — including any port that failed to bind, so the caller can
     * show "3 of 5 decoys are listening; 8888 was already in use" instead of a bare success.
     */
    fun start(ports: List<Int>): Status = synchronized(lock) {
        stopLocked()
        val (accepted, refused) = validate(ports)
        rejected = refused

        val newScope = CoroutineScope(Bg.io + SupervisorJob())
        val boundNow = ArrayList<Int>()
        val failures = ArrayList<BindFailure>()

        for (port in accepted) {
            val server = try {
                // ServerSocket(port) binds the wildcard address (0.0.0.0) — the LAN-facing bind a
                // decoy needs, since a scanner reaches this device on its LAN IP, not loopback.
                ServerSocket(port)
            } catch (e: IOException) {
                failures += BindFailure(port, e.message ?: e.javaClass.simpleName)
                Diagnostics.warn(TAG, "decoy bind on $port failed: ${e.javaClass.simpleName}")
                null
            }
            if (server != null) {
                sockets += server
                boundNow += port
                acceptLoop(newScope, server, port)
            }
        }

        if (boundNow.isEmpty()) {
            // Nothing bound: do not leave a live-but-empty scope claiming the engine is "running".
            newScope.coroutineContext[Job]?.cancel()
            bound = emptyList()
            bindFailures = failures
            Diagnostics.warn(TAG, "deception started but no decoy port could be bound")
            return Status(false, emptyList(), failures, refused, 0)
        }

        scope = newScope
        bound = boundNow
        bindFailures = failures
        Diagnostics.log(TAG, "deception listening on ${boundNow.joinToString()}")
        return Status(true, boundNow, failures, refused, active.get())
    }

    /** Stop every decoy and release its port. Idempotent. */
    fun stop() = synchronized(lock) { stopLocked() }

    private fun stopLocked() {
        scope?.coroutineContext?.get(Job)?.cancel()
        scope = null
        for (s in sockets) runCatching { s.close() }
        sockets.clear()
        bound = emptyList()
        // Rejections and prior bind failures are cleared so a stopped engine reports a clean slate
        // rather than a stale reason from the last run.
        bindFailures = emptyList()
        rejected = emptyList()
        active.set(0)
        Diagnostics.log(TAG, "deception stopped")
    }

    private fun acceptLoop(scope: CoroutineScope, server: ServerSocket, port: Int) {
        scope.launch {
            while (scope.isActive && !server.isClosed) {
                val client = try {
                    server.accept()
                } catch (e: SocketException) {
                    // Expected on stop() closing the socket out from under accept().
                    break
                } catch (e: IOException) {
                    Diagnostics.warn(TAG, "accept on decoy $port failed: ${e.javaClass.simpleName}")
                    break
                }
                scope.launch { handle(client, port) }
            }
        }
    }

    /**
     * Answer one decoy connection: send the fabricated banner, then tarpit — read and discard with
     * a delay until the hold cap, so a scanner that keeps the connection open pays for it in time.
     * A connection over the concurrency ceiling still gets the banner (so the deception holds) but
     * is dropped immediately instead of being held, bounding resource use under a flood.
     */
    private suspend fun handle(client: Socket, port: Int) {
        val holdThis = active.incrementAndGet() <= MAX_CONCURRENT
        try {
            client.soTimeout = SO_TIMEOUT_MS
            val banner = profileFor(port).banner.toByteArray(Charsets.US_ASCII)
            runCatching { client.getOutputStream().apply { write(banner); flush() } }
            if (!holdThis) return

            val deadline = System.currentTimeMillis() + MAX_HOLD_MS
            val input = client.getInputStream()
            val sink = ByteArray(256)
            // coroutineContext.isActive goes false when stop() cancels the scope; delay() below
            // also throws CancellationException on stop, so the hold ends promptly either way.
            while (kotlin.coroutines.coroutineContext.isActive &&
                System.currentTimeMillis() < deadline && !client.isClosed
            ) {
                val n = try {
                    input.read(sink)
                } catch (e: java.net.SocketTimeoutException) {
                    0 // peer is idle; keep holding until the deadline
                } catch (e: IOException) {
                    break // peer hung up
                }
                if (n < 0) break // peer closed cleanly
                delay(DRIP_MS)
            }
        } finally {
            active.decrementAndGet()
            runCatching { client.close() }
        }
    }
}
