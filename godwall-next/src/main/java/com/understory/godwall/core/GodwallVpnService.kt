package com.understory.godwall.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.understory.godwall.MainActivity
import com.understory.godwall.R
import com.understory.godwall.chain.EndpointChain
import com.understory.godwall.dns.BlocklistRepository
import com.understory.godwall.dns.ConnectionAttributor
import com.understory.godwall.dns.DnsEventLog
import com.understory.godwall.dns.DnsSettings
import com.understory.godwall.mesh.Mesh
import com.understory.net.engine.DnsMessage
import com.understory.net.engine.VpnPacketParser
import com.understory.security.Diagnostics
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * The VPN slot holder and the DNS filter that runs inside it.
 *
 * ## What this actually does, stated exactly
 *
 * The tun captures **DNS only**: the interface advertises Godwall as the resolver and routes
 * that one address, so every name lookup on the device comes here and nothing else does. Each
 * query is attributed to the app that made it, checked against the blocklist and the per-app
 * blackhole, and then either answered with a block response or forwarded to the configured
 * encrypted upstream (optionally through the egress chain).
 *
 * It is deliberately **not** a full packet firewall, and the UI says so in those words. A
 * userspace tun that swallowed all routes would have to re-implement TCP for every connection
 * on the device; done badly that is a device-wide outage, and done "mostly" it is a security
 * control that silently passes what it cannot parse. Name-based denial is the honest thing a
 * rootless app can do well, so that is what ships, described as what it is. The packet-level
 * tier is what the Yojimbo privileged shell is for.
 *
 * ## Slot posture
 *
 * There is no incumbent-VPN veto here. Android gives the slot to whichever app the user
 * consents to; when the user arms Godwall, that app is Godwall — including over Tailscale,
 * because Godwall carries its own mesh node rather than deferring to that app.
 */
class GodwallVpnService : VpnService() {

    private val running = AtomicBoolean(false)
    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private var attributor: ConnectionAttributor? = null

    /**
     * Link the mesh data plane here, and here only.
     *
     * This call site is the whole reason the mesh works at all. The previous build's equivalent
     * of [Mesh.linkNative] had ZERO call sites anywhere in the repo, so its backend was null
     * forever: the node could not start under any build configuration, and every tailnet claim
     * in that UI was unreachable code. The backend needs a live [VpnService] to build its tun,
     * so onCreate on this service is the earliest correct moment — and the only one.
     */
    override fun onCreate() {
        super.onCreate()
        Mesh.linkNative(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            Diagnostics.log(TAG, "stop requested")
            teardown("stopped by user")
            stopSelf()
            return START_NOT_STICKY
        }
        if (running.get()) return START_STICKY

        EngineState.publish(EngineState.Phase.STARTING)
        startForeground(NOTIF_ID, buildNotification())

        return try {
            establish()
            START_STICKY
        } catch (t: Throwable) {
            val why = "${t.javaClass.simpleName}: ${t.message}"
            Diagnostics.error(TAG, "establish failed — $why")
            EngineState.publish(EngineState.Phase.FAILED, why)
            stopSelf()
            START_NOT_STICKY
        }
    }

    private fun establish() {
        val builder = Builder()
            .setSession(getString(R.string.vpn_session_name))
            .setMtu(MTU)
            // A tiny private /32 for our own endpoint, plus the resolver address we advertise.
            .addAddress(TUN_ADDR, 32)
            .addDnsServer(DNS_ADDR)
            // Route ONLY the resolver. Everything else keeps its normal path, which is why
            // arming Godwall cannot break unrelated connectivity.
            .addRoute(DNS_ADDR, 32)

        // Apps the user excluded, plus our own siblings, never enter the tun.
        AppPolicy.bypassed(applicationContext).forEach { pkg ->
            runCatching { builder.addDisallowedApplication(pkg) }
                .onFailure { Diagnostics.warn(TAG, "bypass $pkg: ${it.message}") }
        }

        val pfd = builder.establish()
            ?: throw IllegalStateException(
                "Android did not grant the VPN slot. Another app may hold it, or consent was " +
                    "withdrawn.",
            )
        tun = pfd
        attributor = ConnectionAttributor(applicationContext)
        running.set(true)
        EngineState.publish(EngineState.Phase.UP, "filtering DNS")
        Diagnostics.log(TAG, "tun established — DNS filter live")

        worker = thread(name = "godwall-dns", isDaemon = true) {
            // Reading and parsing the blocklist is blocking I/O over a gzipped asset, so it
            // belongs here rather than in onStartCommand — which runs on the main thread and
            // would stall the UI at exactly the moment the user is watching the shield.
            runCatching { BlocklistRepository.reload(applicationContext) }
                .onFailure { Diagnostics.error(TAG, "blocklist reload: ${it.message}") }
            pump(pfd)
        }
    }

    /**
     * The read loop. One thread, blocking reads, because the traffic here is DNS only — a few
     * packets a second on a busy device. Anything more elaborate would be complexity without a
     * measurement to justify it.
     */
    private fun pump(pfd: ParcelFileDescriptor) {
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val buf = ByteArray(MTU)

        while (running.get()) {
            val len = try {
                input.read(buf)
            } catch (t: Throwable) {
                if (running.get()) Diagnostics.error(TAG, "tun read: ${t.message}")
                break
            }
            if (len <= 0) continue

            val reply = runCatching { handle(buf, len) }.getOrElse {
                Diagnostics.error(TAG, "handle threw ${it.javaClass.simpleName}: ${it.message}")
                null
            } ?: continue

            runCatching { output.write(reply) }
                .onFailure { Diagnostics.error(TAG, "tun write: ${it.message}") }
        }
        Diagnostics.log(TAG, "pump exited")
    }

    /** @return the response packet to write back, or null to drop silently. */
    private fun handle(buf: ByteArray, len: Int): ByteArray? {
        if (!VpnPacketParser.isIpv4(buf, len)) return null
        if (VpnPacketParser.protocol(buf) != VpnPacketParser.PROTO_UDP) return null
        val pkt = VpnPacketParser.parseIpv4Udp(buf, len) ?: return null
        if (pkt.dstPort != VpnPacketParser.DNS_PORT) return null
        if (pkt.payloadLen <= 0) return null

        val query = buf.copyOfRange(pkt.payloadOffset, pkt.payloadOffset + pkt.payloadLen)
        val question = DnsMessage.parseFirstQuestion(query) ?: return null
        val domain = question.name

        val ctx = applicationContext
        val uid = attributor?.uidFor(
            protocol = VpnPacketParser.PROTO_UDP.toInt(),
            srcIp = pkt.srcIp.hostAddress ?: "",
            srcPort = pkt.srcPort,
            dstIp = pkt.dstIp.hostAddress ?: "",
            dstPort = pkt.dstPort,
        ) ?: ConnectionAttributor.INVALID_UID
        val label = attributor?.labelFor(uid) ?: "unknown app"
        val pkg = attributor?.packageFor(uid)

        // Two independent reasons to deny, recorded as one outcome.
        val appBlackholed = pkg != null && pkg in AppPolicy.blackholed(ctx)
        val listBlocked = BlocklistRepository.isFilterEnabled(ctx) &&
            BlocklistRepository.current.isBlocked(domain)
        val blocked = appBlackholed || listBlocked

        DnsEventLog.record(domain = domain, appLabel = label, appUid = uid, blocked = blocked)

        val payload = if (blocked) {
            DnsMessage.buildBlockedResponse(query, BlocklistRepository.answerStyle(ctx))
        } else {
            DnsSettings.resolver(ctx).resolve(
                service = this,
                query = query,
                hops = EndpointChain.hops(ctx),
                chainOn = EndpointChain.isEnabled(ctx),
            )
        } ?: return null

        return VpnPacketParser.buildIpv4UdpResponse(pkt, payload)
    }

    private fun teardown(why: String) {
        // The node runs inside this slot, so it goes down with it. Leaving Go holding a tun we
        // just closed would leave a half-live tunnel the UI could not describe.
        runCatching { Mesh.stop(applicationContext) }
        running.set(false)
        runCatching { tun?.close() }
        tun = null
        worker = null
        attributor = null
        EngineState.publish(EngineState.Phase.DOWN, why)
    }

    /**
     * Android revoked the slot — typically because the user consented to a different VPN app.
     * Report it as DOWN with the real reason instead of leaving a stale "protected" indicator,
     * which is the failure this whole state object exists to prevent.
     */
    override fun onRevoke() {
        Diagnostics.warn(TAG, "slot revoked by the system")
        teardown("another VPN took the slot")
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        teardown("service destroyed")
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm?.getNotificationChannel(CHANNEL) == null) {
            nm?.createNotificationChannel(
                NotificationChannel(
                    CHANNEL,
                    getString(R.string.notif_channel_name),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply { setShowBadge(false) },
            )
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, GodwallVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text))
            .setContentIntent(open)
            .addAction(
                Notification.Action.Builder(null, getString(R.string.notif_stop), stop).build(),
            )
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "godwall.vpn"
        private const val CHANNEL = "godwall.engine"
        private const val NOTIF_ID = 0x60D0
        private const val MTU = 1500

        /** Our own endpoint inside the tun. RFC 5737 documentation space — never routable. */
        private const val TUN_ADDR = "203.0.113.2"

        /** The resolver address we advertise and capture. Same reserved block. */
        private const val DNS_ADDR = "203.0.113.53"

        const val ACTION_STOP = "com.understory.godwall.ACTION_STOP"

        fun start(ctx: Context) {
            ctx.startForegroundService(Intent(ctx, GodwallVpnService::class.java))
        }

        fun stop(ctx: Context) {
            runCatching {
                ctx.startService(
                    Intent(ctx, GodwallVpnService::class.java).apply { action = ACTION_STOP },
                )
            }
        }
    }
}
