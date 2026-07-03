package com.understory.firewall

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Firewall VpnService — captures outbound traffic from packages on the
 * user's blocklist and drops it.
 *
 * Approach (Phase B, intentionally simple):
 *   - Establish a tun interface that captures traffic from listed apps.
 *   - We use [VpnService.Builder.addAllowedApplication] for each blocked
 *     app — only those packages have their traffic routed through our
 *     tun. Everything else uses the normal network unmodified.
 *   - We read packets from the tun fd and DROP them. No forwarding, no
 *     parsing, no DNS interception. The blocked apps simply find that
 *     their connections never complete.
 *   - When the blocklist is empty, the VPN is not established at all —
 *     no tun, no foreground service, no overhead.
 *
 * Phase C will add packet parsing for finer-grained rules (per-domain
 * blocking, per-port rules, DNS overrides). This phase is the simplest
 * thing that does what the user expects: "block this app's network."
 *
 * Why "drop everything from listed apps" instead of "drop everything
 * except listed apps":
 *   - Default-allow with blocklist matches user mental model.
 *   - If we used addDisallowedApplication (the inverse), users would
 *     have to whitelist every app they want to keep working — broken
 *     by default until configured.
 *   - The current model: VPN inactive by default → everything works.
 *     Toggle on + add an app to blocklist → only that app loses
 *     network. Other apps unaffected.
 */
class FirewallVpnService : VpnService() {

    private var tunFd: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var readerThread: Thread? = null
    /** Periodic /proc/net scanner. Active while running.get() is true and
     *  the user has at least one port in the block list. Re-runs
     *  startVpn() every PORT_SCAN_INTERVAL_MS to refresh the auto-
     *  derived blocklist; establish() does an atomic-swap so the user
     *  doesn't see a network blip. */
    private var portScannerThread: Thread? = null
    private var lastPortDerived: Set<String> = emptySet()
    /** Phase-3 DNS-redirect mode: an in-flight DnsRedirector consumes
     *  packets from the tun fd and forwards UDP-DNS to the local
     *  DNSCrypt proxy. Null when the VPN is in app-drop mode or idle. */
    private var dnsRedirector: DnsRedirector? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Always promote to foreground first — Android kills services that
        // take too long to startForeground after onStartCommand.
        // On Android 14+ (API 34+) we MUST pass the explicit type or
        // Android throws MissingForegroundServiceTypeException; on older
        // versions the no-type overload is fine.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ID,
                buildNotification(),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ID, buildNotification())
        }

        if (intent?.action == ACTION_STOP) {
            stopVpn()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        // Mark running BEFORE establish, so the new reader thread's
        // running.get() loop is true on first iteration. startVpn()
        // performs an atomic-establish swap (build new tun → swap field →
        // close old fd) so there's no window where blocked apps' traffic
        // bypasses our tun. The previous "close-then-rebuild" pattern
        // had a measurable gap.
        running.set(true)
        startVpn()
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        // System or user revoked our VPN permission. Most common cause:
        // the user (or another app like Proton) called `VpnService.prepare`
        // for a different VPN, which atomically revokes ours and tears
        // down the tun. Android only allows one active VpnService at a
        // time and requires fresh user consent to switch back.
        //
        // Persist two things before tearing down so the UI on next
        // resume reflects reality:
        //   - vpnRequested = false  →  the Switch reads as "off",
        //                              not falsely claiming we're filtering
        //   - vpnPreempted = true   →  MainActivity shows a banner
        //                              "preempted — [Re-enable]" so the
        //                              user has a one-tap recovery path
        //                              that re-walks the consent dialog
        //
        // Without these writes the UI would happily render "firewall on,
        // N apps blocked" while the tun is gone and apps were freely
        // talking to the internet — a silent failure mode that defeats
        // the whole point of the feature.
        FirewallSettings.setVpnRequested(this, false)
        FirewallSettings.setVpnPreempted(this, true)
        stopVpn()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onRevoke()
    }

    private fun startVpn() {
        // ---- Phase-3 mode select ----
        // The VPN can be in one of three states:
        //
        //   IDLE          — no tun, no foreground tun reader. Service
        //                   stays alive (foreground notification) so
        //                   the user can flip the toggle without re-
        //                   prepare. No mode flags set.
        //
        //   APP_DROP      — capture only blocked apps' traffic via
        //                   addAllowedApplication, drop everything.
        //                   Existing phase-2 behavior. Combined with
        //                   /proc/net port discovery to expand the
        //                   blocklist reactively.
        //
        //   DNS_REDIRECT  — capture only traffic to FAKE_DNS_IP via
        //                   selective routing. addDnsServer makes apps
        //                   use FAKE_DNS_IP as their resolver. Reader
        //                   thread (DnsRedirector) forwards UDP DNS
        //                   queries to the local DNSCrypt proxy and
        //                   wraps responses back into tun packets.
        //
        // The two non-idle modes are mutually exclusive in a single
        // VPN session — without a userspace TCP forwarder we can't
        // both selectively-route-only-DNS and capture-blocked-apps'-
        // traffic from one tun. DNS_REDIRECT takes precedence when
        // a DNSCrypt provider is selected; the user's app blocklist
        // and port blocks are stored but not applied while DNSCrypt
        // is active. UI banners on both screens explain the trade-off.
        val dnsProvider = runCatching {
            DnsProvider.byId(FirewallSettings.getDnsProviderId(this))
        }.getOrNull()
        if (dnsProvider?.protocol == DnsProtocol.DNSCRYPT) {
            startVpnDnsRedirectMode()
            return
        }

        // Auto-derived block list: scan /proc/net for apps currently
        // talking to user-blocked ports, fold them into the per-app
        // drop list. Same effect path as the explicit user blocklist;
        // the VPN doesn't distinguish between sources of "drop this
        // package's traffic". See PortBlockDiscovery for limitations
        // (reactive, /proc visibility constraints on Android 10+).
        val ports = FirewallSettings.getBlockedPorts(this)
        val portDerived = PortBlockDiscovery.scan(this, ports)
        lastPortDerived = portDerived
        val blocked = FirewallSettings.getBlockedPackages(this) + portDerived

        // (Re-)spawn the periodic scanner if the user has any port
        // blocks configured. Don't spawn if no ports — saves the wakeup
        // cycle. Spawning is idempotent: kill any prior thread first.
        runCatching { portScannerThread?.interrupt() }
        portScannerThread = if (ports.isNotEmpty()) {
            Thread({
                while (running.get() && !Thread.currentThread().isInterrupted) {
                    try {
                        Thread.sleep(PORT_SCAN_INTERVAL_MS)
                    } catch (_: InterruptedException) {
                        return@Thread
                    }
                    if (!running.get()) return@Thread
                    val freshPorts = FirewallSettings.getBlockedPorts(this)
                    if (freshPorts.isEmpty()) return@Thread
                    val freshDerived = PortBlockDiscovery.scan(this, freshPorts)
                    if (freshDerived != lastPortDerived) {
                        // Auto-blocklist changed — re-establish the tun
                        // with the new combined set. establish() does an
                        // atomic swap so users don't see a network blip.
                        startVpn()
                    }
                }
            }, "firewall-port-scanner").also { it.start() }
        } else {
            null
        }

        if (blocked.isEmpty()) {
            // Empty blocklist — keep the service alive in idle mode but
            // don't establish a tun. This lets the user enable the VPN
            // BEFORE adding apps to block, then add apps incrementally
            // (each add triggers a re-establish via MainActivity calling
            // startVpn(ctx) again). The previous behavior of self-
            // stopping + flipping vpnRequested off was a real device-
            // test bug: on initial enable with no apps blocked yet, the
            // service ran for milliseconds, stopped, and the toggle
            // appeared to do nothing.
            //
            // Tear down any prior tun so we don't have a stale capture
            // session running with the old (now-empty) ruleset.
            runCatching { tunFd?.close() }
            tunFd = null
            runCatching { readerThread?.interrupt() }
            readerThread = null
            return
        }

        val builder = Builder()
            .setSession(getString(R.string.app_name))
            // Reserved private-use IPv4 (RFC 5737 — "documentation" range,
            // never routes on the public internet) and IPv6 (RFC 3849
            // 2001:db8::/32 — the documentation prefix). Without the v6
            // address+route a blocked app on a dual-stack network would
            // happily reach the internet over IPv6 because our tun only
            // claimed the v4 default route — a real bypass.
            .addAddress(VPN_LOCAL_ADDR, 32)
            .addRoute("0.0.0.0", 0)
            .addAddress(VPN_LOCAL_ADDR_V6, 128)
            .addRoute("::", 0)
            .setMtu(MTU)
            .setBlocking(true)

        // Capture only the blocked packages. Everything else bypasses
        // our tun and uses the normal network unmodified.
        var added = 0
        for (pkg in blocked) {
            try {
                builder.addAllowedApplication(pkg)
                added++
            } catch (_: PackageManager.NameNotFoundException) {
                // App was uninstalled since we recorded the rule. Skip.
            }
        }
        if (added == 0) {
            // Every blocked package is uninstalled. Calling establish()
            // without ANY addAllowedApplication() would tell Android the
            // tun captures *every* app's traffic — the silent worst case
            // that drops all device network. Treat the same as an empty
            // blocklist: tear down any prior tun and idle.
            runCatching { tunFd?.close() }
            tunFd = null
            runCatching { readerThread?.interrupt() }
            readerThread = null
            return
        }

        val newTun = builder.establish()
        if (newTun == null) {
            // Something went wrong — possibly user revoked VPN permission
            // between prepare() and establish(). Bail.
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            running.set(false)
            return
        }

        // We hold the tun. Clear any sticky preempted flag from a prior
        // session so the UI banner goes away.
        FirewallSettings.setVpnPreempted(this, false)

        // Refresh the foreground notification so its "N app(s) blocked"
        // line tracks the active rule count. The notification was built
        // once at onStartCommand from the original blocklist; rule edits
        // re-enter this method (MainActivity calls startVpn(ctx) again),
        // so re-publishing here keeps the user-visible count truthful.
        runCatching {
            getSystemService(NotificationManager::class.java)
                ?.notify(NOTIF_ID, buildNotification())
        }

        // Atomic swap: capture the old fd + thread *before* publishing
        // the new fd, so the new reader is up before we tear down the
        // old. VpnService.Builder.establish() is documented to atomically
        // replace any prior session for this VpnService — the system
        // tunnel slot is held continuously, blocked apps don't get a
        // bypass window.
        val oldTun = tunFd
        val oldThread = readerThread
        tunFd = newTun

        // Reader thread: pull packets from the tun and drop them. No
        // forwarding — the blocked apps find their connections silently
        // fail. Future Phase C will parse and selectively forward.
        readerThread = Thread({
            val input = FileInputStream(newTun.fileDescriptor)
            val buf = ByteArray(MTU)
            while (running.get()) {
                try {
                    val n = input.read(buf)
                    if (n < 0) break
                    // Drop. Bump the in-process counter so the UI can
                    // confirm the firewall is actually intercepting —
                    // the silent loop gave the user no feedback signal.
                    DropStats.record()
                } catch (_: Throwable) {
                    break
                }
            }
        }, "firewall-tun-reader").also { it.start() }

        // Tear down the previous session, if any. Closing the old fd
        // unblocks the old reader's input.read(), which sees -1 / throws
        // and exits its loop. join() bounds the cleanup.
        runCatching { oldTun?.close() }
        runCatching { oldThread?.join(500L) }
    }

    /**
     * DNS-redirect mode. Tun routes ONLY [DNS_REDIRECT_FAKE_IP]
     * through itself, with addDnsServer pointing to that IP so apps'
     * resolvers send DNS queries there. The DnsRedirector reader
     * thread parses each query, forwards to the local DNSCrypt
     * proxy on 127.0.0.1:[DnsCryptProxyService.LOCAL_PORT] via a
     * VpnService-protected DatagramSocket, then wraps the response
     * into an IPv4+UDP packet and writes back to the tun.
     *
     * No addAllowedApplication — capture is implicit via the route
     * filter. Non-DNS traffic from any app bypasses the tun entirely
     * (because no other route goes through it).
     */
    private fun startVpnDnsRedirectMode() {
        // Tear down any prior reader / scanner from a previous mode.
        runCatching { readerThread?.interrupt() }
        readerThread = null
        runCatching { portScannerThread?.interrupt() }
        portScannerThread = null
        lastPortDerived = emptySet()

        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .addAddress(VPN_LOCAL_ADDR, 32)
            // Selective route: ONLY the fake DNS IP goes through the
            // tun. Everything else takes the normal network. No need
            // for IPv6 routing here — apps' DNS resolver picks v4
            // first when both are offered, and we're not advertising
            // a v6 DNS server.
            .addRoute(DNS_REDIRECT_FAKE_IP, 32)
            // Tell apps to use FAKE_DNS_IP as their resolver. Combined
            // with the route, all DNS queries land on this tun.
            .addDnsServer(DNS_REDIRECT_FAKE_IP)
            .setMtu(MTU)
            .setBlocking(true)

        val newTun = builder.establish()
        if (newTun == null) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            running.set(false)
            return
        }

        FirewallSettings.setVpnPreempted(this, false)
        runCatching {
            getSystemService(NotificationManager::class.java)
                ?.notify(NOTIF_ID, buildNotification())
        }

        // Atomic swap. The redirector holds a reference to the new
        // tun fd; closing the old fd unblocks the previous reader
        // (if any) so it exits cleanly.
        val oldTun = tunFd
        val oldRedirector = dnsRedirector
        tunFd = newTun
        val redirector = DnsRedirector(
            vpnService = this,
            tun = newTun,
            fakeDnsIp = java.net.InetAddress.getByName(DNS_REDIRECT_FAKE_IP),
        )
        dnsRedirector = redirector
        readerThread = Thread(redirector, "firewall-dns-redirector").also { it.start() }

        oldRedirector?.stop()
        runCatching { oldTun?.close() }
    }

    private fun stopVpn() {
        running.set(false)
        runCatching { tunFd?.close() }
        tunFd = null
        runCatching { readerThread?.interrupt() }
        readerThread = null
        dnsRedirector?.stop()
        dnsRedirector = null
        runCatching { portScannerThread?.interrupt() }
        portScannerThread = null
        lastPortDerived = emptySet()
        // Counters track the current session, not lifetime-of-process —
        // reset on full stop, but NOT on the rule-change re-establish in
        // startVpn() (which only swaps tuns, doesn't call stopVpn).
        DropStats.reset()
    }

    private fun buildNotification(): android.app.Notification {
        ensureChannel()
        val pendingMain = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = Intent(this, FirewallVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingStop = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val blockedCount = FirewallSettings.getBlockedPackages(this).size
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("firewall active")
            .setContentText("$blockedCount app(s) blocked")
            .setOngoing(true)
            .setSilent(true)
            .setContentIntent(pendingMain)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", pendingStop)
            .build()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm?.getNotificationChannel(CHANNEL_ID) == null) {
                val ch = NotificationChannel(
                    CHANNEL_ID,
                    "Firewall status",
                    NotificationManager.IMPORTANCE_LOW,
                )
                ch.description = "Persistent notification while the firewall VPN is active."
                ch.setShowBadge(false)
                nm?.createNotificationChannel(ch)
            }
        }
    }

    companion object {
        const val CHANNEL_ID = "firewall_status"
        const val NOTIF_ID = 1
        const val ACTION_STOP = "com.understory.firewall.ACTION_STOP"
        // RFC 5737 192.0.2.0/24 — TEST-NET-1, never routes publicly.
        // We pick a single host inside it for our tun's local address.
        private const val VPN_LOCAL_ADDR = "192.0.2.42"
        // RFC 3849 2001:db8::/32 — the documentation prefix. Same role
        // as the v4 address: a reserved literal Android is happy to bind
        // to but no real host will ever respond to.
        private const val VPN_LOCAL_ADDR_V6 = "2001:db8::1"
        private const val MTU = 1500
        /** Fake DNS IP exposed to apps as their resolver in DNS-redirect
         *  mode. RFC 5737 192.0.2.0/24 (TEST-NET-1) — same /24 as our
         *  tun's local IP, guaranteed to never route on the public
         *  internet. Distinct from VPN_LOCAL_ADDR (192.0.2.42) so the
         *  tun's own address and the resolver IP don't collide. */
        private const val DNS_REDIRECT_FAKE_IP = "192.0.2.43"
        /** How often to re-scan /proc/net for apps using blocked ports.
         *  10s catches new connections quickly enough for typical flows;
         *  longer would let a torrent client run for a full transfer
         *  before getting auto-blocked. Shorter is wasted CPU. */
        private const val PORT_SCAN_INTERVAL_MS = 10_000L
    }
}
