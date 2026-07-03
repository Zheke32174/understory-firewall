package com.understory.firewall

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.understory.security.Diagnostics
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground service that runs the bundled `dnscrypt-proxy` binary.
 *
 * Activation:
 *   - Started by MainActivity when the user picks a DNSCrypt provider
 *     from DnsPrefsScreen (the protocol field on DnsProvider is
 *     [DnsProtocol.DNSCRYPT]).
 *   - Stopped when the user switches away from DNSCrypt or stops the
 *     firewall altogether.
 *
 * Binary:
 *   - Bundled via tools/fetch-dnscrypt-proxy.sh -> jniLibs/<abi>/
 *     libdnscrypt-proxy.so. Android extracts these to
 *     applicationInfo.nativeLibraryDir at install time, with the
 *     correct ABI for the current device. The .so suffix is the
 *     standard Android trick for shipping non-JNI executables.
 *
 * Runtime contract:
 *   - The proxy listens on 127.0.0.1:[LOCAL_PORT].
 *   - DNS queries from apps don't yet reach this listener — Android's
 *     system DNS resolver doesn't know to route to a private port,
 *     and Private DNS specifiers can't point at loopback.
 *     Phase 3 (userspace packet forwarder in FirewallVpnService) is
 *     what actually wires apps' UDP-port-53 traffic to this listener.
 *     Until then, this service runs the proxy successfully and
 *     surfaces its status in Diagnostics; the listener is reachable
 *     manually for debugging via `dig @127.0.0.1 -p 5354 example.com`
 *     when running with shell access on the device.
 *
 * Process supervision:
 *   - One instance at a time. Repeated start commands are idempotent
 *     (re-config + soft-restart of the binary on stamp change).
 *   - If the binary exits unexpectedly, [maybeRestart] kicks in with
 *     exponential backoff capped at 60s. Crash loops surface in
 *     Diagnostics.
 *   - On stop: SIGTERM via Process.destroy(), 2s grace, then SIGKILL.
 */
class DnsCryptProxyService : Service() {

    private val running = AtomicBoolean(false)
    @Volatile private var process: Process? = null
    private var supervisorThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
            stopProxy()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        startProxy()
        return START_STICKY
    }

    override fun onDestroy() {
        stopProxy()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startProxy() {
        // Re-entrant: stop any prior process before starting fresh.
        // The user may have switched DNSCrypt providers, which writes
        // a new config and needs the binary to re-read it.
        if (running.get()) {
            stopProxy()
        }
        running.set(true)

        val provider = providerForCurrent()
        if (provider == null || provider.dnscryptStamp.isBlank()) {
            Diagnostics.error("firewall.DnsCryptProxy",
                "no DNSCrypt provider selected; refusing to start")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val binary = File(applicationInfo.nativeLibraryDir, "libdnscrypt-proxy.so")
        if (!binary.exists()) {
            Diagnostics.error("firewall.DnsCryptProxy",
                "binary missing at ${binary.absolutePath} — run " +
                    "tools/fetch-dnscrypt-proxy.sh and rebuild")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val configFile = writeConfig(provider)
        Diagnostics.log("firewall.DnsCryptProxy",
            "starting binary=${binary.absolutePath} config=${configFile.absolutePath} " +
                "stamp_id=${provider.id}")

        supervisorThread = Thread({
            var attempt = 0
            while (running.get() && !Thread.currentThread().isInterrupted) {
                attempt++
                val pb = ProcessBuilder(
                    binary.absolutePath,
                    "-config", configFile.absolutePath,
                ).redirectErrorStream(true)
                pb.directory(File(applicationInfo.dataDir))
                val p = runCatching { pb.start() }.getOrNull()
                if (p == null) {
                    Diagnostics.error("firewall.DnsCryptProxy",
                        "ProcessBuilder.start() failed (attempt $attempt)")
                    backoffSleep(attempt)
                    continue
                }
                process = p

                // Drain stdout/stderr line-by-line into Diagnostics so
                // a misconfigured stamp surfaces immediately. The
                // binary's normal log volume is low (a handful of
                // lines on init, periodic certificate-refresh entries).
                runCatching {
                    p.inputStream.bufferedReader().use { br ->
                        while (running.get()) {
                            val line = br.readLine() ?: break
                            Diagnostics.log("firewall.DnsCryptProxy.binary", line)
                        }
                    }
                }
                val exit = runCatching { p.waitFor() }.getOrNull() ?: -1
                Diagnostics.log("firewall.DnsCryptProxy",
                    "binary exited code=$exit attempt=$attempt running=${running.get()}")
                process = null
                if (!running.get()) return@Thread
                backoffSleep(attempt)
            }
        }, "dnscrypt-proxy-supervisor").also { it.start() }
    }

    private fun stopProxy() {
        running.set(false)
        runCatching { supervisorThread?.interrupt() }
        supervisorThread = null
        val p = process
        if (p != null) {
            runCatching { p.destroy() }
            // Grace window for clean shutdown before SIGKILL.
            val died = runCatching { p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS) }
                .getOrDefault(false)
            if (!died) {
                runCatching { p.destroyForcibly() }
            }
        }
        process = null
    }

    private fun providerForCurrent(): DnsProvider? {
        val id = FirewallSettings.getDnsProviderId(applicationContext)
        return runCatching { DnsProvider.byId(id) }.getOrNull()
    }

    /** Write a minimal dnscrypt-proxy.toml config that points at the
     *  user's chosen stamp. The proxy has hundreds of options; we
     *  only set the ones we care about. */
    private fun writeConfig(provider: DnsProvider): File {
        val dir = File(applicationContext.filesDir, "dnscrypt").apply { mkdirs() }
        val configFile = File(dir, "dnscrypt-proxy.toml")
        val toml = buildString {
            appendLine("# Generated by DnsCryptProxyService — DO NOT EDIT BY HAND.")
            appendLine("# Source provider: ${provider.id} (${provider.name})")
            appendLine("listen_addresses = ['127.0.0.1:$LOCAL_PORT']")
            appendLine("server_names = ['user_choice']")
            appendLine("ipv4_servers = true")
            appendLine("ipv6_servers = true")
            appendLine("dnscrypt_servers = true")
            // We provide our own [static] entry below, so disable the
            // automatic public-resolvers download. Saves a network hop
            // at start and keeps the proxy reproducible offline.
            appendLine("require_dnssec = false")
            appendLine("cache = true")
            appendLine("cache_size = 4096")
            appendLine("cache_min_ttl = 600")
            appendLine("cache_max_ttl = 86400")
            appendLine("[static]")
            appendLine("  [static.user_choice]")
            appendLine("    stamp = '${provider.dnscryptStamp}'")
        }
        configFile.writeText(toml, Charsets.UTF_8)
        return configFile
    }

    private fun backoffSleep(attempt: Int) {
        // Exponential 1s, 2s, 4s, ... capped at 60s.
        val seconds = (1L shl (attempt - 1).coerceIn(0, 6)).coerceAtMost(60L)
        runCatching { Thread.sleep(seconds * 1000L) }
    }

    private fun buildNotification(): Notification {
        ensureChannel()
        val pendingMain = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = Intent(this, DnsCryptProxyService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingStop = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("dnscrypt-proxy active")
            .setContentText("DNS routed through 127.0.0.1:$LOCAL_PORT")
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pendingMain)
            .addAction(0, "Stop", pendingStop)
            .build()
    }

    private fun ensureChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "DNSCrypt proxy",
                    NotificationManager.IMPORTANCE_LOW,
                ).apply { description = "DNSCrypt-proxy supervisor status" }
            )
        }
    }

    companion object {
        const val CHANNEL_ID = "dnscrypt_proxy_status"
        const val NOTIF_ID = 2
        const val ACTION_STOP = "com.understory.firewall.dnscrypt.ACTION_STOP"
        /** Loopback port the binary listens on. Picked above the
         *  default 53 (privileged) and above 5353 (mDNS) to avoid
         *  collisions with anything else userland-bindable. */
        const val LOCAL_PORT = 5354

        fun start(ctx: Context) {
            ctx.startForegroundService(Intent(ctx, DnsCryptProxyService::class.java))
        }

        fun stop(ctx: Context) {
            ctx.startForegroundService(
                Intent(ctx, DnsCryptProxyService::class.java).apply { action = ACTION_STOP }
            )
        }
    }
}
