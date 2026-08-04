package com.understory.firewall

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.FileProvider
import com.understory.firewall.tunnel.PcapController
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import java.io.File

/**
 * Packet capture surface (PCAPdroid-style). Toggles capture, shows live counts,
 * and lists / shares / deletes the standard libpcap files the tun produced. Honest
 * about scope: this records the packets Godwall's tun actually sees (DNS in filter
 * mode; restricted-app packets in drop mode), not the whole device.
 */
@Composable
fun PacketCaptureScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var enabled by remember { mutableStateOf(PcapController.isCaptureEnabled(ctx)) }
    var capturing by remember { mutableStateOf(PcapController.isCapturing()) }
    var packets by remember { mutableStateOf(PcapController.packetCount()) }
    var bytes by remember { mutableStateOf(PcapController.byteCount()) }
    var truncated by remember { mutableStateOf(PcapController.wasTruncated()) }
    var files by remember { mutableStateOf(PcapController.captures(ctx)) }
    var status by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        while (true) {
            capturing = PcapController.isCapturing()
            packets = PcapController.packetCount()
            bytes = PcapController.byteCount()
            truncated = PcapController.wasTruncated()
            files = PcapController.captures(ctx)
            kotlinx.coroutines.delay(1000)
        }
    }

    fun share(f: File) {
        runCatching {
            val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.pcapprovider", f)
            val send = Intent(Intent.ACTION_SEND)
                .setType("application/octet-stream")
                .putExtra(Intent.EXTRA_STREAM, uri)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            ctx.startActivity(Intent.createChooser(send, "Share capture").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }.onFailure { status = "Couldn't share: ${it.javaClass.simpleName}" }
    }

    SuiteScaffold(title = "Packet capture", onBack = onBack, showSuiteFooter = false) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            SuiteCard {
                Text("Capture to PCAP", style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    "Records the raw IP packets flowing through Godwall's tun to a standard .pcap " +
                        "file you can open in Wireshark, tcpdump, or PCAPdroid.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                SwitchRow(
                    label = "Capture while the tunnel runs",
                    checked = enabled,
                    onCheckedChange = {
                        enabled = it
                        PcapController.setCaptureEnabled(ctx, it)
                        status = if (it) "Capture will start when the DNS-filter tunnel is armed (or re-arm now)."
                        else { PcapController.stop(); "Capture off. Existing files are kept below." }
                    },
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    if (capturing)
                        "● Capturing: $packets packets, ${bytes / 1024} KiB" +
                            (PcapController.currentFileName()?.let { " → $it" } ?: "")
                    else "Not capturing.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (capturing) UnderstoryTheme.semantic.success else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (truncated) {
                    Text("Capture hit the 64 MiB cap and stopped to protect storage.",
                        style = MaterialTheme.typography.bodySmall, color = UnderstoryTheme.semantic.warning)
                }
                BoundaryText(
                    "Scope: this captures what the tun sees — every app's DNS in DNS-filter mode, or " +
                        "restricted-app packets in per-app-block mode. It is NOT a whole-device capture " +
                        "(that needs a full userspace TCP/IP stack). IPv6 DNS isn't captured in filter mode.",
                )
            }

            SuiteCard {
                Text("Saved captures (${files.size})", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                if (files.isEmpty()) {
                    Text("No captures yet.", style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    files.forEach { f ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(f.name, style = MaterialTheme.typography.bodyMedium)
                                Text("${f.length() / 1024} KiB", style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            SecureOutlinedButton(onClick = { share(f) }) { Text("Share") }
                        }
                        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                    }
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    SecureButton(onClick = {
                        val n = PcapController.deleteAll(ctx)
                        files = PcapController.captures(ctx)
                        status = "Deleted $n capture file(s)."
                    }) { Text("Delete all (except active)") }
                }
            }
            status?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
        }
    }
}
