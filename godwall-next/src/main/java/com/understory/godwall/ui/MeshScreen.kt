package com.understory.godwall.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.understory.godwall.R
import com.understory.godwall.mesh.Mesh
import com.understory.godwall.mesh.MeshSettings
import androidx.compose.runtime.rememberCoroutineScope
import com.understory.security.SecureButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The mesh node Godwall runs itself.
 *
 * There is no button here that opens another app, and no status line that reports on one. That
 * is the point of the screen: Godwall *is* the node. When the data plane is absent from the
 * build, the banner says exactly that — it does not offer to hand the user off to the app this
 * one replaces.
 */
@Composable
fun MeshScreen(padding: PaddingValues) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var revision by remember { mutableStateOf(0) }
    var actionResult by remember { mutableStateOf("") }

    val status = remember(revision) { Mesh.status(ctx) }
    var loginServer by remember(revision) { mutableStateOf(MeshSettings.loginServer(ctx)) }
    var authKey by remember(revision) { mutableStateOf(MeshSettings.authKey(ctx)) }
    var exitNode by remember(revision) { mutableStateOf(MeshSettings.exitNode(ctx)) }
    var hostname by remember(revision) { mutableStateOf(MeshSettings.hostname(ctx)) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(padding)
            .verticalScroll(rememberScrollState()),
    ) {
        SuiteCard(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
            Text(
                text = stringResource(R.string.mesh_state, status.state.name),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (status.detail.isNotBlank()) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    text = status.detail,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (status.tailnetIps.isNotEmpty()) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    text = stringResource(
                        R.string.mesh_ips,
                        status.tailnetIps.joinToString(", "),
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (status.authUrl.isNotBlank()) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    text = stringResource(R.string.mesh_auth_url, status.authUrl),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            if (!Mesh.compiledIn) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text(
                    text = stringResource(R.string.mesh_absent_help),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            // The node runs inside Godwall's own VPN slot, so the slot has to be held
            // before there is anything for the data plane to build a tun on. Saying that
            // is the honest alternative to a Start button that silently does nothing.
            if (Mesh.awaitingSlot()) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                Text(
                    text = stringResource(R.string.mesh_needs_slot),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (actionResult.isNotBlank()) {
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    text = actionResult,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.md))
            SecureButton(
                // Disabled rather than hidden: a control the user can see and cannot press,
                // next to a sentence saying why, is honest. A missing control just looks broken.
                enabled = Mesh.compiledIn && !Mesh.awaitingSlot(),
                onClick = {
                    // Starting the node boots Go and then talks to its local API, so it is
                    // never run on the composition thread.
                    scope.launch {
                        withContext(Bg.io) {
                            if (status.state == Mesh.State.RUNNING) Mesh.stop(ctx) else Mesh.start(ctx)
                        }
                        revision++
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (status.state == Mesh.State.RUNNING) stringResource(R.string.mesh_stop)
                    else stringResource(R.string.mesh_start),
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SecureButton(
                enabled = Mesh.compiledIn && !Mesh.awaitingSlot(),
                onClick = {
                    scope.launch {
                        actionResult = withContext(Bg.io) { Mesh.requestLogin() }
                        revision++
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.mesh_login))
            }
        }

        SuiteSectionHeader(stringResource(R.string.mesh_node))
        SuiteCard(modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.lg)) {
            Text(
                text = stringResource(R.string.mesh_settings_note),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        OutlinedTextField(
            value = hostname,
            onValueChange = { hostname = it; MeshSettings.setHostname(ctx, it) },
            singleLine = true,
            label = { Text(stringResource(R.string.mesh_hostname)) },
            modifier = Modifier.fillMaxWidth().padding(horizontal = UnderstoryTheme.spacing.lg),
        )
        OutlinedTextField(
            value = loginServer,
            onValueChange = { loginServer = it; MeshSettings.setLoginServer(ctx, it) },
            singleLine = true,
            label = { Text(stringResource(R.string.mesh_login_server)) },
            modifier = Modifier.fillMaxWidth().padding(UnderstoryTheme.spacing.lg),
        )
        OutlinedTextField(
            value = authKey,
            onValueChange = { authKey = it; MeshSettings.setAuthKey(ctx, it) },
            singleLine = true,
            label = { Text(stringResource(R.string.mesh_auth_key)) },
            modifier = Modifier.fillMaxWidth().padding(horizontal = UnderstoryTheme.spacing.lg),
        )
        OutlinedTextField(
            value = exitNode,
            onValueChange = { exitNode = it; MeshSettings.setExitNode(ctx, it) },
            singleLine = true,
            label = { Text(stringResource(R.string.mesh_exit_node)) },
            modifier = Modifier.fillMaxWidth().padding(UnderstoryTheme.spacing.lg),
        )

        SwitchRow(
            label = stringResource(R.string.mesh_accept_routes),
            supporting = stringResource(R.string.mesh_accept_routes_help),
            checked = MeshSettings.acceptRoutes(ctx),
            onCheckedChange = { MeshSettings.setAcceptRoutes(ctx, it); revision++ },
        )
        SwitchRow(
            label = stringResource(R.string.mesh_accept_dns),
            supporting = stringResource(R.string.mesh_accept_dns_help),
            checked = MeshSettings.acceptDns(ctx),
            onCheckedChange = { MeshSettings.setAcceptDns(ctx, it); revision++ },
        )
        SwitchRow(
            label = stringResource(R.string.mesh_advertise_exit),
            supporting = stringResource(R.string.mesh_advertise_exit_help),
            checked = MeshSettings.advertiseExit(ctx),
            onCheckedChange = { MeshSettings.setAdvertiseExit(ctx, it); revision++ },
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
    }
}
