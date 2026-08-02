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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.understory.godwall.R
import com.understory.godwall.privilege.Privilege
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.withContext

/**
 * Where Godwall's elevated capability comes from — and, just as importantly, where it does not.
 *
 * The previous build declared `<queries>` on `moe.shizuku.privileged.api` and
 * `com.rosan.dhizuku` and read its shell tier from them. That was flagged directly at the start
 * of this campaign: *"so it's not dependent on shizuku. make it dependent on yojimbo"*. Yojimbo
 * is the suite's replacement for both, so Godwall reaching around it to the apps Yojimbo
 * supersedes would mean neither app had replaced anything.
 *
 * This screen therefore has no Shizuku path, no Dhizuku path, and no "install X" button. It
 * reports one channel and explains it.
 *
 * Nothing in Godwall's core function depends on this being ATTACHED — the DNS filter, the
 * encrypted upstream, the per-app blackhole, the chain and the mesh node all run unprivileged.
 * Privilege buys the packet-level tier, and until it is attached the UI says so instead of
 * offering controls that would silently do nothing.
 */
@Composable
fun PrivilegeScreen(padding: PaddingValues) {
    val ctx = LocalContext.current
    var revision by remember { mutableStateOf(0) }

    val state by produceState(initialValue = Privilege.State.BROKER_ABSENT, revision) {
        value = withContext(Bg.io) { Privilege.state(ctx) }
    }
    val explanation by produceState(initialValue = "", revision) {
        value = withContext(Bg.io) { Privilege.explain(ctx) }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(padding)
            .verticalScroll(rememberScrollState()),
    ) {
        SuiteCard(modifier = Modifier.padding(UnderstoryTheme.spacing.lg)) {
            Text(
                text = when (state) {
                    Privilege.State.ATTACHED -> stringResource(R.string.priv_attached)
                    Privilege.State.NOT_ATTACHED -> stringResource(R.string.priv_not_attached)
                    Privilege.State.BROKER_ABSENT -> stringResource(R.string.priv_broker_absent)
                },
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                text = explanation,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        SuiteSectionHeader(stringResource(R.string.priv_how))
        SuiteCard(modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.lg)) {
            Text(
                text = stringResource(R.string.priv_how_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        SuiteSectionHeader(stringResource(R.string.priv_without))
        SuiteCard(modifier = Modifier.padding(horizontal = UnderstoryTheme.spacing.lg)) {
            Text(
                text = stringResource(R.string.priv_without_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xl))
    }
}
