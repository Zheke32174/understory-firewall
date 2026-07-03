package com.understory.security

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.understory.security.ui.theme.LocalSuiteColors
import com.understory.security.ui.theme.LocalUnderstoryThemeActive
import kotlinx.coroutines.delay
import java.util.Locale

/**
 * Shared "suite status" footer rendered at the bottom of every suite
 * app's main screen. Tiny, dim, non-interactive — but it's the smoke
 * test that proves [SuiteCapabilityRegistry] actually works at runtime.
 *
 * If this footer renders the right tier and the right peers on a real
 * device, then the manifest permissions, ContentProvider authorities,
 * package-visibility entries, and cert-pin propagation are all
 * correctly wired together — none of which the compiler can verify on
 * its own.
 *
 * Visual posture: dim grey on near-black, ~11sp, single short line if
 * standalone, two lines if peers present. Designed to not compete with
 * the primary UI — it's an *informational* surface, not interactive.
 *
 * Tokens: when wrapped in `UnderstoryTheme` this reads the design tokens
 * (surface / semantic.dim / semantic.success / error / labelSmall). When an
 * app has not yet adopted the theme it falls back to the exact legacy hexes so
 * the footer looks identical before and after migration (§2.1).
 *
 * A11y (§3 A-6): in production the whole footer sets
 * [clearAndSetSemantics] {} so TalkBack skips this dim, purely-informational
 * smoke-test surface instead of reading four status lines on every screen open.
 */
@Composable
fun SuiteStatusFooter(
    modifier: Modifier = Modifier,
) {
    val ctx = LocalContext.current
    val themed = LocalUnderstoryThemeActive.current
    val semantic = LocalSuiteColors.current

    // Token-or-legacy resolution. Behavior is identical when not themed.
    val containerColor = if (themed) MaterialTheme.colorScheme.surface else Color(0xFF111111)
    val dimColor = if (themed) semantic.dim else Color(0xFF6E6E6E)
    val successColor = if (themed) semantic.success else Color(0xFF7E9E7E)
    val markBg = if (themed) semantic.success.copy(alpha = 0.18f) else Color(0xFF1F3A1F)
    val markFg = if (themed) semantic.success else Color(0xFF81C784)
    val errorColor = if (themed) MaterialTheme.colorScheme.error else Color(0xFFEF5350)
    val statusStyle: TextStyle =
        if (themed) MaterialTheme.typography.labelSmall else TextStyle(fontSize = 9.sp)
    val containerShape = if (themed) MaterialTheme.shapes.small else RoundedCornerShape(6.dp)
    val markShape = if (themed) MaterialTheme.shapes.extraSmall else RoundedCornerShape(3.dp)

    // We snapshot on first composition and on every recomposition that's
    // forced by parent state changes. A future enhancement will subscribe
    // to PACKAGE_ADDED/REMOVED broadcasts to live-update; for the smoke
    // test "did this wire correctly", a single read on screen-show is
    // already the primary signal.
    var snap by remember { mutableStateOf<SuiteCapabilityRegistry.Snapshot?>(null) }
    LaunchedEffect(Unit) {
        snap = runCatching { SuiteCapabilityRegistry.snapshot(ctx) }.getOrNull()
    }

    val s = snap ?: return  // first frame: render nothing rather than flash

    // Eng-only triple-tap → DiagnosticsDump.mark. Three taps within
    // 800 ms total triggers a MARK line in the rolling log file plus
    // a brief on-screen "MARK" pill so the tester knows it landed.
    // The clickable modifier is only attached when the dump is active
    // (eng build); in production the footer remains non-interactive.
    val dumpActive = remember { DiagnosticsDump.isActive() }
    var tapTimes by remember { mutableStateOf<List<Long>>(emptyList()) }
    var markPulse by remember { mutableStateOf(0L) }
    LaunchedEffect(markPulse) {
        // markPulse is the key — when a new tap fires during the delay,
        // this coroutine is cancelled and a fresh one starts, so the
        // pill stays visible for the full 900 ms after the *latest* tap.
        if (markPulse != 0L) {
            delay(900)
            markPulse = 0L
        }
    }

    // A11y: production footer is skipped by TalkBack (§3 A-6). The eng-build
    // triple-tap keeps its clickable but still exposes no a11y text — it's a
    // debug affordance, not a control.
    val a11yModifier = if (dumpActive) Modifier else Modifier.clearAndSetSemantics {}

    val containerModifier = if (dumpActive) {
        modifier
            .fillMaxWidth()
            .background(containerColor, containerShape)
            .clickable {
                val now = System.currentTimeMillis()
                val recent = (tapTimes + now).filter { now - it <= 800L }
                tapTimes = recent
                if (recent.size >= 3) {
                    DiagnosticsDump.mark("footer-triple-tap")
                    Diagnostics.log("SuiteStatusFooter", "triple-tap MARK fired")
                    markPulse = now
                    tapTimes = emptyList()
                }
            }
            .padding(horizontal = 10.dp, vertical = 6.dp)
    } else {
        modifier
            .fillMaxWidth()
            .then(a11yModifier)
            .background(containerColor, containerShape)
            .padding(horizontal = 10.dp, vertical = 6.dp)
    }

    Column(
        modifier = containerModifier,
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        if (markPulse != 0L) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(markBg, markShape)
                    .padding(horizontal = 6.dp, vertical = 2.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "MARK written to dump",
                    color = markFg,
                    style = statusStyle,
                )
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = "suite",
                color = dimColor,
                style = statusStyle,
            )
            Text(
                text = tierLabel(s.tier),
                color = tierColor(s.tier, dimColor),
                style = statusStyle,
            )
        }
        if (s.peers.isEmpty()) {
            Text(
                text = "no peers detected",
                color = dimColor,
                style = statusStyle,
            )
        } else {
            for (peer in s.peers) {
                Text(
                    text = peerLine(peer),
                    color = if (peer.certVerified) successColor else errorColor,
                    style = statusStyle,
                )
            }
        }
        if (s.capabilities.isNotEmpty()) {
            Text(
                text = "peer caps: " + s.capabilities.joinToString(", ") { it.shortName() },
                color = dimColor,
                style = statusStyle,
            )
        }
    }
}

private fun tierLabel(t: SuiteTier): String = when (t) {
    SuiteTier.STANDALONE -> "standalone"
    SuiteTier.PAIR -> "tier-2 (pair)"
    SuiteTier.TRIPLE -> "tier-3 (triple)"
    SuiteTier.MESH -> "tier-4 (mesh)"
}

// Tier tint keeps its own laddered greens/olives (they encode the tier level,
// not a Material role); STANDALONE uses the resolved dim token so it matches
// the surrounding "suite"/"no peers" text.
private fun tierColor(t: SuiteTier, dim: Color): Color = when (t) {
    SuiteTier.STANDALONE -> dim
    SuiteTier.PAIR -> Color(0xFF8AA38A)
    SuiteTier.TRIPLE -> Color(0xFFA3B98A)
    SuiteTier.MESH -> Color(0xFFC9D88A)
}

private fun peerLine(p: PeerInfo): String {
    val pkg = p.packageName.removePrefix("com.understory.")
    val ver = if (p.attestedVersion >= 0) "v${p.attestedVersion}" else "v?"
    val ok = if (p.certVerified) "✓" else "✗ cert"
    return "$pkg $ver $ok"
}

/** Compact label for the capability list: drop _ and lowercase. */
private fun SuiteCapability.shortName(): String =
    name.lowercase(Locale.ROOT).replace('_', '-')
