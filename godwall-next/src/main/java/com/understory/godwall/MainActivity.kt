package com.understory.godwall

import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.core.view.WindowCompat
import com.understory.godwall.ui.GodwallRoot
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.SuiteAttestation
import com.understory.security.Tamper
import com.understory.security.TestingMode
import com.understory.security.ui.components.FatalScreen
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * Godwall's single Activity.
 *
 * It does three things and then gets out of the way: check integrity, set the window posture,
 * and hand off to [GodwallRoot]. Navigation lives entirely in the shared `SuiteNav`, so there
 * is no back handling here — the previous app scattered back logic across the Activity and
 * twenty-odd route arms, which is how it came to disagree with itself.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        DiagnosticsDump.activateIfEng(this)
        Diagnostics.log(TAG, "onCreate")
        super.onCreate(savedInstanceState)

        try {
            initialize()
        } catch (t: Throwable) {
            // Never a silent death. The predecessor crashed on launch with nothing on screen —
            // reported as "godwall crashes instantly" — so an unexpected throw here renders the
            // reason instead of vanishing.
            Diagnostics.error(TAG, "onCreate threw: ${t.javaClass.simpleName}: ${t.message}")
            setContent {
                UnderstoryTheme(accent = UnderstoryAccent.GODWALL) {
                    FatalScreen(
                        title = getString(R.string.fatal_title),
                        reason = getString(R.string.fatal_reason),
                        details = t.toString(),
                    )
                }
            }
        }
    }

    private fun initialize() {
        val debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        if (debuggerAttached ||
            Tamper.check(applicationContext).hardFail ||
            SuiteAttestation.verify(applicationContext).hardFail
        ) {
            setContent {
                UnderstoryTheme(accent = UnderstoryAccent.GODWALL) {
                    FatalScreen(
                        title = getString(R.string.tamper_title),
                        reason = getString(R.string.tamper_reason),
                    )
                }
            }
            return
        }

        if (!TestingMode.ALLOW_SCREENSHOTS) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                setRecentsScreenshotEnabled(false)
            }
        }
        runCatching { WindowCompat.setDecorFitsSystemWindows(window, false) }

        setContent {
            UnderstoryTheme(accent = UnderstoryAccent.GODWALL) {
                GodwallRoot()
            }
        }
    }

    override fun onPause() {
        super.onPause()
        DiagnosticsDump.snapshotState(this, "onPause")
    }

    override fun onResume() {
        super.onResume()
        Tamper.invalidate()
        if (Tamper.check(applicationContext).hardFail) {
            Diagnostics.error(TAG, "tamper hardFail on resume — finishing")
            finishAndRemoveTask()
        }
    }

    private companion object {
        const val TAG = "godwall.MainActivity"
    }
}
