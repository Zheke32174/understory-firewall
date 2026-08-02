package com.ant.emichaosbg

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.WindowCompat
import com.ant.emichaosbg.core.Sentinel
import com.ant.emichaosbg.core.SentinelService
import com.ant.emichaosbg.ui.ChaosOrbTheme
import com.ant.emichaosbg.ui.OrbRoot

/**
 * Chaos Orb's single Activity. It does four things and gets out of the way:
 *
 *  1. Builds the detector registry ([Sentinel.init]).
 *  2. STARTS DETECTION. This is the line whose absence produced "security
 *     scanners not working". In the previous build the only starter of ScanEngine,
 *     BleWatcher, the escalation/cell/net timer and the tower timer was
 *     MaskerService, and the only two callers of MaskerService were
 *     `@JavascriptInterface` methods on the WebView bridge. Launch the app, never
 *     press GO on the Masker tab, and not one scanner ever ran.
 *  3. Asks for the permissions the detectors need, once, and then starts anyway —
 *     each detector reports honestly what it could not do rather than pretending.
 *  4. Hands off to [OrbRoot].
 *
 * There is no WebView here, and no WebView anywhere in this module.
 */
class MainActivity : ComponentActivity() {

    private val permissions = ActivityResultContracts.RequestMultiplePermissions()

    private val askPermissions = registerForActivityResult(permissions) {
        // Whatever the answer, detection starts. A denied permission narrows what
        // can be observed; it does not stop the app from observing what it can, and
        // every screen names the permission it is missing.
        startEverything()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runCatching { WindowCompat.setDecorFitsSystemWindows(window, false) }

        Sentinel.init(applicationContext)

        val wanted = buildList {
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            add(Manifest.permission.ACCESS_COARSE_LOCATION)
            add(Manifest.permission.READ_PHONE_STATE)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                add(Manifest.permission.BLUETOOTH_SCAN)
                add(Manifest.permission.BLUETOOTH_CONNECT)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }.toTypedArray()

        // The permission round trip must land BEFORE the detectors read a radio,
        // or the first Wi-Fi and BLE sweep is thrown away for a reason the user
        // never sees. RECORD_AUDIO is deliberately NOT in this set — it is asked
        // for on the Mask screen, at the moment the user turns the mic on.
        var asked = false
        runCatching {
            askPermissions.launch(wanted)
            asked = true
        }
        if (!asked) startEverything()

        setContent {
            ChaosOrbTheme {
                OrbRoot(onMinimise = { moveTaskToBack(true) })
            }
        }
    }

    private fun startEverything() {
        // Detection starts here, natively. The service that follows keeps it alive
        // with the app backgrounded — it is not what permits it to run.
        runCatching { Sentinel.startDetection() }
        runCatching { SentinelService.start(this) }
    }
}
