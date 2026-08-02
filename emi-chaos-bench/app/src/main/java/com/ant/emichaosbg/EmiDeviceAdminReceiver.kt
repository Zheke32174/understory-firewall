package com.ant.emichaosbg

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent

/**
 * Device-admin entry point. Registering this does NOT by itself give the app any power —
 * it is inert until a human explicitly activates it, either by making this app device
 * owner over adb:
 *
 *     adb shell dpm set-device-owner com.ant.emichaosbg/.EmiDeviceAdminReceiver
 *
 * or by granting the app Dhizuku permission (Dhizuku is itself the device owner and
 * delegates to us).
 *
 * Why this exists at all: it is the only route on stock Android by which an app can become
 * resistant to being silently force-stopped — `setUserControlDisabledPackages` (API 30+).
 * That is the concrete answer to "can't be tampered with without appops": once set, the
 * Settings force-stop button is disabled and the AMS path refuses, so stopping the masker
 * takes a deliberate privileged action rather than a background tap.
 *
 * The policies requested in res/xml/device_admin.xml are deliberately minimal. Note what is
 * NOT there: no wipe-data, no reset-password, no watch-login, no disable-keyguard. A masking
 * app has no business holding those, and asking for them would make this receiver a far more
 * attractive thing to compromise than the app it protects.
 */
class EmiDeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
    }

    /** Shown to the user in the confirmation dialog when they go to deactivate admin. */
    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        context.getString(R.string.admin_disable_warning)

    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
    }
}
