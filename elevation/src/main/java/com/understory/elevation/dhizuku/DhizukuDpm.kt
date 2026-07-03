package com.understory.elevation.dhizuku

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import com.rosan.dhizuku.api.Dhizuku

/**
 * Builds a **delegated** [DevicePolicyManager] whose privileged calls execute
 * as the Dhizuku Device Owner, and exposes the DPM operations the broker needs.
 *
 * How the delegation works (the sanctioned Dhizuku recipe):
 *   1. Get the app's ordinary [DevicePolicyManager]. Its private `mService`
 *      field is an `IDevicePolicyManager` binder proxy.
 *   2. Wrap that binder with [Dhizuku.binderWrapper] — every transact on the
 *      wrapped binder is re-issued *by the Dhizuku server process*, which holds
 *      Device-Owner rights.
 *   3. Rebuild an `IDevicePolicyManager` from the wrapped binder and set it back
 *      onto a DPM instance via reflection.
 * The result is a DPM that runs owner-only APIs (setGlobalSetting,
 * setPermissionGrantState, setApplicationHidden, setPackagesSuspended,
 * setUserRestriction) without our app being the owner.
 *
 * The admin [ComponentName] passed to those APIs is Dhizuku's own
 * device-admin component ([Dhizuku.getOwnerComponent]), NOT ours.
 *
 * Every method is defensive: reflection or a failed transact yields `false` /
 * an exception the caller turns into [com.understory.elevation.Outcome.Failed],
 * never a crash. All of this is inert unless Dhizuku is installed, active as
 * owner, and this app's Dhizuku permission is granted (the broker gates first).
 */
internal object DhizukuDpm {

    /**
     * Obtain a delegated DPM + the owner admin component, or null if Dhizuku is
     * unavailable / delegation could not be wired.
     */
    private fun delegated(ctx: Context): Pair<DevicePolicyManager, ComponentName>? = runCatching {
        // Ensure the Dhizuku binder is live for this process.
        if (!Dhizuku.init(ctx)) return null
        if (!Dhizuku.isPermissionGranted()) return null

        val admin = Dhizuku.getOwnerComponent(ctx) ?: return null

        val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

        // DevicePolicyManager.mService : android.app.admin.IDevicePolicyManager
        val mServiceField = DevicePolicyManager::class.java
            .getDeclaredField("mService")
            .apply { isAccessible = true }
        val realService = mServiceField.get(dpm) ?: return null

        // IDevicePolicyManager interface + its Stub.asInterface(IBinder).
        val iDpmClass = Class.forName("android.app.admin.IDevicePolicyManager")
        val stubClass = Class.forName("android.app.admin.IDevicePolicyManager\$Stub")

        // realService.asBinder()  ->  wrap  ->  Stub.asInterface(wrapped)
        val asBinder = realService.javaClass.getMethod("asBinder")
        val realBinder = asBinder.invoke(realService) as android.os.IBinder
        val wrapped = Dhizuku.binderWrapper(realBinder)
        val asInterface = stubClass.getMethod("asInterface", android.os.IBinder::class.java)
        val wrappedService = asInterface.invoke(null, wrapped)

        // Build a fresh DPM and inject the wrapped service so we don't mutate the
        // app's shared system DPM instance.
        val delegatedDpm = newDpm(ctx)
        mServiceField.set(delegatedDpm, iDpmClass.cast(wrappedService))
        delegatedDpm to admin
    }.getOrNull()

    private fun newDpm(ctx: Context): DevicePolicyManager {
        // The public constructor is hidden; reflect the (Context, IDevicePolicyManager)
        // or (Context, Handler) constructor. Fall back to the system instance if
        // construction is unavailable (older/newer platform shapes) — injecting
        // onto the shared instance still works, it is just less isolated.
        return runCatching {
            val ctor = DevicePolicyManager::class.java
                .getDeclaredConstructor(Context::class.java, android.os.Handler::class.java)
                .apply { isAccessible = true }
            ctor.newInstance(ctx, null)
        }.getOrElse {
            ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        }
    }

    /** True when a delegated owner DPM can currently be wired. */
    fun isOwnerDelegate(ctx: Context): Boolean = delegated(ctx) != null

    // ---- Owner-privileged operations. Each returns true on success. ---------

    fun setGlobalSetting(ctx: Context, key: String, value: String): Boolean = runCatching {
        val (dpm, admin) = delegated(ctx) ?: return false
        dpm.setGlobalSetting(admin, key, value)
        true
    }.getOrDefault(false)

    fun setPackagesSuspended(ctx: Context, pkg: String, suspended: Boolean): Boolean = runCatching {
        val (dpm, admin) = delegated(ctx) ?: return false
        // Returns the packages it FAILED to suspend; empty => success.
        val failed = dpm.setPackagesSuspended(admin, arrayOf(pkg), suspended)
        failed.isEmpty()
    }.getOrDefault(false)

    fun setApplicationHidden(ctx: Context, pkg: String, hidden: Boolean): Boolean = runCatching {
        val (dpm, admin) = delegated(ctx) ?: return false
        dpm.setApplicationHidden(admin, pkg, hidden)
    }.getOrDefault(false)

    fun setPermissionGrantState(
        ctx: Context,
        pkg: String,
        permission: String,
        grantState: Int,
    ): Boolean = runCatching {
        val (dpm, admin) = delegated(ctx) ?: return false
        dpm.setPermissionGrantState(admin, pkg, permission, grantState)
    }.getOrDefault(false)

    fun setUserRestriction(ctx: Context, key: String, enable: Boolean): Boolean = runCatching {
        val (dpm, admin) = delegated(ctx) ?: return false
        if (enable) dpm.addUserRestriction(admin, key) else dpm.clearUserRestriction(admin, key)
        true
    }.getOrDefault(false)
}
