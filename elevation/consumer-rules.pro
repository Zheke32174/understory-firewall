# consumer-rules.pro — applied to any app that depends on :elevation.
#
# The elevation broker calls two integrations reflectively / across an AIDL
# binder boundary, so their entry points must survive R8 shrinking in the
# consuming app.

# --- Shizuku -----------------------------------------------------------------
# Shizuku.bindUserService instantiates the app-provided UserService class by
# name across the process boundary; keep our shell UserService + its AIDL stub.
-keep class com.understory.elevation.shizuku.ShellUserService { *; }
-keep class com.understory.elevation.IShellService { *; }
-keep class com.understory.elevation.IShellService$Stub { *; }
-keep class com.understory.elevation.IShellService$Stub$Proxy { *; }
# Shizuku's own provider is referenced by name from the consuming app manifest.
-keep class rikka.shizuku.ShizukuProvider { *; }

# --- Dhizuku -----------------------------------------------------------------
# DhizukuDpm reflects DevicePolicyManager.mService and rebuilds an
# IDevicePolicyManager from a wrapped binder; keep the API surface it touches.
-keep class com.rosan.dhizuku.api.** { *; }
-keep class android.app.admin.IDevicePolicyManager { *; }
-keep class android.app.admin.IDevicePolicyManager$Stub { *; }

# --- Public broker API -------------------------------------------------------
# Kept so an app can call the broker after shrinking. Sealed Outcome subclasses
# are matched via `is` checks in app code, so keep the hierarchy.
-keep class com.understory.elevation.Elevation { *; }
-keep class com.understory.elevation.ElevTier { *; }
-keep class com.understory.elevation.ShellResult { *; }
-keep class com.understory.elevation.Outcome { *; }
-keep class com.understory.elevation.Outcome$* { *; }
-keep class com.understory.elevation.PrivateDnsMode { *; }
