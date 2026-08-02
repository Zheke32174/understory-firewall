# Strip all Log.* calls in shrunk builds.
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
    public static *** wtf(...);
}

# ---------------------------------------------------------------------------
# THE MESH SEAM. This block is load-bearing, and it was found by inspecting the
# shrunk dex rather than by reading the code.
#
# Mesh.linkNative() locates the data plane with
# Class.forName("com.understory.godwall.mesh.LibtailscaleBackend") — the one
# unavoidable reflective hop, because src/main must still compile when the
# source set holding that class was not built. R8 sees no direct reference to
# it, so without this rule it renames the class, Class.forName throws
# ClassNotFoundException, the backend stays null, and the Mesh screen reports
# "not linked" on a build that genuinely contains the data plane.
#
# That is exactly the defect this rebuild exists to remove: a tailnet feature
# that is present in the APK and unreachable at runtime. Do not delete this.
# ---------------------------------------------------------------------------
-keep class com.understory.godwall.mesh.LibtailscaleBackend {
    public <init>(android.net.VpnService);
    public *;
}

# Go calls back into our implementations of these interfaces through JNI, by
# method name and signature resolved at runtime. Keep the interfaces and every
# implementation's members so those lookups still resolve after shrinking.
-keep class libtailscale.** { *; }
-keep class * implements libtailscale.AppContext { *; }
-keep class * implements libtailscale.IPNService { *; }
-keep class * implements libtailscale.VPNServiceBuilder { *; }
-keep class * implements libtailscale.ParcelFileDescriptor { *; }
-keep class * implements libtailscale.InputStream { *; }
-keep class * implements libtailscale.OutputStream { *; }

# ---------------------------------------------------------------------------
# The Yojimbo privilege ABI. Yojimbo binds across a process boundary by these
# exact names: the AIDL stub/proxy and the parcelable's CREATOR are resolved
# reflectively by the binder machinery, so renaming either breaks the handshake
# with a symptom that looks like "Yojimbo never called us".
# ---------------------------------------------------------------------------
-keep class com.understory.godwall.privilege.** { *; }
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

# Settings persist as enum NAMES (upstream transport, block-answer style) and are
# read back with valueOf. Shrinking the synthetic enum members turns a stored
# preference into a silent fall-back to the default.
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
