# Chaos Orb (app-next) — shrink rules.
#
# The app carries no reflection-driven framework, no JSON binding library and no
# WebView bridge, so almost nothing needs keeping. The two exceptions are the
# components the SYSTEM instantiates by name from the manifest, which R8 cannot
# see a call site for.

-keep class com.ant.emichaosbg.MainActivity { *; }
-keep class com.ant.emichaosbg.core.SentinelService { *; }
-keep class com.ant.emichaosbg.OverlayWatch { *; }

# Keystore / crypto provider names are strings; keep the javax.crypto surface we
# call reflectively through KeyInfo.
-keep class android.security.keystore.** { *; }

-dontwarn org.jetbrains.annotations.**
