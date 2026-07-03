plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.understory.elevation"
    compileSdk = 35

    defaultConfig {
        minSdk = 33
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        // The Shizuku UserService is bound across a process boundary, so the
        // shell contract is an AIDL interface (IShellService) the framework
        // generates a Stub/Proxy for.
        aidl = true
        // No BuildConfig here — the broker never reads BuildConfig.DEBUG, and
        // AGP 8 disables library BuildConfig by default. Keep it off to match
        // :common-backup's lean surface (only :common-security needs it for
        // SuitePins' debug-vs-release cert selection).
        buildConfig = false
    }

    lint {
        lintConfig = file("../lint.xml")
        abortOnError = true
        checkReleaseBuilds = true
    }

    // Robolectric needs the test classpath to include Android resources so the
    // capability/tier unit tests can touch PackageManager shadows without an
    // emulator round-trip.
    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

dependencies {
    // :common-security is pulled in for UnderstoryTheme + SuiteCard tokens the
    // shared ElevationCard renders through, and for Diagnostics tags. It also
    // transitively supplies the Compose BOM coordinates this module compiles
    // against, so we do not re-declare the BOM here — we inherit the exact same
    // pinned Compose versions the rest of the suite uses (no version skew).
    api(project(":common-security"))

    // Compose surface for the shared ElevationCard / ElevationGrantSheet. These
    // are already exposed as api() from :common-security, so they resolve
    // transitively; they are listed compileOnly-style via the transitive api and
    // NOT re-pinned. (Left implicit through :common-security by design.)

    // Coroutines: requestShizuku/requestDhizuku are suspend functions that
    // suspendCancellableCoroutine over the callback grant flows, and runShell is
    // a suspend workhorse. Pinned explicitly so the threading contract does not
    // ride on a transitive version.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // --- Shizuku (optional elevation tier 1) ---------------------------------
    // api:      Shizuku.pingBinder / checkSelfPermission / requestPermission /
    //           bindUserService (the UserServiceArgs pattern).
    // provider: ShizukuProvider — the ContentProvider the CONSUMING app declares
    //           in its manifest so the Shizuku manager can hand this app a binder.
    //           Exposed as api() because the consuming app references
    //           rikka.shizuku.ShizukuProvider by name in ITS manifest and may
    //           reference it in code; api() lets that resolve without the app
    //           re-declaring the provider artifact.
    api("dev.rikka.shizuku:api:13.1.5")
    api("dev.rikka.shizuku:provider:13.1.5")

    // --- Dhizuku (optional elevation tier 2) ---------------------------------
    // Rootless Device-Owner delegate. The library AAR's own manifest already
    // declares `uses-permission com.rosan.dhizuku.permission.API` and the
    // <queries> block needed to see the Dhizuku package, so a consuming app
    // inherits both via manifest merge (documented in README, no per-app copy
    // required). Namespace com.rosan.dhizuku.api; entry class
    // com.rosan.dhizuku.api.Dhizuku. api() so a consuming app that wants to call
    // Dhizuku directly inherits it.
    api("com.github.iamr0s:Dhizuku-API:v2.6.0")

    // JUnit + Robolectric — tier-resolution / capability-predicate unit tests
    // run on the JVM with Android framework shadows (PackageManager present /
    // absent, Shizuku binder unpinged) — no emulator, no real elevation.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.test.ext:junit:1.2.1")
}
