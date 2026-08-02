plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

/**
 * The Tailscale data plane ships as `libtailscale.aar` — a gomobile-bound Go
 * library, NOT a Maven artifact. Upstream tailscale-android declares it as a
 * local file dependency (`implementation ':libtailscale@aar'` over a flatDir),
 * and produces it with `gomobile bind -target android ./libtailscale`.
 *
 * So it is a DROP-IN here: put the aar at `firewall/libs/libtailscale.aar` and
 * the real backend compiles and links. Without it the build still succeeds and
 * TailscaleController honestly reports NOT_LINKED — CI must stay green on a
 * clean checkout, and a missing optional data plane is not a build error.
 *
 * See docs/TAILSCALE-LINKING.md for how to obtain or build the aar and what the
 * backend must implement.
 */
val libtailscaleAar: File = (
    (project.findProperty("libtailscale.aar") as String?)
        ?: System.getenv("LIBTAILSCALE_AAR")
    )?.let(::File) ?: file("libs/libtailscale.aar")
val hasLibtailscale: Boolean = libtailscaleAar.isFile

android {
    namespace = "com.understory.firewall"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.understory.firewall"
        minSdk = 33
        targetSdk = 35
        versionCode = 2
        versionName = "1.0-alpha"
        resourceConfigurations += listOf("en")
        base.archivesName = "firewall"
    }

    // The real Tailscale backend lives in its own source dir and is compiled ONLY
    // when the aar is present, so its imports can reference libtailscale.* directly
    // instead of going through fragile reflection.
    sourceSets {
        getByName("main") {
            if (hasLibtailscale) java.srcDir("src/tailscale/java")
        }
    }

    buildTypes {
        debug {
            // Match the suite posture: even the debug variant is sideload-
            // installable security software, so it must not be jdwp-attachable.
            isDebuggable = false
            isJniDebuggable = false
            isPseudoLocalesEnabled = false
            // Opt-in shrinking for SIDELOAD DELIVERY (-PminifyDebug=true).
            //
            // Why this exists rather than "just ship the release variant": the
            // suite pins its own signing cert, and SuitePins picks the expected
            // pin by BuildConfig.DEBUG. A release-named APK therefore checks
            // itself against RELEASE_CERT_SHA256, so signing one with the debug
            // keystore makes the app correctly report itself as TAMPERED. The
            // debug variant keeps BuildConfig.DEBUG=true and so keeps the debug
            // pin — it stays installable while shrinking ~53 MB to ~12 MB.
            val minifyDebug = (project.findProperty("minifyDebug") as String?) == "true"
            isMinifyEnabled = minifyDebug
            isShrinkResources = minifyDebug
            if (minifyDebug) {
                proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro",
                )
            }
        }
        release {
            isDebuggable = false
            isJniDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
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
        // Generates com.understory.firewall.BuildConfig with the FLAVOR field
        // (prod|eng). The dashboard reads BuildConfig.FLAVOR to gate the
        // Diagnostics dev surface out of the shipping (prod) UI. AGP 8 disables
        // BuildConfig generation by default, so it must be opted in here.
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    lint {
        lintConfig = file("../lint.xml")
        abortOnError = true
        checkReleaseBuilds = true
    }

    flavorDimensions += "channel"
    productFlavors {
        create("prod") {
            dimension = "channel"
        }
        create("eng") {
            dimension = "channel"
            applicationIdSuffix = ".eng"
            versionNameSuffix = "-eng"
        }
    }
}

dependencies {
    implementation(project(":common-security"))
    // Optional-elevation broker (Shizuku / Dhizuku). Rootless-by-default:
    // nothing here runs unless the user installed Shizuku or Dhizuku AND
    // granted this app. Lights up the real "Block background data" / "Suspend
    // app" restrict controls and the "Apply Private DNS now" button; every
    // control degrades honestly to the existing OS deep-link when NONE.
    implementation(project(":elevation"))
    // Salvaged packet engine (design-v2/firewall.md §7). The Standalone
    // engine uses plain app-drop; VpnPacketParser/DnsRedirector are
    // compiled but not called (they survive for a future userspace
    // forwarder and carry their own JVM unit tests). DropStats lives here
    // and IS used by the Standalone-armed drop counter.
    implementation(project(":net-engine"))

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")

    // JVM unit tests for the pure-logic pieces: the SOCKS5 / HTTP-CONNECT
    // handshakes and the hop-persistence round trip. All three are framing code
    // where a silent one-byte or one-field mistake changes where traffic actually
    // goes, so they carry tests that run off-device.
    testImplementation("junit:junit:4.13.2")

    // Optional Tailscale data plane — see the note at the top of this file.
    // files() rather than a flatDir repository so this needs no change to
    // settings.gradle.kts dependency-resolution management.
    if (hasLibtailscale) {
        implementation(files(libtailscaleAar))
        logger.lifecycle("firewall: libtailscale.aar found — Tailscale backend WILL be compiled")
    } else {
        logger.lifecycle("firewall: no libs/libtailscale.aar — Tailscale stays an honest seam (NOT_LINKED)")
    }
}
