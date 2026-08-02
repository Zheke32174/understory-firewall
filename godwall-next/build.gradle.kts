plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

/**
 * godwall-next — the from-scratch rebuild of Godwall.
 *
 * Same applicationId as the old `:firewall` module ON PURPOSE: this APK REPLACES
 * that app on device, and the suite's package-name wiring (cert pin, capability
 * beacon authority, sibling attestation) keeps working unchanged. The old module
 * stays in the tree as scrap reference and is no longer what we ship.
 *
 * libtailscale.aar is the Tailscale data plane (a gomobile-bound Go library, not a
 * Maven artifact). Supply it with -Plibtailscale.aar=<path>, LIBTAILSCALE_AAR=<path>,
 * or by dropping it at godwall-next/libs/libtailscale.aar. When it is present the
 * mesh source set compiles and Godwall IS the tailnet node. When it is absent the
 * build still succeeds and the Mesh screen says, in those words, that the data plane
 * is not in this build — it never pretends a tailnet exists, and it never defers to
 * another app for one.
 */
val libtailscaleAar: File = (
    (project.findProperty("libtailscale.aar") as String?)
        ?: System.getenv("LIBTAILSCALE_AAR")
    )?.let(::File) ?: file("libs/libtailscale.aar")
val hasLibtailscale: Boolean = libtailscaleAar.isFile

android {
    namespace = "com.understory.godwall"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.understory.firewall"
        minSdk = 33
        targetSdk = 35
        versionCode = 3
        versionName = "2.0"
        resourceConfigurations += listOf("en")
        base.archivesName = "godwall"
        buildConfigField("boolean", "HAS_MESH_DATAPLANE", hasLibtailscale.toString())
    }

    sourceSets {
        getByName("main") {
            if (hasLibtailscale) java.srcDir("src/tailscale/java")
        }
    }

    buildTypes {
        debug {
            // Sideload-installable security software: never jdwp-attachable.
            isDebuggable = false
            isJniDebuggable = false
            isPseudoLocalesEnabled = false
            // -PminifyDebug=true shrinks the sideload APK while keeping
            // BuildConfig.DEBUG=true, so SuitePins still checks the DEBUG pin
            // and the committed debug keystore verifies.
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
                "proguard-rules.pro",
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
        buildConfig = true
        aidl = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    lint {
        lintConfig = file("../lint.xml")
        // Lint runs as its own task; assemble must not be gated on style.
        abortOnError = false
        checkReleaseBuilds = false
    }
}

dependencies {
    // Suite chrome + attestation + Diagnostics. Reused, never forked.
    implementation(project(":common-security"))
    // Pure-JVM packet/DNS engine (unit-tested off-device).
    implementation(project(":net-engine"))
    //
    // DELIBERATELY ABSENT: project(":elevation"). That module's privileged path
    // is `dev.rikka.shizuku:api` — i.e. it takes privilege from the Shizuku app.
    // Godwall takes privilege from Yojimbo (see privilege/Privilege.kt), so this
    // module has no Shizuku or Dhizuku dependency at any level.
    //

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    // collectAsStateWithLifecycle — the engine state the shield screen renders is
    // written by the service, so the UI must stop collecting when it is not visible.
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    // StateFlow + the io dispatcher the screens offload SharedPreferences and
    // PackageManager work onto. :common-security keeps this as implementation, so
    // it is declared here rather than inherited.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")

    testImplementation("junit:junit:4.13.2")

    if (hasLibtailscale) {
        implementation(files(libtailscaleAar))
        logger.lifecycle("godwall-next: libtailscale.aar found (${libtailscaleAar.path}) — the mesh node WILL be compiled")
    } else {
        logger.lifecycle("godwall-next: no libtailscale.aar — the Mesh screen will state the data plane is absent from this build")
    }
}
