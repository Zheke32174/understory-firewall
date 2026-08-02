plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

/**
 * app-next — the from-scratch Chaos Orb rebuild.
 *
 * SAME applicationId AS :app ON PURPOSE. This APK REPLACES the old Chaos Orb on
 * device and the suite's package-name wiring keeps working. :app stays in the
 * tree as scrap reference.
 *
 * WHAT IS DELIBERATELY ABSENT, and why:
 *   - No `dev.rikka.shizuku:*`. Yojimbo IS Shizuku; compiling against the app we
 *     replace is the invariant violation the last build shipped.
 *   - No `io.github.iamr0s:Dhizuku-API`. Same reason.
 *   - No WebView, no assets/index.html, no @JavascriptInterface anywhere. The
 *     half-finished web->native migration is the direct cause of "menu half non
 *     existent, security scanners not working": the only two call sites that
 *     started the scanners were both page JavaScript.
 *   - No android.permission.INTERNET. A counter-surveillance tool that can open
 *     a socket is a contradiction, and it is what the old mesh-node needed. The
 *     one detector that wanted it (the Frida loopback-port probe) is dropped and
 *     the App-integrity screen says so in those words rather than pretending.
 */
android {
    namespace = "com.ant.emichaosbg"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.ant.emichaosbg"
        minSdk = 26
        targetSdk = 34
        versionCode = 20
        versionName = "4.0-native"
        base.archivesName = "chaos-orb"
        resourceConfigurations += listOf("en")
    }

    signingConfigs {
        // The suite pins its signing cert (common-security/SuitePins.kt). This
        // nested build is not a subproject of the suite root, so the root's
        // signing wiring does not reach here — it is pinned explicitly to the
        // same committed keystore so verifyCertPin and the runtime cert check in
        // AppIntegrity agree with every sibling app.
        getByName("debug") {
            storeFile = rootProject.file("../keystore/debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    buildTypes {
        debug {
            // Sideloaded security software: never jdwp-attachable.
            isDebuggable = false
            isJniDebuggable = false
            // -PminifyDebug=true shrinks the sideload APK while keeping
            // BuildConfig.DEBUG=true, so the DEBUG cert pin stays the one
            // checked and the committed debug keystore verifies.
            val minifyDebug = (project.findProperty("minifyDebug") as String?) == "true"
            isMinifyEnabled = minifyDebug
            isShrinkResources = minifyDebug
            if (minifyDebug) {
                proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro",
                )
            }
            signingConfig = signingConfigs.getByName("debug")
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
    }
    packaging {
        resources.excludes += setOf(
            "/META-INF/{AL2.0,LGPL2.1}",
            "DebugProbesKt.bin",
            "kotlin-tooling-metadata.json",
        )
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // org.json is a STUB in the Android JAR — every method throws "not mocked"
    // under a plain JVM test — so a real implementation has to be on the test
    // classpath or anything touching JSONObject fails for reasons unrelated to
    // the code under test.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
