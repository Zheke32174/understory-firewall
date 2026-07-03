plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.understory.firewall"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.understory.firewall"
        minSdk = 33
        targetSdk = 35
        versionCode = 2
        versionName = "2.0"
        resourceConfigurations += listOf("en")
        base.archivesName = "firewall"
    }

    buildTypes {
        debug {
            // Match the suite posture: even the debug variant is sideload-
            // installable security software, so it must not be jdwp-attachable.
            isDebuggable = false
            isJniDebuggable = false
            isPseudoLocalesEnabled = false
            isMinifyEnabled = false
            isShrinkResources = false
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
}
