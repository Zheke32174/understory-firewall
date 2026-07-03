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
        versionCode = 1
        versionName = "0.1-skeleton"
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
    // Overlay status singletons — read-only consumption to render the
    // active proxy in firewall's posture banner and to gate the
    // Overlay-routing toggle. We never start an overlay daemon from
    // firewall (same-UID rule); the browser owns daemon lifecycle.
    implementation(project(":overlay-i2p"))
    implementation(project(":overlay-lokinet"))
    implementation(project(":overlay-yggdrasil"))

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
}
