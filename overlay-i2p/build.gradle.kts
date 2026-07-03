plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.understory.overlay.i2p"
    compileSdk = 35

    defaultConfig {
        minSdk = 33
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    lint {
        lintConfig = file("../lint.xml")
        abortOnError = true
        checkReleaseBuilds = true
    }
}

dependencies {
    // Compose used only for MutableState in the I2pStatus singleton —
    // any consumer (browser, future firewall integration) reads it from
    // a Composable and gets reactive updates without an extra coroutines
    // bridge. Kept as a transitive `api` dep so consumers don't need a
    // separate compose-runtime line for this module's API surface.
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    api(composeBom)
    api("androidx.compose.runtime:runtime")

    // Foreground service notification builder.
    implementation("androidx.core:core-ktx:1.15.0")

    // JUnit for the provider catalog + status singleton tests. No
    // Robolectric needed — I2pStatus uses Compose mutableStateOf which
    // runs fine on pure JVM, and I2pProvider is plain data classes.
    testImplementation("junit:junit:4.13.2")
}
