plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.understory.net.engine"
    compileSdk = 35

    defaultConfig {
        minSdk = 33
        // Consumer proguard so an app minifying against this keeps the
        // salvage classes if it ever wires the optional engine.
        consumerProguardFiles("consumer-rules.pro")
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
    }
}

dependencies {
    // Deliberately no common-security dependency: the packet code is pure
    // JVM (VpnPacketParser) plus a thin Android VpnService-protected
    // forwarder (DnsRedirector). Keeping the module dependency-light is
    // what makes VpnPacketParser unit-testable off the app.
    testImplementation("junit:junit:4.13.2")
}
