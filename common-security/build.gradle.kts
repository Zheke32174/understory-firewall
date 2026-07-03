plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.understory.security"
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
        // BuildConfig.DEBUG drives SuitePins' debug-vs-release cert-pin
        // selection; AGP 8 disables library BuildConfig by default.
        buildConfig = true
    }

    lint {
        lintConfig = file("../lint.xml")
        abortOnError = true
        checkReleaseBuilds = true
    }

    // Robolectric needs the test classpath to include Android resources;
    // includeAndroidResources lets unit tests touch resources / framework
    // shadowed by Robolectric without an emulator round-trip.
    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    // Promoted to api() so apps inherit the shared design-system surface
    // (UnderstoryTheme, SuiteScaffold, state composables) without having to
    // re-declare these Compose artifacts. Apps already depend on the same BOM
    // coordinates, so promotion is additive — it only widens visibility.
    api("androidx.compose.foundation:foundation")
    api("androidx.compose.material3:material3")
    api("androidx.compose.ui:ui")
    // Scaffold/dialog icons for the design system — Icons.Filled.Warning and
    // Icons.AutoMirrored.Filled.ArrowBack. Version is BOM-managed. api() so an
    // app that renders these shared components inherits the artifact without
    // re-declaring it (passgen already declares it directly, which is
    // compatible — same coordinate).
    api("androidx.compose.material:material-icons-extended")
    // androidx.activity.compose for BackHandler in shared composables
    // (e.g. KeepAliveBackHandler).
    implementation("androidx.activity:activity-compose:1.9.3")

    // Bg.io / Bg.cpu / produceUiState — the suite's off-main-thread convention.
    // Already present transitively via Compose; pinned explicitly so the crypto/
    // IO threading contract does not depend on a transitive version.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // BouncyCastle: Base32 encoding for HotpSecret (RFC 4648 compatible
    // with authenticator apps). Pure-Java, no native deps. Both :passgen
    // and :aegis transitively get this through :common-security via api().
    api("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // Robolectric — JVM-side Android framework shadow for running unit
    // tests that exercise Activity lifecycle / Compose / Android APIs
    // without an emulator. Lets us catch JVM-runtime regressions
    // (e.g. rememberSaveable AutoSaver behavior) before shipping.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.test.ext:junit:1.2.1")
}
