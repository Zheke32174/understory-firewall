plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.ant.emichaosbg"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.ant.emichaosbg"
        minSdk = 26
        targetSdk = 34
        versionCode = 14
        versionName = "3.9-audit"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
        aidl = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-ktx:1.9.1")
    // Optional privileged-execution channel. The app works fully without Shizuku installed;
    // this only enables the read-only diagnostics panel when the user has set it up themselves.
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")
    // Dhizuku client API. This MUST be a real dependency — the earlier reflection-only
    // approach could never work: com.rosan.dhizuku.api.Dhizuku lives in the CLIENT library,
    // not inside the Dhizuku app, so Class.forName() in our process always failed and the
    // tier could never activate. 2.5.3 is pinned deliberately: 2.6.0 requires compileSdk 37
    // (this app targets 34) and 2.5.4+ ship Java 21 bytecode.
    implementation("io.github.iamr0s:Dhizuku-API:2.5.3")

    // Unit tests. org.json is only a STUB in the Android JAR — every method throws
    // "not mocked" under plain JVM tests — so a real implementation has to be on the test
    // classpath or anything touching JSONObject fails for reasons unrelated to the code
    // under test.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
