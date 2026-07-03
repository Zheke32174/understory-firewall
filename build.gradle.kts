plugins {
    id("com.android.application") version "8.7.3" apply false
    id("com.android.library") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}

// ---------------------------------------------------------------------------
// verifyCertPin — suite-wide. Reads the debug + release pins from
// :common-security/.../SuitePins.kt and checks every app module's APK output
// against the pin for its variant: debug APKs must be signed by the committed
// debug keystore, release APKs by the offline release keystore. One pin pair
// to rule them all.
//
// Without this, a keystore swap silently produces builds that hard-fail on
// launch (the runtime check fails because the pin doesn't match the cert).
// ---------------------------------------------------------------------------
tasks.register("verifyCertPin") {
    group = "verification"
    description = "Verify every app APK's signing cert matches its variant's SuitePins digest."

    doLast {
        val androidHome = System.getenv("ANDROID_HOME")
            ?: project.findProperty("sdk.dir")?.toString()
            ?: throw GradleException("ANDROID_HOME not set")
        val apksigner = file("$androidHome/build-tools/35.0.0/apksigner")
        if (!apksigner.exists()) {
            throw GradleException("apksigner not found at $apksigner")
        }

        val pinsFile = file("common-security/src/main/java/com/understory/security/SuitePins.kt")
        if (!pinsFile.exists()) {
            throw GradleException("SuitePins.kt not found at $pinsFile")
        }
        val pinsSrc = pinsFile.readText()
        fun pin(name: String): String =
            Regex("$name\\s*=\\s*\"([a-f0-9]{64})\"").find(pinsSrc)?.groupValues?.get(1)
                ?: throw GradleException("$name not found in SuitePins.kt")
        val debugPin = pin("DEBUG_CERT_SHA256")
        val releasePin = pin("RELEASE_CERT_SHA256")

        // Iterate every app module's APK output dir. Add new app modules here
        // as they ship — single source of truth so the same pin gates the
        // whole suite.
        val appModules = listOf("firewall")
        val apks = appModules.flatMap { mod ->
            val dir = file("$mod/build/outputs/apk")
            if (dir.exists()) dir.walkTopDown().filter { it.extension == "apk" }.toList()
            else emptyList()
        }
        if (apks.isEmpty()) {
            logger.lifecycle("verifyCertPin: no APK outputs yet; nothing to check")
            return@doLast
        }

        val problems = mutableListOf<String>()
        for (apk in apks) {
            val isRelease = apk.name.contains("release", ignoreCase = true)
            val pinned = if (isRelease) releasePin else debugPin
            val pinName = if (isRelease) "RELEASE_CERT_SHA256" else "DEBUG_CERT_SHA256"
            val out = providers.exec {
                commandLine(apksigner.absolutePath, "verify", "--print-certs", apk.absolutePath)
                isIgnoreExitValue = true
            }.standardOutput.asText.get()

            // Unsigned APKs report "DOES NOT VERIFY" and have no cert
            // digest. We're explicitly permissive during the self-test
            // dev phase (release signing is opt-in via -PreleaseKeystore),
            // but loud about it: silent skip would let an
            // externally-signed-after-build release APK ship with an
            // unverified cert, and "sign before installing" lifecycle
            // messages aren't a substitute for a hard build-time invariant.
            //
            // To enforce on release before publication, pass
            //     -PrequireSignedRelease=true
            // and the task will fail any unsigned release variant.
            // CI for publication must set this property.
            if (out.contains("DOES NOT VERIFY") || apk.name.contains("unsigned")) {
                val enforce = (project.findProperty("requireSignedRelease") as? String)
                    ?.equals("true", ignoreCase = true) == true
                if (isRelease && enforce) {
                    problems += "${apk.name}: unsigned release APK refused under -PrequireSignedRelease=true. " +
                        "Sign it via -PreleaseKeystore=<path> -PreleaseKeystorePassFile=<path> before publishing."
                } else {
                    logger.warn(
                        "verifyCertPin: ${apk.name} is unsigned — pin check SKIPPED. " +
                            "${if (isRelease) "RELEASE variant: do not publish this artifact without signing." else ""}",
                    )
                }
                continue
            }

            val actual = Regex("Signer #1 certificate SHA-256 digest: ([a-f0-9]+)")
                .find(out)?.groupValues?.get(1)
            when {
                actual == null ->
                    problems += "${apk.name}: could not parse cert digest from apksigner output"
                actual.equals(pinned, ignoreCase = true) ->
                    logger.lifecycle("verifyCertPin: ${apk.name} cert matches $pinName ($pinned)")
                else -> problems += buildString {
                    append("${apk.name}: cert digest mismatch\n")
                    append("    actual: $actual\n")
                    append("    pinned: $pinned ($pinName)\n")
                    append("  Either $pinName in SuitePins.kt is stale (update it to '$actual')\n")
                    append("  or this APK was signed by an unexpected keystore.")
                }
            }
        }
        if (problems.isNotEmpty()) {
            throw GradleException("verifyCertPin failed:\n  ${problems.joinToString("\n  ")}")
        }
    }
}

// Wire verifyCertPin to every app module's assemble. Runs after all assembles
// finish so it sees both APKs at once.
subprojects {
    afterEvaluate {
        if (plugins.hasPlugin("com.android.application")) {
            // Pin every app module's debug signing to the project's
            // committed debug.keystore (under android/keystore/) so the cert
            // digest is reproducible across developer machines and matches
            // SuitePins.DEBUG_CERT_SHA256 (consumed by Tamper /
            // SuiteAttestation / SuiteCapabilityRegistry). See
            // keystore/README.md for rotation.
            extensions.configure<com.android.build.gradle.AppExtension> {
                signingConfigs.getByName("debug") {
                    storeFile = rootProject.file("keystore/debug.keystore")
                    storePassword = "android"
                    keyAlias = "androiddebugkey"
                    keyPassword = "android"
                }
                // Release signing is opt-in: the release keystore lives
                // OFFLINE (never committed — see docs/SIGNING.md in
                // understory-common). Wire it per-invocation with
                //     -PreleaseKeystore=<path> -PreleaseKeystorePassFile=<path>
                // PKCS12, alias "understory", key password == store password.
                // Without both properties, release stays unsigned exactly as
                // before (CI builds debug only).
                val releaseKeystore = findProperty("releaseKeystore")?.toString()
                val releasePassFile = findProperty("releaseKeystorePassFile")?.toString()
                if (releaseKeystore != null && releasePassFile != null) {
                    val storePass = rootProject.file(releasePassFile).readText().trim()
                    val releaseSigning = signingConfigs.create("release") {
                        storeFile = rootProject.file(releaseKeystore)
                        storeType = "PKCS12"
                        storePassword = storePass
                        keyAlias = "understory"
                        keyPassword = storePass
                    }
                    buildTypes.getByName("release").signingConfig = releaseSigning
                }
            }
            tasks.matching { it.name.startsWith("assemble") }.configureEach {
                finalizedBy(rootProject.tasks.named("verifyCertPin"))
            }
        }
    }
}
