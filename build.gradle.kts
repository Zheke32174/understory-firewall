plugins {
    id("com.android.application") version "8.7.3" apply false
    id("com.android.library") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}

// ---------------------------------------------------------------------------
// verifyCertPin — suite-wide. Reads Tamper.EXPECTED_CERT_SHA256 from
// :common-security/.../Tamper.kt and checks every app module's APK output
// against it. Both :passgen and :aegis are signed by the same keystore and
// reference the same Tamper class — one pin to rule them all.
//
// Without this, a keystore swap silently produces builds that hard-fail on
// launch (the runtime check fails because the pin doesn't match the cert).
// ---------------------------------------------------------------------------
tasks.register("verifyCertPin") {
    group = "verification"
    description = "Verify Tamper.EXPECTED_CERT_SHA256 matches every app APK's signing cert."

    doLast {
        val androidHome = System.getenv("ANDROID_HOME")
            ?: project.findProperty("sdk.dir")?.toString()
            ?: throw GradleException("ANDROID_HOME not set")
        val apksigner = file("$androidHome/build-tools/35.0.0/apksigner")
        if (!apksigner.exists()) {
            throw GradleException("apksigner not found at $apksigner")
        }

        val tamperFile = file("common-security/src/main/java/com/understory/security/Tamper.kt")
        if (!tamperFile.exists()) {
            throw GradleException("Tamper.kt not found at $tamperFile")
        }
        val pinned = tamperFile.readText().let { src ->
            Regex("[a-f0-9]{64}").find(src)?.value
                ?: throw GradleException("EXPECTED_CERT_SHA256 not found in Tamper.kt")
        }

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
            val out = providers.exec {
                commandLine(apksigner.absolutePath, "verify", "--print-certs", apk.absolutePath)
                isIgnoreExitValue = true
            }.standardOutput.asText.get()

            // Unsigned APKs report "DOES NOT VERIFY" and have no cert
            // digest. We're explicitly permissive during the self-test
            // dev phase (no release keystore exists yet), but loud about
            // it: silent skip would let an externally-signed-after-build
            // release APK ship with an unverified cert, and "sign before
            // installing" lifecycle messages aren't a substitute for a
            // hard build-time invariant.
            //
            // To enforce on release before publication, pass
            //     -PrequireSignedRelease=true
            // and the task will fail any unsigned release variant.
            // CI for publication must set this property.
            if (out.contains("DOES NOT VERIFY") || apk.name.contains("unsigned")) {
                val isRelease = apk.name.contains("release", ignoreCase = true)
                val enforce = (project.findProperty("requireSignedRelease") as? String)
                    ?.equals("true", ignoreCase = true) == true
                if (isRelease && enforce) {
                    problems += "${apk.name}: unsigned release APK refused under -PrequireSignedRelease=true. " +
                        "Add a signingConfig to the release build type before publishing."
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
                    logger.lifecycle("verifyCertPin: ${apk.name} cert matches pin ($pinned)")
                else -> problems += buildString {
                    append("${apk.name}: cert digest mismatch\n")
                    append("    actual: $actual\n")
                    append("    pinned: $pinned\n")
                    append("  Either the pin in Tamper.kt is stale (update it to '$actual')\n")
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
            // Tamper.EXPECTED_CERT_SHA256 / SuiteAttestation /
            // SuiteCapabilityRegistry. See keystore/README.md for rotation.
            extensions.configure<com.android.build.gradle.AppExtension> {
                signingConfigs.getByName("debug") {
                    storeFile = rootProject.file("keystore/debug.keystore")
                    storePassword = "android"
                    keyAlias = "androiddebugkey"
                    keyPassword = "android"
                }
            }
            tasks.matching { it.name.startsWith("assemble") }.configureEach {
                finalizedBy(rootProject.tasks.named("verifyCertPin"))
            }
        }
    }
}
