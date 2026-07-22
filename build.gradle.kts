plugins {
    id("com.android.application") version "8.7.3" apply false
    id("com.android.library") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}

tasks.register("verifyCertPin") {
    group = "verification"
    description = "Verify every signed release APK matches the offline Understory release certificate."

    doLast {
        val androidHome = System.getenv("ANDROID_HOME")
            ?: project.findProperty("sdk.dir")?.toString()
            ?: throw GradleException("ANDROID_HOME not set")
        val apksigner = file("$androidHome/build-tools/35.0.0/apksigner")
        if (!apksigner.exists()) throw GradleException("apksigner not found at $apksigner")

        val pinsSource = file("common-security/src/main/java/com/understory/security/SuitePins.kt").readText()
        val releasePin = Regex("RELEASE_CERT_SHA256\\s*=\\s*\"([a-f0-9]{64})\"")
            .find(pinsSource)?.groupValues?.get(1)
            ?: throw GradleException("RELEASE_CERT_SHA256 not found")

        val apks = rootDir.walkTopDown()
            .filter { it.isFile && it.extension == "apk" && "androidTest" !in it.name }
            .toList()
        if (apks.isEmpty()) {
            logger.lifecycle("verifyCertPin: no APK outputs yet")
            return@doLast
        }

        val enforceSignedRelease = (project.findProperty("requireSignedRelease") as? String)
            ?.equals("true", ignoreCase = true) == true
        val problems = mutableListOf<String>()
        for (apk in apks) {
            if (!apk.name.contains("release", ignoreCase = true)) {
                logger.lifecycle("verifyCertPin: ${apk.name} is a local debug artifact; no suite identity asserted")
                continue
            }
            val output = providers.exec {
                commandLine(apksigner.absolutePath, "verify", "--print-certs", apk.absolutePath)
                isIgnoreExitValue = true
            }.standardOutput.asText.get()
            if (output.contains("DOES NOT VERIFY") || apk.name.contains("unsigned")) {
                if (enforceSignedRelease) problems += "${apk.name}: unsigned release APK refused"
                else logger.warn("verifyCertPin: ${apk.name} is unsigned; no release identity asserted")
                continue
            }
            val actual = Regex("Signer #1 certificate SHA-256 digest: ([a-f0-9]+)")
                .find(output)?.groupValues?.get(1)
            when {
                actual == null -> problems += "${apk.name}: cannot parse signer certificate"
                actual.equals(releasePin, ignoreCase = true) -> logger.lifecycle("verifyCertPin: ${apk.name} matches RELEASE_CERT_SHA256")
                else -> problems += "${apk.name}: release signer mismatch; actual=$actual expected=$releasePin"
            }
        }
        if (problems.isNotEmpty()) throw GradleException("verifyCertPin failed:\n  ${problems.joinToString("\n  ")}")
    }
}

subprojects {
    afterEvaluate {
        if (plugins.hasPlugin("com.android.application")) {
            extensions.configure<com.android.build.gradle.AppExtension> {
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
