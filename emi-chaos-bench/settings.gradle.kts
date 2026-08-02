pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "EMIChaosBench"

// :app is the ORIGINAL Chaos Orb — a half-finished web->native migration whose
// scanners could only ever be started from page JavaScript. It stays in the tree
// as SCRAP REFERENCE and is no longer what we ship.
include(":app")

// :app-next is the from-scratch, fully-native rebuild. Same applicationId as
// :app, so this APK REPLACES that app on device.
include(":app-next")
