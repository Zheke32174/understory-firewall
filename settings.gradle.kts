pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}

rootProject.name = "firewall"
include(":common-security")
include(":net-engine")
include(":elevation")

// godwall-next — the from-scratch Godwall rebuild, and the ONLY Godwall app in
// this build. It carries the same applicationId as the retired :firewall module,
// so it REPLACES that app on device.
//
// :firewall is NOT included. It is scrap (REBUILD-CHARTER) and it carries the
// three measured charter violations — a <queries> entry for com.tailscale.ipn,
// the moe.shizuku API permission, and a rikka.shizuku provider — so while it was
// still in the build, the root `assembleDebug` kept building an app that asks for
// the things Godwall replaces, and emitted a second APK contending for the same
// applicationId. The directory stays in the tree as salvage reference only;
// nothing depends on it (it was reachable from settings.gradle.kts and nowhere
// else). SuiteInvariantTest fails the build if it comes back.
include(":godwall-next")
