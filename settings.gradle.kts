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
include(":firewall")

// godwall-next — the from-scratch Godwall rebuild. Same applicationId as
// :firewall, so it REPLACES that app on device. :firewall stays in the tree as
// scrap reference and is no longer what we ship.
include(":godwall-next")
