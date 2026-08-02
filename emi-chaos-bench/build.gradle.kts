// Plugin versions are shared by every module in this nested build. They were
// bumped from AGP 8.5.2 / Kotlin 1.9.24 so :app-next can use the Kotlin 2.0
// Compose compiler plugin and the same Compose BOM the rest of the suite is on.
// :app (the scrap module) is untouched on disk and simply rides the newer
// toolchain; it is no longer what we ship.
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}
