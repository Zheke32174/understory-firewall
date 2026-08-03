package com.understory.godwall

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * THE INVARIANT, enforced mechanically.
 *
 *   "If it has to ask the thing it replaces, it has not replaced it."
 *   — docs/REBUILD-CHARTER.md
 *
 * The charter states this rule and supplies a grep for it. A grep nobody runs is
 * a rule nobody keeps, so this is that grep as a build-failing test.
 *
 * Godwall **is** the Tailscale node and draws its privilege from **Yojimbo**.
 * Therefore no module in this build may:
 *   - declare `<queries>`/`<package>` visibility of Tailscale, Shizuku or Dhizuku,
 *   - hold a Shizuku/Dhizuku permission,
 *   - or call `getLaunchIntentForPackage` on any of them.
 *
 * Scope is derived from `settings.gradle.kts` — only modules actually in the
 * build are scanned, so retiring a scrap module removes it from scope
 * automatically and no allowlist can silently rot.
 *
 * Comments are stripped before scanning, deliberately: the correct modules
 * *name* these packages in comments to record why they are absent (see
 * `godwall-next/src/main/AndroidManifest.xml` and `mesh/Mesh.kt`). Explaining
 * the absence is the opposite of the violation, and must not trip the guard.
 */
class SuiteInvariantTest {

    /** Packages Godwall REPLACES — never to be queried, permitted, or launched. */
    private val forbidden = listOf(
        "com.tailscale.ipn",
        "moe.shizuku",
        "com.rosan.dhizuku",
        "rikka.shizuku",
    )

    private fun repoRoot(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            if (File(dir, "settings.gradle.kts").isFile) return dir
            dir = dir.parentFile
        }
        fail("could not locate repo root (no settings.gradle.kts above ${System.getProperty("user.dir")})")
        error("unreachable")
    }

    /** Module dirs from `include(":name")` lines — the real build scope. */
    private fun modulesInBuild(root: File): List<File> {
        val settings = File(root, "settings.gradle.kts").readText()
        val re = Regex("""^\s*include\(\s*"(:[^"]+)"\s*\)""", RegexOption.MULTILINE)
        return re.findAll(settings)
            .map { it.groupValues[1].removePrefix(":").replace(':', '/') }
            .map { File(root, it) }
            .filter { it.isDirectory }
            .toList()
    }

    private fun stripXmlComments(s: String) = s.replace(Regex("""(?s)<!--.*?-->"""), "")

    private fun stripKotlinComments(s: String) =
        s.replace(Regex("""(?s)/\*.*?\*/"""), "").replace(Regex("""//[^\n]*"""), "")

    private fun sourceFiles(module: File, ext: String): List<File> =
        module.walkTopDown()
            .onEnter { it.name != "build" && it.name != ".git" }
            .filter { it.isFile && it.name.endsWith(ext) }
            .toList()

    @Test
    fun noModuleInTheBuildAsksForWhatGodwallReplaces() {
        val root = repoRoot()
        val modules = modulesInBuild(root)
        // Guard the guard: an empty scope would pass vacuously — a false all-clear,
        // which is exactly the failure mode the charter calls out.
        assertTrue("no modules resolved from settings.gradle.kts", modules.isNotEmpty())

        val violations = mutableListOf<String>()

        for (module in modules) {
            for (manifest in sourceFiles(module, "AndroidManifest.xml")) {
                val body = stripXmlComments(manifest.readText())
                for (pkg in forbidden) {
                    if (body.contains(pkg)) {
                        violations += "${manifest.relativeTo(root)} declares '$pkg'"
                    }
                }
            }
            for (kt in sourceFiles(module, ".kt")) {
                if (kt.name == "SuiteInvariantTest.kt") continue // the guard names them by design
                val body = stripKotlinComments(kt.readText())
                for (pkg in forbidden) {
                    if (body.contains("\"$pkg") ) {
                        violations += "${kt.relativeTo(root)} references '$pkg'"
                    }
                }
            }
        }

        if (violations.isNotEmpty()) {
            fail(
                "REBUILD-CHARTER invariant violated — Godwall must not ask for what it " +
                    "replaces (Tailscale / Shizuku / Dhizuku):\n" +
                    violations.joinToString("\n") { "  - $it" },
            )
        }
    }

    @Test
    fun scrapFirewallModuleIsNotInTheBuild() {
        val root = repoRoot()
        val names = modulesInBuild(root).map { it.name }
        assertTrue(
            "the scrap ':firewall' module is back in settings.gradle.kts; godwall-next " +
                "replaces it (same applicationId) and :firewall carries the charter violations",
            "firewall" !in names,
        )
        assertTrue("godwall-next must be in the build", "godwall-next" in names)
    }
}
