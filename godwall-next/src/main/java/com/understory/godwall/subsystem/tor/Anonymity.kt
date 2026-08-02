package com.understory.godwall.subsystem.tor

import android.content.Context
import android.os.Build
import com.understory.godwall.subsystem.PrefixInstaller
import com.understory.security.Diagnostics
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.ZipFile

/**
 * The honest gate in front of the Anonymity backend, and the step that seeds its
 * binaries into the prefix.
 *
 * ## The payload this capability lives or dies by
 *
 * Tor and i2pd are per-ABI ELF binaries built in Gedsh's separate toolchain repos;
 * InviZible ships them in `assets/` renamed `.mp3` (docs/DONOR-ASSETS.md, row
 * "InviZible Pro | tor, i2pd ELF" — an OPEN payload). Godwall carries them the way
 * `tools/donor-assets/fetch.sh` prescribes: as `jniLibs/<abi>/lib{tor,i2pd}.so`, so
 * the platform packages them and marks them executable. On a clean checkout they are
 * NOT present, and the build still succeeds — a missing optional payload is not a
 * build error, exactly as with libtailscale.
 *
 * ## Why this probes the APK rather than trusting a build flag
 *
 * Bootstrap.kt sets the house rule: never a hardcoded guess, always probe the actual
 * artifact. So [torPresent] et al. open Godwall's own APK and look for the real
 * `lib/<abi>/lib*.so` entry for this device's ABI. That works whether or not native
 * libs are extracted at install time, and it can never report a binary this build
 * does not carry. Present ⇒ the backend is real; absent ⇒ every Anonymity control
 * reports absent, naming the missing binary, and no screen claims Tor or I2P is
 * running.
 *
 * ## Getting the bytes into the prefix
 *
 * The daemons run as uid 2000 out of `/data/local/tmp/godwall/usr/bin`, not from the
 * app's own `nativeLibraryDir`. The APK is world-readable, so Yojimbo's shell unzips
 * the binary straight out of it into the prefix and chmods it — the same trick
 * [PrefixInstaller] uses for the bootstrap, and it needs no storage permission and no
 * temp file another app could tamper with.
 */
object Anonymity {

    private const val TAG = "godwall.subsystem.tor.Anonymity"

    /** One native payload: the `lib*.so` in the APK and where it lands in the prefix. */
    enum class Binary(val libName: String, val prefixDest: String, val label: String) {
        TOR("libtor.so", "usr/bin/tor", "Tor"),
        I2PD("libi2pd.so", "usr/bin/i2pd", "i2pd"),
        OBFS4PROXY("libobfs4proxy.so", "usr/bin/obfs4proxy", "obfs4proxy"),
        SNOWFLAKE("libsnowflake.so", "usr/bin/snowflake-client", "snowflake-client"),
    }

    /** Whether this build carries the Anonymity backend at all — the anchor is tor. */
    enum class State {
        /** Neither tor nor i2pd is in this build. Nothing runs; nothing pretends to. */
        ABSENT,

        /** At least the tor binary is bundled for this device's ABI. */
        BUNDLED,
    }

    private val presenceCache = ConcurrentHashMap<String, Boolean>()

    @Volatile
    private var cachedAbi: String? = null

    @Volatile
    private var abiResolved = false

    /** `Build.SUPPORTED_ABIS` is a platform type and is null on the JVM test classpath. */
    private fun supportedAbis(): List<String> =
        runCatching { Build.SUPPORTED_ABIS?.toList() }.getOrNull().orEmpty()

    /**
     * The ABI Godwall's Anonymity binaries are read under: the first
     * `Build.SUPPORTED_ABIS` entry whose `lib/<abi>/` actually carries one of our
     * binaries, or — when none are bundled — the platform's preferred ABI. Null only
     * when the device reports no ABIs at all.
     */
    fun abi(context: Context): String? {
        if (abiResolved) return cachedAbi
        val abis = supportedAbis()
        val chosen = abis.firstOrNull { a ->
            hasApkEntry(context, "lib/$a/${Binary.TOR.libName}") ||
                hasApkEntry(context, "lib/$a/${Binary.I2PD.libName}")
        } ?: abis.firstOrNull()
        cachedAbi = chosen
        abiResolved = true
        return chosen
    }

    /** True when [binary]'s `lib*.so` is packaged in this APK for this device's ABI. Blocking. */
    fun has(context: Context, binary: Binary): Boolean {
        val abi = abi(context) ?: return false
        val key = "$abi/${binary.libName}"
        presenceCache[key]?.let { return it }
        val present = hasApkEntry(context, "lib/$abi/${binary.libName}")
        presenceCache[key] = present
        return present
    }

    fun torPresent(context: Context): Boolean = has(context, Binary.TOR)
    fun i2pdPresent(context: Context): Boolean = has(context, Binary.I2PD)
    fun obfs4Present(context: Context): Boolean = has(context, Binary.OBFS4PROXY)
    fun snowflakePresent(context: Context): Boolean = has(context, Binary.SNOWFLAKE)

    /**
     * Whether tor's GeoIP tables are installed in the prefix. Country-code node
     * selection (Exit/Entry/Exclude Nodes) is meaningless without them — tor has no
     * country data to match — so a control that sets a country list must gate on this
     * rather than silently doing nothing. Blocking; false when there is no privileged
     * shell, which is the honest answer (the prefix is unreadable to Godwall's own uid).
     *
     * The GeoIP files come from InviZible's app_data tree (docs/DONOR-ASSETS.md, OPEN)
     * and are not bundled here; when present they live at usr/etc/tor/geoip[6], the
     * path the shipped torrc references.
     */
    fun geoipPresent(): Boolean =
        PrefixInstaller.exists("usr/etc/tor/geoip") && PrefixInstaller.exists("usr/etc/tor/geoip6")

    /** Which pluggable-transport binaries are bundled, for [TorBridges]. */
    fun bridgePresence(context: Context): TorBridges.Presence =
        TorBridges.Presence(obfs4proxy = obfs4Present(context), snowflakeClient = snowflakePresent(context))

    fun state(context: Context): State = if (torPresent(context)) State.BUNDLED else State.ABSENT

    /**
     * One sentence for a disabled Anonymity control. Names exactly which binary is
     * missing and where it goes, and never tells the user to install another app.
     */
    fun explain(context: Context): String {
        val abi = abi(context)
        if (abi == null) {
            return "This device reports no supported ABI, so no Tor or i2pd binary can be selected. " +
                "The Anonymity backend is absent from this build."
        }
        return when (state(context)) {
            State.BUNDLED -> {
                val extras = buildList {
                    if (!i2pdPresent(context)) add("i2pd (I2P routing)")
                    if (!obfs4Present(context)) add("obfs4proxy (obfs4 / meek bridges)")
                    if (!snowflakePresent(context)) add("snowflake-client (Snowflake bridges)")
                }
                if (extras.isEmpty()) {
                    "The Tor and i2pd binaries are bundled for $abi. They run as uid 2000 from " +
                        "${PrefixInstaller.PREFIX}/usr/bin once the subsystem is installed."
                } else {
                    "The Tor binary is bundled for $abi; still absent from this build: " +
                        extras.joinToString(", ") + ". Controls backed by an absent binary stay disabled."
                }
            }
            State.ABSENT ->
                "No Tor binary (lib/$abi/${Binary.TOR.libName}) is in this build, so Tor and I2P " +
                    "routing report absent. Add the per-ABI binaries under jniLibs (see " +
                    "tools/donor-assets/fetch.sh invizible); nothing else in Godwall depends on them."
        }
    }

    // ---- Seeding the binaries into the prefix ------------------------------------

    data class InstallResult(val ok: Boolean, val installed: List<Binary>, val message: String)

    /**
     * Copy every bundled Anonymity binary out of the APK into the prefix as uid 2000,
     * and make it executable. Blocking — call off the main thread. Idempotent: it
     * overwrites in place, so a rebuilt binary replaces the previous one.
     *
     * Requires the prefix to be installed and a privileged shell attached; without
     * either it returns a failure that names the reason rather than a silent no-op.
     * A binary that is not bundled is simply skipped — its capability stays gated.
     */
    fun installBinaries(context: Context): InstallResult {
        val abi = abi(context)
            ?: return InstallResult(false, emptyList(), "This device reports no supported ABI.")
        if (PrefixInstaller.state(context) != PrefixInstaller.State.INSTALLED) {
            return InstallResult(
                false, emptyList(),
                "The Linux subsystem prefix is not installed, so the Tor/i2pd binaries have " +
                    "nowhere to go. Install the subsystem first.",
            )
        }
        val present = Binary.entries.filter { has(context, it) }
        if (present.isEmpty()) {
            return InstallResult(
                false, emptyList(),
                "No Anonymity binaries are bundled for $abi; nothing to install. " + explain(context),
            )
        }
        val apks = apkCandidates(context)
        val installed = ArrayList<Binary>(present.size)
        for (binary in present) {
            if (seedOne(abi, binary, apks)) {
                installed += binary
            } else {
                return InstallResult(
                    false, installed,
                    "Could not copy ${binary.label} (lib/$abi/${binary.libName}) from the APK into " +
                        "${PrefixInstaller.PREFIX}/${binary.prefixDest}.",
                )
            }
        }
        Diagnostics.log(TAG, "seeded ${installed.joinToString { it.label }} into the prefix")
        return InstallResult(
            true, installed,
            "Installed ${installed.joinToString { it.label }} into ${PrefixInstaller.PREFIX}/usr/bin as uid 2000.",
        )
    }

    /** Unzip one `lib/<abi>/<lib>` entry from whichever APK holds it into its prefix path. */
    private fun seedOne(abi: String, binary: Binary, apks: List<String>): Boolean {
        val q = PrefixInstaller::quote
        val entry = "lib/$abi/${binary.libName}"
        val dest = PrefixInstaller.resolve(binary.prefixDest)
        val stageDir = "${PrefixInstaller.TMP}/anon-install"
        val staged = "$stageDir/${binary.libName}"
        for (apk in apks) {
            val r = PrefixInstaller.exec(
                buildList {
                    add("set -e")
                    add("mkdir -p " + q(stageDir) + " " + q(dest.substringBeforeLast('/')))
                    add("rm -f " + q(staged))
                    // -j junks the archive path so the file lands directly in the stage dir.
                    add("unzip -o -q -j " + q(apk) + " " + q(entry) + " -d " + q(stageDir) + " >/dev/null 2>&1 || exit 4")
                    add("[ -f " + q(staged) + " ] || exit 5")
                    add("mv -f " + q(staged) + " " + q(dest))
                    add("chmod 755 " + q(dest))
                    add("rm -rf " + q(stageDir))
                    add("exit 0")
                }.joinToString("\n"),
                timeoutMs = 120_000L,
            )
            if (r.ok) return true
        }
        return false
    }

    private fun apkCandidates(context: Context): List<String> {
        val info = context.applicationInfo
        return buildList {
            info.sourceDir?.let { add(it) }
            info.splitSourceDirs?.forEach { if (it !in this) add(it) }
            info.publicSourceDir?.let { if (it !in this) add(it) }
        }
    }

    /** True when any of Godwall's APKs contains [entry]. Reads the app's own world-readable APK. */
    private fun hasApkEntry(context: Context, entry: String): Boolean {
        for (apk in apkCandidates(context)) {
            val found = runCatching {
                ZipFile(apk).use { it.getEntry(entry) != null }
            }.getOrDefault(false)
            if (found) return true
        }
        return false
    }
}
