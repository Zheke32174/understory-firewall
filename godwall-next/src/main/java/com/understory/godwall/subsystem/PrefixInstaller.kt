package com.understory.godwall.subsystem

import android.content.Context
import android.os.Build
import com.understory.godwall.privilege.Privilege
import com.understory.security.Diagnostics
import java.io.BufferedInputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipInputStream

/**
 * Puts Godwall's own Linux userland on disk at `/data/local/tmp/godwall`, as uid 2000,
 * through Yojimbo — and reports honestly when it cannot.
 *
 * ## Why that path, and why not the app's own directory
 *
 * Since API 29 an app's private data dir is effectively W^X: a file the app writes there
 * cannot be exec'd, so extracting an ELF into `getFilesDir()` produces a binary that will
 * never run. `/data/local/tmp` is the one location that is both writable and executable, and
 * it is owned by uid 2000 (shell) — which is exactly the uid Yojimbo already stands a process
 * up at. Not proot: exec'ing directly out of an exec-friendly prefix has no ptrace overhead
 * and is what actually works here.
 *
 * ## Why every single filesystem operation goes through the privileged shell
 *
 * `/data/local/tmp` is `drwxrwx--x shell:shell`, and SELinux labels its contents
 * `shell_data_file`, which an app domain cannot read. Godwall's own uid therefore cannot
 * list the prefix, stat a file in it, or read a log out of it — not "should not", cannot.
 * So there is no fast path here: [state], [exists], [readText] and [writeText] are all
 * binder round trips to Yojimbo, all blocking, all off the main thread by contract. It is
 * also why [State] has a [State.NO_PRIVILEGE] value rather than defaulting to
 * "not installed": with no shell attached, the answer is genuinely unknown, and guessing
 * would be the subsystem's first lie.
 *
 * ## How the bytes get across the uid boundary
 *
 * The app can read its own assets but cannot write to the prefix. The shell can write to the
 * prefix but cannot read the app's private storage. Nothing bridges them — except that the
 * APK itself is world-readable at `applicationInfo.sourceDir`, so the shell can unzip the
 * payload straight out of Godwall's own APK. No external storage, no storage permission, no
 * chunked base64 of a 40 MB archive, and no temp file another app could tamper with between
 * the write and the read.
 *
 * ## The seam with the ELF repatcher
 *
 * `tools/donor-assets/bootstrap.sh` fetches a stock Termux bootstrap, runs
 * `tools/donor-assets/elf-repatch.py` over it to rewrite PT_INTERP and DT_RUNPATH from
 * `/data/data/com.termux/files/usr` to [USR], and repackages the result at
 * `assets/subsystem/bootstrap/<abi>.zip`. That path is a contract between three files and is
 * duplicated here deliberately rather than imported, so a concurrent edit to one cannot
 * silently break the other two — [ASSET_DIR] must keep matching `ASSET_DIR` in that script
 * and `Bootstrap.assetPath()`.
 *
 * Unpatched is the failure mode worth spending code on: it installs perfectly and then every
 * service fails to exec with a loader error, which reads to a user as "Godwall is broken"
 * rather than "this build shipped the wrong payload". So [unpatchedInterpreter] reads the
 * payload's own ELF program headers before anything is unpacked, and the install refuses on
 * proof that the repatch never ran.
 */
object PrefixInstaller {

    private const val TAG = "godwall.subsystem.PrefixInstaller"

    /** The prefix root. Must match `--new-prefix`'s parent in `tools/donor-assets/bootstrap.sh`. */
    const val PREFIX = "/data/local/tmp/godwall"

    /** The Termux-shaped tree: `bin`, `lib`, `etc`, `libexec`, … */
    const val USR = "$PREFIX/usr"

    /** `HOME` for every supervised service. */
    const val HOME = "$PREFIX/home"

    /** Pid files, one per service. */
    const val RUN = "$PREFIX/run"

    /** Captured stdout+stderr, one file per service. */
    const val LOGS = "$PREFIX/logs"

    /** `TMPDIR` for every supervised service. */
    const val TMP = "$PREFIX/tmp"

    /** Records which payload produced the installed prefix, so staleness is detectable. */
    const val MARKER = "$PREFIX/.godwall-prefix"

    /** Scratch space used only while installing; removed on the way out. */
    private const val STAGE = "$PREFIX/.stage"

    /** Assets directory the per-ABI bootstrap payload is written to by `bootstrap.sh`. */
    const val ASSET_DIR = "subsystem/bootstrap"

    /** What a stock Termux bootstrap hardcodes, and what the repatcher removes. */
    const val UPSTREAM_PREFIX = "/data/data/com.termux/files/usr"

    /**
     * Cap on [writeText]. Linux allows at most 128 KiB in a single argv element
     * (MAX_ARG_STRLEN = 32 pages), and the content travels as one base64 argument inside a
     * `sh -c` script, so the raw cap has to leave room for base64's 4/3 expansion plus the
     * script around it. Config files are kilobytes; anything approaching this is not a config
     * file and is refused rather than truncated.
     */
    const val MAX_WRITE_BYTES = 64 * 1024

    /** How much of an entry is read when looking for its PT_INTERP. */
    private const val ELF_SAMPLE_BYTES = 64 * 1024

    /** How many interpreter-carrying executables are enough to judge a payload. */
    private const val ELF_SAMPLES = 8

    /** External tools the install depends on. All are toybox applets present since API 29. */
    private val REQUIRED_TOOLS = listOf("unzip", "base64", "chmod", "ln", "grep", "tail")

    /** What the subsystem's substrate is, as an observation rather than an assumption. */
    enum class State {
        /** This build carries no bootstrap payload for any ABI this device supports. */
        PAYLOAD_ABSENT,

        /** A payload exists, but with no privileged shell nothing can be installed or read. */
        NO_PRIVILEGE,

        /** Payload and shell are both present; the prefix is not on disk. */
        NOT_INSTALLED,

        /** A prefix is installed, but from a different payload than this build carries. */
        STALE,

        /** Installed, and its marker matches this build's payload. */
        INSTALLED,
    }

    /**
     * A bootstrap payload found in this APK's assets.
     *
     * @param assetPath path under `assets/`, e.g. `subsystem/bootstrap/arm64-v8a.zip`.
     * @param abi the Android ABI it was built for.
     */
    data class Payload(val assetPath: String, val abi: String) {
        /** The full zip entry name inside the APK. */
        val apkEntry: String get() = "assets/$assetPath"
    }

    /** The outcome of a multi-step operation: which step, and what it actually said. */
    data class Report(val ok: Boolean, val step: String, val message: String)

    @Volatile
    private var scannedPayload: Payload? = null

    @Volatile
    private var payloadScanned = false

    @Volatile
    private var cachedDigest: String? = null

    // ---- Discovery -------------------------------------------------------------------

    /**
     * The bootstrap payload for this device, or null when this build does not carry one.
     *
     * Devices are asked in `Build.SUPPORTED_ABIS` order — the platform's own preference, not
     * ours — so a 64-bit device installs its 64-bit userland and only falls back to a 32-bit
     * one if that is all that was packaged.
     *
     * Cheap: reads the asset directory listing, never the payload itself.
     */
    fun payload(context: Context): Payload? {
        if (payloadScanned) return scannedPayload
        val names = runCatching { context.assets.list(ASSET_DIR) }
            .getOrNull()
            ?.toSet()
            .orEmpty()
        val found = supportedAbis()
            .firstOrNull { "$it.zip" in names }
            ?.let { Payload(assetPath = "$ASSET_DIR/$it.zip", abi = it) }
        scannedPayload = found
        payloadScanned = true
        if (found == null) {
            Diagnostics.warn(TAG, "no bootstrap payload in assets/$ASSET_DIR for any supported ABI")
        } else {
            Diagnostics.log(TAG, "bootstrap payload: ${found.assetPath}")
        }
        return found
    }

    /** `Build.SUPPORTED_ABIS` is a platform type and is null on the JVM test classpath. */
    private fun supportedAbis(): List<String> =
        runCatching { Build.SUPPORTED_ABIS?.toList() }.getOrNull().orEmpty()

    /**
     * SHA-256 of the payload asset, hex. Used as the installed-prefix identity so a rebuilt
     * payload is detected as [State.STALE] instead of silently continuing to run the previous
     * install's binaries. Blocking — reads the whole asset. Cached after the first call.
     */
    fun payloadDigest(context: Context, payload: Payload): String {
        cachedDigest?.let { return it }
        val md = MessageDigest.getInstance("SHA-256")
        context.assets.open(payload.assetPath).use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        val hex = md.digest().joinToString("") { "%02x".format(it) }
        cachedDigest = hex
        return hex
    }

    // ---- Repatch verification ----------------------------------------------------------

    /**
     * The stock-Termux interpreter path still baked into the payload, or null when there is no
     * such evidence. Blocking — streams part of the asset. No shell needed.
     *
     * Reads PT_INTERP straight out of the program header table of the first few executables in
     * the payload, the same field the kernel reads when it execs them. A hit is proof the
     * repatch never ran: the loader would be looked for under `/data/data/com.termux`, which
     * does not exist here, and nothing in the prefix would start.
     *
     * Deliberately one-directional. A miss is not proof the payload IS patched — some ABIs
     * link against `/system/bin/linker64` and carry no prefix in PT_INTERP at all — so this
     * never reports success, only the failure it can actually prove. The residual case is
     * covered honestly downstream: [Supervisor] surfaces a failed daemon's own stderr, so a
     * bad DT_RUNPATH shows up as the linker's real "library not found" message rather than as
     * a shrug.
     */
    fun unpatchedInterpreter(context: Context, payload: Payload): String? {
        var sampled = 0
        return runCatching {
            ZipInputStream(BufferedInputStream(context.assets.open(payload.assetPath))).use { zin ->
                while (sampled < ELF_SAMPLES) {
                    val entry = zin.nextEntry ?: break
                    if (entry.isDirectory) continue
                    val head = readAtMost(zin, ELF_SAMPLE_BYTES)
                    val interp = interpreterOf(head) ?: continue
                    sampled++
                    if (interp.startsWith(UPSTREAM_PREFIX)) return@runCatching interp
                }
            }
            null
        }.getOrElse {
            Diagnostics.warn(TAG, "could not inspect payload ELFs: ${it.javaClass.simpleName}")
            null
        }
    }

    private fun readAtMost(input: InputStream, limit: Int): ByteArray {
        val buf = ByteArray(limit)
        var read = 0
        while (read < limit) {
            val n = input.read(buf, read, limit - read)
            if (n <= 0) break
            read += n
        }
        return if (read == limit) buf else buf.copyOf(read)
    }

    /**
     * The PT_INTERP string of a little-endian ELF, or null when [bytes] is not an ELF, is not
     * an executable with an interpreter, or does not carry it within the sampled prefix.
     *
     * Program headers only — the same table the kernel and the dynamic linker consult. Section
     * headers are debugger metadata and a stripped binary still runs without them, so driving
     * this off sections would misjudge exactly the packages most likely to be stripped. This
     * mirrors the reasoning in `tools/donor-assets/elf-repatch.py`; it is a reader, not a
     * second implementation of the patcher.
     */
    private fun interpreterOf(bytes: ByteArray): String? {
        if (bytes.size < 64) return null
        if (bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            return null
        }
        val is64 = when (bytes[4].toInt()) {
            2 -> true
            1 -> false
            else -> return null
        }
        // Android is little-endian on every ABI Godwall ships for; a big-endian ELF here is
        // not something to guess about.
        if (bytes[5].toInt() != 1) return null

        val phoff = if (is64) readU64(bytes, 0x20) else readU32(bytes, 0x1C)
        val phentsize = if (is64) readU16(bytes, 0x36) else readU16(bytes, 0x2A)
        val phnum = if (is64) readU16(bytes, 0x38) else readU16(bytes, 0x2C)
        if (phoff <= 0L || phentsize <= 0 || phnum <= 0) return null

        for (i in 0 until phnum) {
            val ph = phoff + i.toLong() * phentsize
            if (ph + phentsize > bytes.size) return null
            val type = readU32(bytes, ph.toInt())
            if (type != PT_INTERP) continue
            val offset = if (is64) readU64(bytes, (ph + 8).toInt()) else readU32(bytes, (ph + 4).toInt())
            val size = if (is64) readU64(bytes, (ph + 32).toInt()) else readU32(bytes, (ph + 16).toInt())
            if (offset <= 0L || size <= 0L || offset + size > bytes.size) return null
            val raw = String(bytes, offset.toInt(), size.toInt(), Charsets.UTF_8)
            return raw.substringBefore('\u0000')
        }
        return null
    }

    private const val PT_INTERP = 3L

    private fun readU16(b: ByteArray, at: Int): Int =
        (b[at].toInt() and 0xFF) or ((b[at + 1].toInt() and 0xFF) shl 8)

    private fun readU32(b: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 4) v = v or ((b[at + i].toLong() and 0xFF) shl (8 * i))
        return v
    }

    private fun readU64(b: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = v or ((b[at + i].toLong() and 0xFF) shl (8 * i))
        return v
    }

    // ---- State -----------------------------------------------------------------------

    /** Blocking — talks to the privileged shell. Call off the main thread. */
    fun state(context: Context): State {
        val payload = payload(context) ?: return State.PAYLOAD_ABSENT
        if (!Privilege.isAvailable()) return State.NO_PRIVILEGE
        val r = exec(
            "if [ -f " + quote(MARKER) + " ]; then printf 'MARKER\\n'; cat " + quote(MARKER) +
                "; else printf 'NONE\\n'; fi",
        )
        if (!r.ok) {
            Diagnostics.warn(TAG, "marker read failed: ${r.summary()}")
            return State.NO_PRIVILEGE
        }
        val lines = r.out.lines()
        if (lines.firstOrNull()?.trim() != "MARKER") return State.NOT_INSTALLED
        val recorded = lines.firstOrNull { it.startsWith("sha256=") }?.removePrefix("sha256=")?.trim()
        return if (recorded != null && recorded == payloadDigest(context, payload)) {
            State.INSTALLED
        } else {
            State.STALE
        }
    }

    /**
     * The one sentence the UI shows for [state]. Each names exactly what is missing; none
     * blames the user, and none instructs them to install something Godwall replaces.
     */
    fun explain(context: Context, state: State = state(context)): String = when (state) {
        State.PAYLOAD_ABSENT ->
            "Godwall's Linux subsystem is not in this build: no bootstrap payload " +
                "(assets/$ASSET_DIR/${supportedAbis().firstOrNull() ?: "<abi>"}.zip) was " +
                "packaged. Nothing is installed at $PREFIX and no subsystem service can run."

        State.NO_PRIVILEGE ->
            "The Linux subsystem lives at $PREFIX, which is owned by uid 2000 (shell). " +
                "Godwall's own uid cannot read or write it, so without a privileged shell " +
                "from Yojimbo the subsystem cannot be installed and its state cannot even " +
                "be read. ${Privilege.explain(context)}"

        State.NOT_INSTALLED ->
            "The Linux subsystem is not installed yet. Installing it unpacks Godwall's own " +
                "userland into $PREFIX as uid 2000. It touches no other app and no system " +
                "directory, and it is not a Termux install — nothing outside $PREFIX is written."

        State.STALE ->
            "A Linux subsystem is installed at $PREFIX, but it was unpacked from a different " +
                "payload than this build of Godwall carries. Services started from it would " +
                "be the previous build's binaries. Reinstall to replace it."

        State.INSTALLED ->
            "Godwall's Linux subsystem is installed at $PREFIX and matches this build's " +
                "payload. It runs as uid 2000: it can open sockets and read its own prefix, " +
                "and it cannot write the device's firewall tables or reach into other apps."
    }

    // ---- Install ---------------------------------------------------------------------

    /**
     * Unpack the payload into the prefix. Blocking; call off the main thread.
     *
     * Each step is its own privileged call so a failure names the step that failed instead of
     * a shell exit code from a hundred-line script. [onStep] is invoked before each one, for
     * progress display.
     *
     * Idempotent: re-running over an installed prefix overwrites it in place with the same
     * payload, which is also how [State.STALE] is repaired.
     */
    fun install(context: Context, onStep: (String) -> Unit = {}): Report {
        val payload = payload(context)
            ?: return Report(false, "payload", explain(context, State.PAYLOAD_ABSENT))
        if (!Privilege.isAvailable()) {
            return Report(false, "privilege", explain(context, State.NO_PRIVILEGE))
        }

        onStep("Verifying the payload was ELF-repatched")
        unpatchedInterpreter(context, payload)?.let { interp ->
            return Report(
                false,
                "verify",
                "The bundled bootstrap still names '$interp' as its loader, so it was never " +
                    "ELF-repatched for $USR. Every binary in it would fail to exec. Nothing " +
                    "was written to $PREFIX — rebuild the asset with " +
                    "tools/donor-assets/bootstrap.sh.",
            )
        }

        onStep("Checking device tooling")
        toolingProblem()?.let { return Report(false, "tooling", it) }

        onStep("Preparing $PREFIX")
        val prepare = exec(
            joinLines(
                "set -e",
                "mkdir -p " + quote(PREFIX),
                // 0700: the prefix belongs to uid 2000 and nothing else has business in it.
                // /data/local/tmp is world-traversable, so a laxer mode here would expose
                // every service's config and log to any app that guesses the path.
                "chmod 700 " + quote(PREFIX),
                "mkdir -p " + listOf(USR, HOME, RUN, LOGS, TMP).joinToString(" ") { quote(it) },
                "rm -rf " + quote(STAGE),
                "mkdir -p " + quote(STAGE),
            ),
        )
        if (!prepare.ok) {
            return Report(false, "prepare", "Could not create $PREFIX: ${prepare.summary()}")
        }

        onStep("Extracting the payload from Godwall's APK")
        val stagedPayload = "$STAGE/payload.zip"
        val apk = extractFromApk(context, payload.apkEntry, stagedPayload)
            ?: return Report(
                false,
                "extract",
                "The privileged shell could not read ${payload.apkEntry} out of Godwall's " +
                    "own APK. Nothing was written to $PREFIX.",
            )
        Diagnostics.log(TAG, "payload staged from $apk")

        onStep("Unpacking the userland")
        val unpack = exec(
            "unzip -o -q " + quote(stagedPayload) + " -d " + quote(USR),
            timeoutMs = 300_000L,
        )
        if (!unpack.ok) {
            cleanStage()
            return Report(false, "unpack", "Unpacking the userland failed: ${unpack.summary()}")
        }

        onStep("Recreating symlinks")
        val links = restoreSymlinks()
        if (!links.ok) {
            cleanStage()
            return Report(
                false,
                "symlinks",
                "The userland unpacked but its symlink table could not be applied: " +
                    "${links.summary()}. Most of the prefix's commands would be missing, so " +
                    "the install is not being marked complete.",
            )
        }

        onStep("Setting executable bits")
        val modes = exec(
            joinLines(
                // zip carries unix modes in an extra field that not every extractor restores,
                // and a bootstrap whose bin/ came out 0600 fails to exec with a permission
                // error that reads like a privilege problem. Set them explicitly instead of
                // trusting the archiver.
                "chmod -R u+rwX " + quote(USR),
                "[ -d " + quote("$USR/bin") + " ] && chmod -R u+rwx " + quote("$USR/bin"),
                "[ -d " + quote("$USR/libexec") + " ] && chmod -R u+rwx " + quote("$USR/libexec"),
                "exit 0",
            ),
            timeoutMs = 300_000L,
        )
        if (!modes.ok) {
            cleanStage()
            return Report(false, "modes", "Could not set executable bits: ${modes.summary()}")
        }

        onStep("Recording the installed payload")
        val marker = joinLines(
            "sha256=" + payloadDigest(context, payload),
            "abi=" + payload.abi,
            "asset=" + payload.assetPath,
            "prefix=" + USR,
            "installed=" + System.currentTimeMillis(),
            "",
        )
        val wrote = exec("printf '%s' " + quote(marker) + " > " + quote(MARKER))
        cleanStage()
        if (!wrote.ok) {
            return Report(
                false,
                "marker",
                "The userland unpacked but the install marker could not be written, so " +
                    "Godwall cannot tell this prefix apart from a stale one: ${wrote.summary()}",
            )
        }

        Diagnostics.log(TAG, "prefix installed from ${payload.assetPath}")
        return Report(
            true,
            "done",
            "Godwall's Linux userland is installed at $PREFIX and runs as uid 2000. No " +
                "service is running yet.",
        )
    }

    /**
     * Remove the prefix entirely. Blocking.
     *
     * Refuses any path that is not exactly the constant below — [PREFIX] is not user-supplied
     * today, but `rm -rf` reached through a privileged shell is the most destructive call in
     * this app and it gets a guard regardless of who is expected to be holding it.
     */
    fun uninstall(): Report {
        if (PREFIX != "/data/local/tmp/godwall") {
            return Report(false, "guard", "Refusing to remove '$PREFIX' — not Godwall's prefix.")
        }
        if (!Privilege.isAvailable()) {
            return Report(
                false,
                "privilege",
                "No privileged shell is attached, so $PREFIX cannot be removed.",
            )
        }
        val r = exec("rm -rf " + quote(PREFIX), timeoutMs = 120_000L)
        return if (r.ok) {
            Diagnostics.log(TAG, "prefix removed")
            Report(
                true,
                "done",
                "Removed $PREFIX. No subsystem service can run until it is installed again.",
            )
        } else {
            Report(false, "remove", "Could not remove $PREFIX: ${r.summary()}")
        }
    }

    // ---- Files inside the prefix ------------------------------------------------------

    /** Absolute path for a prefix-relative path. Throws on anything that escapes the prefix. */
    fun resolve(relPath: String): String {
        require(ServiceSpec.isSafeRelPath(relPath)) { "'$relPath' is not a prefix-relative path" }
        return "$PREFIX/$relPath"
    }

    /** True when the path exists inside the prefix. Blocking; false when there is no shell. */
    fun exists(relPath: String): Boolean {
        if (!Privilege.isAvailable()) return false
        val r = exec("[ -e " + quote(resolve(relPath)) + " ] && printf 'YES\\n' || printf 'NO\\n'")
        return r.ok && r.out.trim() == "YES"
    }

    /**
     * Copy a config asset out of the APK into the prefix.
     *
     * Honours [ServiceConfigFile.overwrite]: by default an existing file is left untouched,
     * which is what lets an Advanced surface's edited config survive a service restart. The
     * shipped default seeds the file exactly once.
     *
     * Blocking. Names the asset when it fails, because "tor did not start" and "torrc never
     * made it into the prefix" are different problems with different fixes.
     */
    fun installConfig(context: Context, config: ServiceConfigFile): Report {
        if (!Privilege.isAvailable()) {
            return Report(
                false,
                "privilege",
                "No privileged shell is attached, so ${config.destination} cannot be written.",
            )
        }
        val dest = resolve(config.destination)
        if (!config.overwrite && exists(config.destination)) {
            return Report(true, "keep", "${config.destination} already exists; left as it is.")
        }
        val mk = exec("mkdir -p " + quote(dest.substringBeforeLast('/')))
        if (!mk.ok) {
            return Report(false, "mkdir", "Could not create the directory for ${config.destination}: ${mk.summary()}")
        }

        val staged = "$STAGE/config"
        val apk = extractFromApk(context, "assets/${config.asset}", staged)
            ?: return Report(
                false,
                "extract",
                "The privileged shell could not read assets/${config.asset} out of Godwall's " +
                    "APK, so ${config.destination} was not written.",
            )
        Diagnostics.log(TAG, "config ${config.asset} staged from $apk")
        val move = exec(
            joinLines(
                "set -e",
                "mv -f " + quote(staged) + " " + quote(dest),
                "chmod 600 " + quote(dest),
            ),
        )
        cleanStage()
        return if (move.ok) {
            Report(true, "done", "Installed ${config.destination} from the shipped default.")
        } else {
            Report(false, "install", "Could not place ${config.destination}: ${move.summary()}")
        }
    }

    /**
     * Read a text file out of the prefix, capped at [maxBytes]. Blocking.
     *
     * Returns null when there is no privileged shell or the file does not exist — the caller
     * must render that as "cannot read", never as an empty config.
     */
    fun readText(relPath: String, maxBytes: Int = MAX_WRITE_BYTES): String? {
        if (!Privilege.isAvailable()) return null
        val path = resolve(relPath)
        val r = exec("[ -f " + quote(path) + " ] || exit 3\nhead -c $maxBytes " + quote(path))
        return if (r.ok) r.out else null
    }

    /**
     * Write a text file into the prefix. Blocking.
     *
     * The content crosses as one base64 argv element, so it is bounded by [MAX_WRITE_BYTES]
     * (see that constant for the kernel limit behind the number). Over the cap the write is
     * refused, never truncated: a config file silently cut in half is a daemon that starts
     * with half a policy.
     */
    fun writeText(relPath: String, content: String): Report {
        if (!Privilege.isAvailable()) {
            return Report(
                false,
                "privilege",
                "No privileged shell is attached, so $relPath cannot be written.",
            )
        }
        val bytes = content.toByteArray(Charsets.UTF_8)
        if (bytes.size > MAX_WRITE_BYTES) {
            return Report(
                false,
                "size",
                "Refusing to write $relPath: ${bytes.size} bytes exceeds the " +
                    "$MAX_WRITE_BYTES-byte limit for a single privileged write. Nothing was " +
                    "changed.",
            )
        }
        val path = resolve(relPath)
        val b64 = Base64.getEncoder().encodeToString(bytes)
        val r = exec(
            joinLines(
                "set -e",
                "mkdir -p " + quote(path.substringBeforeLast('/')),
                "printf '%s' " + quote(b64) + " | base64 -d > " + quote(path),
                "chmod 600 " + quote(path),
            ),
        )
        return if (r.ok) {
            Report(true, "done", "Wrote ${bytes.size} bytes to $relPath.")
        } else {
            Report(false, "write", "Could not write $relPath: ${r.summary()}")
        }
    }

    // ---- Shell plumbing ---------------------------------------------------------------

    /**
     * Single-quote a value for `sh -c`.
     *
     * The privileged interface takes an already-split argv precisely so a package name cannot
     * become a command. Backgrounding a daemon needs a shell, which reintroduces the surface,
     * so every interpolated value is quoted here and the quoting is not optional: POSIX single
     * quotes make every byte literal except `'` itself, which is closed, escaped and reopened.
     */
    fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    /** Join script lines. Kept separate so scripts read as lines rather than one long string. */
    private fun joinLines(vararg lines: String): String = lines.joinToString("\n")

    /** Run one script through Yojimbo. Blocking. */
    internal fun exec(script: String, timeoutMs: Long = 60_000L) =
        Privilege.exec(listOf("sh", "-c", script), timeoutMs)

    /** Missing tools, as a sentence, or null when everything needed is present. */
    private fun toolingProblem(): String? {
        val probe = REQUIRED_TOOLS.joinToString("\n") {
            "command -v " + quote(it) + " >/dev/null 2>&1 || printf '%s\\n' " + quote(it)
        }
        val r = exec("$probe\nexit 0")
        if (!r.ok) return "Could not probe the device for required tools: ${r.summary()}"
        val missing = r.out.lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (missing.isEmpty()) return null
        return "This device's shell is missing ${missing.joinToString(", ")}, which the " +
            "subsystem install needs to unpack the userland. Nothing was written to $PREFIX."
    }

    /**
     * Have the shell pull one entry out of Godwall's own APK to [destination].
     *
     * Tries the base APK and then each split, because an asset lands in whichever artefact the
     * packaging produced and Godwall does not control that from here. Returns the APK path
     * that worked, or null.
     */
    private fun extractFromApk(context: Context, entry: String, destination: String): String? {
        val info = context.applicationInfo
        val candidates = buildList {
            info.sourceDir?.let { add(it) }
            info.splitSourceDirs?.forEach { if (it !in this) add(it) }
            info.publicSourceDir?.let { if (it !in this) add(it) }
        }
        val unpackDir = "$STAGE/apk"
        for (apk in candidates) {
            val r = exec(
                joinLines(
                    "rm -rf " + quote(unpackDir),
                    "mkdir -p " + quote(unpackDir),
                    "unzip -o -q " + quote(apk) + " " + quote(entry) + " -d " + quote(unpackDir) +
                        " >/dev/null 2>&1 || exit 4",
                    "[ -f " + quote("$unpackDir/$entry") + " ] || exit 5",
                    "mv -f " + quote("$unpackDir/$entry") + " " + quote(destination),
                    "rm -rf " + quote(unpackDir),
                ),
                timeoutMs = 300_000L,
            )
            if (r.ok) return apk
        }
        return null
    }

    /**
     * Recreate the symlinks the payload could not carry.
     *
     * Termux's bootstrap ships a `SYMLINKS.txt` of `target<separator>linkname` pairs rather
     * than real symlink entries, because symlinks-in-zip are unreliable across the tooling
     * that produces and consumes these archives; upstream's own installer replays the manifest
     * with `Os.symlink()`. Without this step `usr/bin` is missing most of its commands and
     * `usr/lib` most of its versioned `.so` aliases.
     *
     * Both separators are accepted: upstream has shipped U+2190 (`←`) and a plain tab in
     * different releases, and `tools/donor-assets/bootstrap.sh` passes the manifest through
     * untouched, so the installer is the place that has to cope with either.
     */
    private fun restoreSymlinks() = exec(
        joinLines(
            "cd " + quote(USR) + " || exit 6",
            "[ -f SYMLINKS.txt ] || exit 0",
            // A literal tab cannot be written inside a shell case pattern legibly, and an
            // escaped \\t inside ${var%%...} matches the letter t, not a tab — so the byte is
            // built once, up front, and referenced as a variable everywhere below.
            "tab=\$(printf '\\t')",
            "while IFS= read -r line; do",
            "  case \"\$line\" in",
            "    *←*) target=\${line%%←*}; link=\${line#*←} ;;",
            "    *\"\$tab\"*) target=\${line%%\"\$tab\"*}; link=\${line#*\"\$tab\"} ;;",
            "    *) continue ;;",
            "  esac",
            "  [ -n \"\$target\" ] || continue",
            "  [ -n \"\$link\" ] || continue",
            "  dir=\${link%/*}",
            "  if [ \"\$dir\" != \"\$link\" ]; then mkdir -p \"\$dir\"; fi",
            "  rm -f \"\$link\"",
            "  ln -s \"\$target\" \"\$link\"",
            "done < SYMLINKS.txt",
            "rm -f SYMLINKS.txt",
            "exit 0",
        ),
        timeoutMs = 300_000L,
    )

    private fun cleanStage() {
        exec("rm -rf " + quote(STAGE))
    }
}
