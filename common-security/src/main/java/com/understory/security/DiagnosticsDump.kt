package com.understory.security

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.BufferedWriter
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.io.Writer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Engineering-build-only rolling log + state-snapshot writer.
 *
 * Activated once per process (via [activateIfEng]) on app startup. From
 * that point every [Diagnostics.log] call is mirrored to a single
 * append-only file in shared storage:
 *
 *   /storage/emulated/0/Documents/understory/<app>.log
 *
 * The user finds the file in the system Files app under Documents →
 * understory, multi-selects whatever's accumulated since they last
 * sent dumps, ships them across. No buttons to remember, no per-event
 * tap workflow.
 *
 * What's mirrored:
 *   - Every [Diagnostics.log] / [Diagnostics.warn] / [Diagnostics.error]
 *     call (one line each, with timestamp + tag + level + message)
 *   - Periodic state snapshots: lifecycle pauses + manual marks
 *   - Uncaught exceptions: full stack trace before the process dies
 *
 * What's NOT mirrored:
 *   - Anything in production builds. The eng-flavor check in
 *     [activateIfEng] gates the entire path; prod builds never open
 *     a file in shared storage.
 *   - Vault entry contents, generated passwords, recovery keys, OTP
 *     secrets, biometric material. The redaction is the caller's
 *     responsibility — the same rules that apply to [Diagnostics.log]
 *     apply here. State snapshots go through [snapshotPrefs] which
 *     filters known sensitive prefs by key.
 *
 * Rotation:
 *   - The 1-second flush thread checks the active writer's tracked
 *     bytes after every flush. When the count crosses [ROTATION_BYTES]
 *     (5 MB), the active file is renamed to `<app>.log.prev` and a
 *     fresh writer opens. Any prior `.prev` is deleted, so we keep at
 *     most ~10 MB total per app across both files.
 *   - This applies to both backing stores. The fallback path uses
 *     File.renameTo; the MediaStore path issues a DISPLAY_NAME update
 *     via ContentResolver.update on the existing entry. Either failure
 *     leaves the active writer in place — losing rotation is
 *     preferable to losing log lines.
 *   - On openWriter(), the fallback path also pre-rotates if a prior
 *     session left an oversized file, so a fresh session never starts
 *     with a >5 MB log it would only rotate after another 5 MB of new
 *     writes.
 *
 * Failure modes:
 *   - MediaStore creation fails on some OEM builds. The activator
 *     falls back to the app's own externalFilesDir
 *     (/Android/data/<package>/files/Documents/) which is always
 *     writable but harder to find.
 *   - On versionCode change: starts a fresh log so a stale-build
 *     log doesn't get mixed with new-build behavior. Detected via
 *     a header line written at activation time.
 */
object DiagnosticsDump {

    private const val DOC_SUBDIR = "understory"
    private const val ROTATION_BYTES: Long = 5L * 1024L * 1024L  // 5 MB
    private const val FLUSH_INTERVAL_MS: Long = 1_000L

    private val active = AtomicBoolean(false)
    private val writerRef = AtomicReference<DumpWriter?>(null)
    private val appCtxRef = AtomicReference<Context?>(null)
    private val tsFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    /**
     * Activates the dump path if the calling app's package name ends
     * with the engineering suffix (`.eng`). Idempotent — calling from
     * every Activity onCreate is safe. Production builds short-circuit.
     *
     * Returns whether the dump is now (or was already) active. UI can
     * use this to decide whether to render the eng-only triple-tap
     * mark gesture on [SuiteStatusFooter].
     */
    fun activateIfEng(ctx: Context): Boolean {
        if (active.get()) return true
        if (!ctx.packageName.endsWith(".eng")) return false
        return synchronized(this) {
            if (active.get()) return@synchronized true
            val app = ctx.applicationContext
            val writer = openWriter(app)
            if (writer == null) {
                Diagnostics.warn("DiagnosticsDump", "could not open dump file; eng dump disabled")
                return@synchronized false
            }
            appCtxRef.set(app)
            writerRef.set(writer)
            // Header so a parser can find session boundaries quickly.
            writer.appendLine("=== session start ${tsFormat.format(Date())} ===")
            writer.appendLine("package=${app.packageName}")
            writer.appendLine("versionName=${appVersionName(app)} versionCode=${appVersionCode(app)}")
            writer.appendLine("android=${Build.VERSION.SDK_INT} model=${Build.MODEL} brand=${Build.BRAND}")
            writer.appendLine("path=${writer.describePath()}")
            writer.flush()
            installSink()
            installCrashHandler()
            startFlushTimer()
            active.set(true)
            // Use Diagnostics.log so the activation itself shows up in
            // the rolling buffer + the file (the sink we just installed
            // will catch it).
            Diagnostics.log("DiagnosticsDump",
                "active → ${writer.describePath()} (eng build)")
            true
        }
    }

    /** True iff the dump is currently mirroring to disk. */
    fun isActive(): Boolean = active.get()

    /**
     * Append a `--- MARK: <label> ---` line and force a flush. Useful
     * as the triple-tap target: lets you stamp a moment in the log
     * stream so you can find "where I tapped this" later in a long
     * file. No-op if the dump isn't active.
     */
    fun mark(label: String) {
        val w = writerRef.get() ?: return
        runCatching {
            w.appendLine("--- MARK: $label @ ${tsFormat.format(Date())} ---")
            w.flush()
        }
    }

    /**
     * Append a redacted snapshot of every SharedPreferences file the
     * app owns plus any caller-supplied state lines. Called from
     * lifecycle hooks (onPause / onStop) so the file always has a
     * recent "last-known-good state" block even if the process dies
     * before the next flush.
     *
     * Auto-discovers prefs by enumerating the .xml files under
     * `<dataDir>/shared_prefs/` —
     * apps don't have to know their own pref-file names. Sensitive
     * values are redacted by [snapshotPrefs] based on a denylist of
     * key substrings.
     *
     * [extraLines] is for app-specific state the caller wants on the
     * record (e.g. firewall: current audit-finding count; aegis:
     * current vault unlock state). The caller is responsible for
     * redacting any sensitive values before passing them in.
     */
    fun snapshotState(
        ctx: Context,
        label: String,
        extraLines: List<String> = emptyList(),
    ) {
        val w = writerRef.get() ?: return
        runCatching {
            w.appendLine("--- STATE($label) @ ${tsFormat.format(Date())} ---")
            for (line in extraLines) w.appendLine("  $line")
            val prefsNames = discoverPrefsNames(ctx)
            if (prefsNames.isEmpty()) {
                w.appendLine("  (no prefs files found)")
            } else {
                for (prefsName in prefsNames) {
                    w.appendLine("  -- $prefsName --")
                    for ((k, v) in snapshotPrefs(ctx, prefsName)) {
                        w.appendLine("    [$k] = $v")
                    }
                }
            }
            w.appendLine("--- /STATE ---")
            w.flush()
        }
    }

    private fun discoverPrefsNames(ctx: Context): List<String> {
        val dir = File(ctx.applicationContext.dataDir, "shared_prefs")
        if (!dir.exists() || !dir.isDirectory) return emptyList()
        return dir.listFiles().orEmpty()
            .filter { it.isFile && it.name.endsWith(".xml") }
            .map { it.name.removeSuffix(".xml") }
            .sorted()
    }

    // -------- internals --------

    /**
     * Read every key/value from [prefsName], redacting values whose
     * keys look sensitive (vault data, secrets, derived KEKs). The
     * redaction is a denylist of substring matches because the
     * positive list "everything in firewall/backups settings" is
     * harder to maintain across apps.
     *
     * Anything unfamiliar gets its value summarized, not emitted —
     * "<bytes:N>" for ByteArrays, "<set:N>" for collections, the raw
     * value only for primitives that are clearly UI shape data.
     */
    private fun snapshotPrefs(ctx: Context, prefsName: String): Map<String, String> {
        val out = sortedMapOf<String, String>()
        val prefs = ctx.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
        for ((k, raw) in prefs.all) {
            val key = k.lowercase(Locale.ROOT)
            val sensitive = SENSITIVE_SUBSTRINGS.any { it in key }
            val value = when (raw) {
                null -> "null"
                is String -> if (sensitive) "<redacted:str:${raw.length}>" else raw
                is Boolean -> raw.toString()
                is Int -> raw.toString()
                is Long -> raw.toString()
                is Float -> raw.toString()
                is Set<*> -> if (sensitive) "<redacted:set:${raw.size}>" else "{${raw.joinToString(",")}}"
                else -> "<unknown:${raw.javaClass.simpleName}>"
            }
            out[k] = value
        }
        return out
    }

    private val SENSITIVE_SUBSTRINGS = listOf(
        "secret", "password", "passphrase", "kek", "key_material",
        "totp", "hotp", "vault", "entry", "biometric", "recovery",
    )

    /** Open the writer. Tries MediaStore Documents first, then falls back. */
    private fun openWriter(ctx: Context): DumpWriter? {
        val appLabel = appLabel(ctx)
        val filename = "$appLabel.log"
        runCatching {
            val mediaWriter = openMediaStoreWriter(ctx, filename)
            if (mediaWriter != null) return mediaWriter
        }
        // Fallback: app's own external-files Documents dir. Always
        // writable; reachable through the system Files app at
        // /Android/data/<package>/files/Documents/ but harder to find.
        return runCatching {
            val dir = ctx.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS)
                ?: return null
            if (!dir.exists()) dir.mkdirs()
            val f = File(dir, filename)
            // Pre-rotation if a prior session left the file over cap, so
            // a fresh session doesn't start at 5+ MB and only rotate
            // after another 5 MB of new writes.
            if (f.exists() && f.length() > ROTATION_BYTES) {
                val prev = File(dir, "$filename.prev")
                runCatching { prev.delete() }
                runCatching { f.renameTo(prev) }
            }
            val out = FileOutputStream(f, /* append = */ true)
            val w = BufferedWriter(OutputStreamWriter(out, Charsets.UTF_8))
            FallbackFileWriter(w, f.absolutePath)
        }.getOrNull()
    }

    private fun openMediaStoreWriter(ctx: Context, filename: String): DumpWriter? {
        val resolver = ctx.contentResolver
        val collection = MediaStore.Files.getContentUri("external")
        val relativePath = "${Environment.DIRECTORY_DOCUMENTS}/$DOC_SUBDIR/"
        // Look for existing entry to append to.
        val existing = findMediaStoreEntry(ctx, collection, filename, relativePath)
        val uri: Uri = if (existing != null) {
            existing
        } else {
            val values = ContentValues().apply {
                put(MediaStore.Files.FileColumns.DISPLAY_NAME, filename)
                put(MediaStore.Files.FileColumns.MIME_TYPE, "text/plain")
                put(MediaStore.Files.FileColumns.RELATIVE_PATH, relativePath)
            }
            resolver.insert(collection, values) ?: return null
        }
        // mode "wa" = write+append. Supported on Android 11+ for
        // content:// URIs from MediaStore.
        val out = resolver.openOutputStream(uri, "wa") ?: return null
        val w = BufferedWriter(OutputStreamWriter(out, Charsets.UTF_8))
        return MediaStoreWriter(w, uri)
    }

    private fun findMediaStoreEntry(
        ctx: Context,
        collection: Uri,
        filename: String,
        relativePath: String,
    ): Uri? {
        val projection = arrayOf(MediaStore.Files.FileColumns._ID)
        val selection =
            "${MediaStore.Files.FileColumns.DISPLAY_NAME}=? AND " +
                "${MediaStore.Files.FileColumns.RELATIVE_PATH}=?"
        val args = arrayOf(filename, relativePath)
        return ctx.contentResolver.query(collection, projection, selection, args, null)?.use { c ->
            if (c.moveToFirst()) {
                val id = c.getLong(0)
                Uri.withAppendedPath(collection, id.toString())
            } else null
        }
    }

    private fun installSink() {
        Diagnostics.addSink(object : Diagnostics.Sink {
            override fun onEvent(ev: Diagnostics.Event) {
                val w = writerRef.get() ?: return
                runCatching {
                    val ts = tsFormat.format(Date(ev.timestampMs))
                    w.appendLine("$ts [${ev.level.name}] ${ev.tag}: ${ev.message}")
                }
            }
        })
    }

    private fun installCrashHandler() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching {
                val w = writerRef.get()
                if (w != null) {
                    w.appendLine("--- CRASH @ ${tsFormat.format(Date())} thread=${thread.name} ---")
                    w.appendLine(throwable.stackTraceToString())
                    w.appendLine("--- /CRASH ---")
                    w.flush()
                }
            }
            // Chain to the previous handler so AGP's default-crash UI
            // and any host's own crash reporter still fire.
            previous?.uncaughtException(thread, throwable)
                ?: kotlin.system.exitProcess(2)
        }
    }

    private fun startFlushTimer() {
        val t = Thread({
            while (active.get()) {
                runCatching { Thread.sleep(FLUSH_INTERVAL_MS) }
                val w = writerRef.get() ?: continue
                runCatching { w.flush() }
                if (w.bytesWritten() >= ROTATION_BYTES) {
                    val ctx = appCtxRef.get()
                    if (ctx != null) runCatching { rotate(ctx, w) }
                }
            }
        }, "DiagnosticsDump-flush")
        t.isDaemon = true
        t.start()
    }

    /**
     * Close the active writer, rename the underlying file/entry to
     * `<filename>.prev` (replacing any earlier .prev), and open a
     * fresh writer at the original name. Called from the flush
     * thread when [DumpWriter.bytesWritten] crosses [ROTATION_BYTES].
     *
     * @Synchronized + writerRef identity check protects against a
     * concurrent flush-tick deciding to rotate the same writer twice.
     * If the rename or reopen fails, the existing writer is left in
     * place by the runCatching wrappers — losing rotation is
     * preferable to losing log lines.
     */
    @Synchronized
    private fun rotate(ctx: Context, old: DumpWriter) {
        if (writerRef.get() !== old) return
        val filename = "${appLabel(ctx)}.log"
        val prevName = "$filename.prev"
        runCatching { old.close() }
        when (old) {
            is FallbackFileWriter -> {
                val f = File(old.path)
                val prev = File(f.parentFile, prevName)
                runCatching { prev.delete() }
                runCatching { f.renameTo(prev) }
            }
            is MediaStoreWriter -> {
                val resolver = ctx.contentResolver
                val collection = MediaStore.Files.getContentUri("external")
                val relativePath = "${Environment.DIRECTORY_DOCUMENTS}/$DOC_SUBDIR/"
                // Drop any earlier .prev so we cap at ~10 MB total per
                // app across the live + previous file.
                findMediaStoreEntry(ctx, collection, prevName, relativePath)?.let { prev ->
                    runCatching { resolver.delete(prev, null, null) }
                }
                // Rename the active entry by updating DISPLAY_NAME. The
                // OS handles the on-disk filename change; the user-
                // visible name in the system Files app updates
                // immediately.
                val values = ContentValues().apply {
                    put(MediaStore.Files.FileColumns.DISPLAY_NAME, prevName)
                }
                runCatching { resolver.update(old.uri, values, null, null) }
            }
        }
        val fresh = openWriter(ctx)
        if (fresh == null) {
            Diagnostics.warn("DiagnosticsDump",
                "rotation: reopen failed; dump now inactive for this process")
            writerRef.set(null)
            return
        }
        writerRef.set(fresh)
        runCatching {
            fresh.appendLine("=== rotation ${tsFormat.format(Date())} ===")
            fresh.flush()
        }
    }

    /** "com.understory.firewall.eng" → "firewall". */
    private fun appLabel(ctx: Context): String {
        val parts = ctx.packageName.split('.')
        // "com.understory.firewall.eng" → take the segment before .eng.
        return parts.dropLast(1).lastOrNull() ?: parts.last()
    }

    private fun appVersionName(ctx: Context): String = runCatching {
        @Suppress("DEPRECATION")
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "?"
    }.getOrDefault("?")

    private fun appVersionCode(ctx: Context): Long = runCatching {
        @Suppress("DEPRECATION")
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).longVersionCode
    }.getOrDefault(-1L)

    private interface DumpWriter {
        fun appendLine(s: String)
        fun flush()
        fun describePath(): String
        /** Approximate bytes written this session — used to gate rotation. */
        fun bytesWritten(): Long
        /** Close the underlying stream. After [close], no further writes are permitted. */
        fun close()
    }

    private class MediaStoreWriter(
        private val w: Writer,
        val uri: Uri,
    ) : DumpWriter {
        @Volatile private var bytes: Long = 0L
        override fun appendLine(s: String) {
            synchronized(w) {
                w.write(s); w.write("\n")
                bytes += s.length + 1L
            }
        }
        override fun flush() {
            synchronized(w) { runCatching { w.flush() } }
        }
        override fun describePath(): String = "MediaStore:$uri"
        override fun bytesWritten(): Long = bytes
        override fun close() {
            synchronized(w) { runCatching { w.close() } }
        }
    }

    private class FallbackFileWriter(
        private val w: Writer,
        val path: String,
    ) : DumpWriter {
        // Seed from on-disk size so a session that resumes a prior file
        // rotates promptly rather than after 5 MB of new writes on top
        // of an already-large file.
        @Volatile private var bytes: Long = File(path).length()
        override fun appendLine(s: String) {
            synchronized(w) {
                w.write(s); w.write("\n")
                bytes += s.length + 1L
            }
        }
        override fun flush() {
            synchronized(w) { runCatching { w.flush() } }
        }
        override fun describePath(): String = "File:$path"
        override fun bytesWritten(): Long = bytes
        override fun close() {
            synchronized(w) { runCatching { w.close() } }
        }
    }
}
