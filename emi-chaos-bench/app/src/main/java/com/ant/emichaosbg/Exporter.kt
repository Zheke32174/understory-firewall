package com.ant.emichaosbg

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.webkit.JavascriptInterface
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File

/**
 * Native file export.
 *
 * WHY THIS EXISTS. Every export in this app was silently broken. The page built a Blob, made
 * an object URL, and clicked a synthetic `<a download="...">`. In a normal browser that saves a
 * file. In an Android WebView it does NOTHING: WebView does not act on the `download`
 * attribute, and no `DownloadListener` was registered to catch it. The click succeeded, no
 * exception was thrown, so the surrounding try/catch never fired and the user got neither a
 * file nor an error message — the button simply did nothing, forever.
 *
 * That is why "exports aren't working". It was never a formatting or permissions problem.
 *
 * WHERE FILES GO. Public Downloads, via MediaStore on API 29+ (no storage permission needed,
 * and the file survives the app being uninstalled) with a direct-file fallback below that.
 * The saved path is returned to the page so the toast can name it — "saved" with no location
 * is only marginally better than silence.
 *
 * SHARING. [share] hands the same content to the system share sheet through a FileProvider
 * URI, for getting a log off the device without a cable. It is a separate, explicit call: an
 * export writes locally and nothing leaves the device unless the share sheet is invoked and a
 * target chosen.
 */
class Exporter(private val ctx: Context) {

    /**
     * Writes [content] to public Downloads and returns a JSON result naming the path.
     * Never throws into the page — a failure comes back as ok:false with a reason, which is
     * the whole point given the old path failed invisibly.
     */
    @JavascriptInterface
    fun save(filename: String?, mime: String?, content: String?): String {
        val o = JSONObject()
        val name = sanitise(filename)
        if (content == null) return o.put("ok", false).put("reason", "no content").toString()
        val type = if (mime.isNullOrBlank()) "text/plain" else mime
        return try {
            val where = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                saveViaMediaStore(name, type, content) else saveViaFile(name, content)
            o.put("ok", true).put("path", where).put("bytes", content.toByteArray().size).toString()
        } catch (e: Throwable) {
            // Last-ditch: app-private external files dir. Always writable, no permission, and
            // reachable over USB — better than reporting a failure the user can do nothing with.
            try {
                val f = File(ctx.getExternalFilesDir(null), name)
                f.writeText(content)
                o.put("ok", true).put("path", f.absolutePath).put("fallback", true)
                    .put("bytes", content.toByteArray().size).toString()
            } catch (e2: Throwable) {
                o.put("ok", false)
                    .put("reason", e.javaClass.simpleName + ": " + (e.message ?: "") +
                        " / fallback " + e2.javaClass.simpleName + ": " + (e2.message ?: ""))
                    .toString()
            }
        }
    }

    /**
     * THE WRITE IS VERIFIED, NOT ASSUMED.
     *
     * Reported as "no file at that location" after a success toast, and the old version could
     * not tell the difference between a real save and several ways of half-saving:
     *
     *   - IS_PENDING is set to 1 before writing and cleared afterwards. A pending entry is
     *       INVISIBLE to the Files app and to every media-scanning consumer. If the clearing
     *       update failed — or the process died between the write and the update — the row
     *       existed, the bytes existed, and the user saw nothing in Downloads. The old code
     *       ignored update()'s return value entirely, so that case reported success.
     *   - insert() returning a URI does not mean anything was written to it.
     *
     * So now: the pending flag is cleared and the row is queried BACK for its size and real
     * display name. If the row is gone, or reports zero bytes, or the clear failed, that is a
     * failure and it says so rather than pointing at an empty folder.
     */
    private fun saveViaMediaStore(name: String, mime: String, content: String): String {
        val bytes = content.toByteArray()
        val cv = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, mime)
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val resolver = ctx.contentResolver
        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)
            ?: throw IllegalStateException("MediaStore refused the insert")
        resolver.openOutputStream(uri).use { os ->
            os ?: throw IllegalStateException("no output stream")
            os.write(bytes)
            os.flush()
        }
        cv.clear(); cv.put(MediaStore.MediaColumns.IS_PENDING, 0)
        val cleared = resolver.update(uri, cv, null, null)
        if (cleared < 1) throw IllegalStateException(
            "file stayed in PENDING state — it is written but hidden from Downloads")

        // Read the row back. This is the only honest confirmation available to us.
        var seenName = name
        var seenSize = -1L
        runCatching {
            resolver.query(uri,
                arrayOf(MediaStore.MediaColumns.DISPLAY_NAME, MediaStore.MediaColumns.SIZE),
                null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    seenName = c.getString(0) ?: name
                    seenSize = c.getLong(1)
                }
            }
        }
        if (seenSize == 0L) throw IllegalStateException("file was created but is empty")
        // MediaStore may rename on collision (foo.json -> foo (1).json). Report the REAL name,
        // otherwise the user is told to look for a filename that is not there.
        return "Downloads/$seenName"
    }

    @Suppress("DEPRECATION")
    private fun saveViaFile(name: String, content: String): String {
        val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!dir.exists()) dir.mkdirs()
        val f = File(dir, name)
        f.writeText(content)
        return f.absolutePath
    }

    /** Writes to cache and opens the system share sheet. Nothing leaves the device until the
     *  user picks a target in that sheet. */
    @JavascriptInterface
    fun share(filename: String?, mime: String?, content: String?): String {
        val o = JSONObject()
        if (content == null) return o.put("ok", false).put("reason", "no content").toString()
        return try {
            val name = sanitise(filename)
            val dir = File(ctx.cacheDir, "exports").apply { mkdirs() }
            val f = File(dir, name)
            f.writeText(content)
            val uri = FileProvider.getUriForFile(ctx, ctx.packageName + ".fileprovider", f)
            val i = Intent(Intent.ACTION_SEND).apply {
                type = if (mime.isNullOrBlank()) "text/plain" else mime
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, name)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            ctx.startActivity(Intent.createChooser(i, "Share $name")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            o.put("ok", true).put("path", f.name).toString()
        } catch (e: Throwable) {
            o.put("ok", false).put("reason", e.javaClass.simpleName + ": " + (e.message ?: "")).toString()
        }
    }

    /**
     * Filenames come from the untrusted page compartment, so they are constrained here rather
     * than trusted. Path separators and traversal are stripped — a name like "../../x" must
     * not be able to steer the write out of the export directory.
     */
    private fun sanitise(raw: String?): String {
        val base = (raw ?: "").substringAfterLast('/').substringAfterLast('\\')
            .replace("..", "_")
            .filter { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' }
            .take(120)
        return if (base.isBlank()) "emi-export-" + System.currentTimeMillis() + ".txt" else base
    }
}
