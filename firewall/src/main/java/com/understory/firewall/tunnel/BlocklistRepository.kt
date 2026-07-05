package com.understory.firewall.tunnel

import android.content.Context
import com.understory.net.engine.DnsBlocklist
import com.understory.security.Diagnostics
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPInputStream

/**
 * Loads and holds the on-device [DnsBlocklist] for the S6 tunnel. Merges three
 * sources, cheapest-first:
 *   1. the BUNDLED, gzip-compressed starter list ("blocklist/base.hosts.gz") —
 *      lazily decompressed once, off the UI thread;
 *   2. a USER-UPDATABLE list fetched from a URL the user supplies (capped +
 *      cached to a private file), refreshed on demand only;
 *   3. the user's own custom BLOCK and ALLOW domains (prefs).
 *
 * HONESTY / CAPS (design invariant): the bundled list is a CURATED SEED (~100
 * domain roots, each blocking its subtree), NOT an exhaustive blocklist — the UI
 * says so and points at the update-URL path. A fetched list is hard-capped at
 * [MAX_FETCH_BYTES]; if the source is larger we load a prefix and LOG that we
 * capped/sampled it (never silently truncate into a false "fully loaded").
 *
 * Thread-safety: [current] is volatile; [reload] builds a new immutable
 * [DnsBlocklist] and publishes it atomically. Callers read [current] on the hot
 * path with no lock.
 */
object BlocklistRepository {

    private const val TAG = "firewall.tunnel.BlocklistRepository"
    private const val ASSET = "blocklist/base.hosts.gz"
    private const val CACHE_FILE = "blocklist_fetched.txt"
    private const val PREF = "firewall_dns_filter"
    private const val K_ENABLED = "dns_filter_enabled"
    private const val K_UPDATE_URL = "dns_filter_update_url"
    private const val K_CUSTOM_BLOCK = "dns_filter_custom_block"
    private const val K_CUSTOM_ALLOW = "dns_filter_custom_allow"
    private const val K_ANSWER_STYLE = "dns_filter_answer_style"
    private const val K_LAST_FETCH = "dns_filter_last_fetch_millis"

    /** Hard cap on a fetched list to bound memory + APK-independent growth. */
    private const val MAX_FETCH_BYTES = 8 * 1024 * 1024 // 8 MiB
    private const val FETCH_TIMEOUT_MS = 20_000

    @Volatile
    private var loaded: DnsBlocklist = DnsBlocklist.empty()

    @Volatile
    private var lastLoadStats: LoadStats = LoadStats(0, 0, false, null)

    /** The live blocklist. Empty until [reload] runs at least once. */
    val current: DnsBlocklist get() = loaded

    /** Diagnostics for the settings screen. */
    data class LoadStats(
        val bundledDomains: Int,
        val totalDomains: Int,
        val fetchedListPresent: Boolean,
        val cappedNote: String?,
    )

    fun stats(): LoadStats = lastLoadStats

    // ---------------------------------------------------------------
    // Prefs-backed settings the UI edits
    // ---------------------------------------------------------------

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun isFilterEnabled(ctx: Context): Boolean = prefs(ctx).getBoolean(K_ENABLED, true)
    fun setFilterEnabled(ctx: Context, on: Boolean) =
        prefs(ctx).edit().putBoolean(K_ENABLED, on).apply()

    fun updateUrl(ctx: Context): String = prefs(ctx).getString(K_UPDATE_URL, "") ?: ""
    fun setUpdateUrl(ctx: Context, url: String) =
        prefs(ctx).edit().putString(K_UPDATE_URL, url.trim()).apply()

    fun customBlock(ctx: Context): Set<String> =
        prefs(ctx).getStringSet(K_CUSTOM_BLOCK, emptySet())?.toSet() ?: emptySet()

    fun customAllow(ctx: Context): Set<String> =
        prefs(ctx).getStringSet(K_CUSTOM_ALLOW, emptySet())?.toSet() ?: emptySet()

    fun addCustomBlock(ctx: Context, domain: String) = mutateSet(ctx, K_CUSTOM_BLOCK, domain, true)
    fun removeCustomBlock(ctx: Context, domain: String) = mutateSet(ctx, K_CUSTOM_BLOCK, domain, false)
    fun addCustomAllow(ctx: Context, domain: String) = mutateSet(ctx, K_CUSTOM_ALLOW, domain, true)
    fun removeCustomAllow(ctx: Context, domain: String) = mutateSet(ctx, K_CUSTOM_ALLOW, domain, false)

    private fun mutateSet(ctx: Context, key: String, domain: String, add: Boolean) {
        val norm = DnsBlocklist.extractDomain(domain) ?: return
        val cur = (prefs(ctx).getStringSet(key, emptySet()) ?: emptySet()).toMutableSet()
        if (add) cur += norm else cur -= norm
        prefs(ctx).edit().putStringSet(key, cur).apply()
    }

    /** Which sinkhole answer the tunnel returns for a blocked domain. */
    fun answerStyle(ctx: Context): com.understory.net.engine.DnsMessage.BlockAnswer {
        val raw = prefs(ctx).getString(K_ANSWER_STYLE, null)
        return runCatching { com.understory.net.engine.DnsMessage.BlockAnswer.valueOf(raw ?: "") }
            .getOrDefault(com.understory.net.engine.DnsMessage.BlockAnswer.NXDOMAIN)
    }

    fun setAnswerStyle(ctx: Context, style: com.understory.net.engine.DnsMessage.BlockAnswer) =
        prefs(ctx).edit().putString(K_ANSWER_STYLE, style.name).apply()

    fun lastFetchMillis(ctx: Context): Long = prefs(ctx).getLong(K_LAST_FETCH, 0L)

    // ---------------------------------------------------------------
    // Load / reload
    // ---------------------------------------------------------------

    /**
     * Rebuild [current] from the bundled asset + cached fetched list + custom
     * sets. Blocking I/O — call off the main thread. Idempotent.
     */
    @Synchronized
    fun reload(ctx: Context) {
        val bundled = readBundled(ctx)
        val fetched = readFetchedCache(ctx)
        val fetchedPresent = fetched.isNotEmpty()

        val blockLines = sequence {
            yieldAll(bundled.asSequence())
            yieldAll(fetched.asSequence())
            yieldAll(customBlock(ctx).asSequence())
        }
        val bl = DnsBlocklist.build(blockLines, customAllow(ctx).asSequence())
        loaded = bl
        lastLoadStats = LoadStats(
            bundledDomains = bundled.size, // pre-parse line count is fine as a floor
            totalDomains = bl.size,
            fetchedListPresent = fetchedPresent,
            cappedNote = lastCappedNote,
        )
        Diagnostics.log(TAG, "reload: ${bl.size} domains (bundledLines=${bundled.size}, fetchedLines=${fetched.size})")
    }

    private fun readBundled(ctx: Context): List<String> = try {
        ctx.assets.open(ASSET).use { raw ->
            GZIPInputStream(raw).bufferedReader().use { it.readLines() }
        }
    } catch (t: Throwable) {
        Diagnostics.error(TAG, "readBundled failed: ${t.javaClass.simpleName}")
        emptyList()
    }

    private fun readFetchedCache(ctx: Context): List<String> {
        val f = ctx.getFileStreamPath(CACHE_FILE)
        if (f == null || !f.exists()) return emptyList()
        return try {
            ctx.openFileInput(CACHE_FILE).bufferedReader().use { it.readLines() }
        } catch (t: Throwable) {
            Diagnostics.error(TAG, "readFetchedCache failed: ${t.javaClass.simpleName}")
            emptyList()
        }
    }

    @Volatile private var lastCappedNote: String? = null

    /**
     * Fetch the user's update URL over HTTPS, cap it, cache it, and reload.
     * Blocking — call off the main thread. Returns a human result string.
     *
     * HONEST: only https:// URLs are accepted (no cleartext). A body over
     * [MAX_FETCH_BYTES] is truncated at a line boundary and the cap is recorded
     * in [LoadStats.cappedNote] + logged, never silently.
     */
    fun fetchAndCache(ctx: Context): String {
        val url = updateUrl(ctx).trim()
        if (url.isEmpty()) return "No update URL set."
        if (!url.startsWith("https://")) return "Update URL must be https:// (refused cleartext)."

        return try {
            val conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = FETCH_TIMEOUT_MS
                readTimeout = FETCH_TIMEOUT_MS
                requestMethod = "GET"
                instanceFollowRedirects = true
            }
            val code = conn.responseCode
            if (code != HttpURLConnection.HTTP_OK) {
                conn.disconnect()
                return "Fetch failed (HTTP $code)."
            }
            var bytes = 0L
            var capped = false
            val kept = StringBuilder()
            BufferedReader(InputStreamReader(conn.inputStream)).use { reader ->
                var line = reader.readLine()
                while (line != null) {
                    val add = line.length + 1
                    if (bytes + add > MAX_FETCH_BYTES) { capped = true; break }
                    bytes += add
                    kept.append(line).append('\n')
                    line = reader.readLine()
                }
            }
            conn.disconnect()
            ctx.openFileOutput(CACHE_FILE, Context.MODE_PRIVATE).use { it.write(kept.toString().toByteArray()) }
            prefs(ctx).edit().putLong(K_LAST_FETCH, System.currentTimeMillis()).apply()
            lastCappedNote = if (capped)
                "Fetched list exceeded ${MAX_FETCH_BYTES / (1024 * 1024)} MiB — loaded a prefix only."
            else null
            if (capped) Diagnostics.log(TAG, "fetch CAPPED at $MAX_FETCH_BYTES bytes: $url")
            reload(ctx)
            val note = if (capped) " (capped to prefix)" else ""
            "Updated — ${lastLoadStats.totalDomains} domains loaded$note."
        } catch (t: Throwable) {
            Diagnostics.error(TAG, "fetchAndCache threw ${t.javaClass.simpleName}: ${t.message}")
            "Fetch failed: ${t.javaClass.simpleName}"
        }
    }

    /** Delete the fetched cache and reload (back to bundled + custom only). */
    fun clearFetched(ctx: Context): String {
        runCatching { ctx.deleteFile(CACHE_FILE) }
        prefs(ctx).edit().remove(K_LAST_FETCH).apply()
        lastCappedNote = null
        reload(ctx)
        return "Cleared the fetched list — using the bundled seed + your custom domains."
    }
}
