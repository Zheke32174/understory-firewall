package com.understory.firewall.tunnel

import android.content.Context
import com.understory.net.engine.dnscrypt.DnsStamp
import com.understory.security.Diagnostics
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPInputStream

/**
 * The DNSCrypt / DoH resolver + relay lists that InviZible Pro and dnscrypt-proxy
 * ship, bundled here as gzipped assets and parseable at runtime. Each list is the
 * canonical `sdns://`-stamp markdown from the DNSCrypt project; [load] parses it
 * into typed [Resolver]s, filtered by the user's privacy requirements.
 *
 * The bundled snapshot is a real, complete list (~900 resolvers, ~350 relays),
 * NOT a curated stub — but it ages, so [refresh] re-fetches the canonical file
 * over HTTPS (the same source dnscrypt-proxy uses) and caches it. Selecting a
 * resolver stores its stamp; [selectedResolver] parses it back for the tunnel's
 * native [DnsFilterTun.UpstreamResolver.fromStamp] upstream.
 *
 * HONEST scope: this consumes only the plaintext markdown lists. It does NOT
 * verify the upstream minisign signature on the list file (dnscrypt-proxy does);
 * the per-resolver security guarantee comes instead from the DNSCrypt certificate
 * chain enforced at query time (Ed25519 cert verification in DnscryptClient), so a
 * tampered LIST could swap which resolver you talk to but cannot forge a resolver
 * identity. The UI states this.
 */
object DnscryptResolvers {

    private const val TAG = "firewall.tunnel.DnscryptResolvers"
    private const val PREF = "firewall_dnscrypt"

    private const val K_ENABLED = "dnscrypt_enabled"
    private const val K_SELECTED = "dnscrypt_selected_stamp"
    private const val K_REQ_NOLOG = "dnscrypt_require_nolog"
    private const val K_REQ_DNSSEC = "dnscrypt_require_dnssec"
    private const val K_REQ_NOFILTER = "dnscrypt_require_nofilter"
    private const val K_LAST_REFRESH = "dnscrypt_last_refresh"

    private const val ASSET_RESOLVERS = "dnscrypt/public-resolvers.md.gz"
    private const val ASSET_RELAYS = "dnscrypt/relays.md.gz"
    private const val CACHE_RESOLVERS = "dnscrypt_public_resolvers.md"
    const val RESOLVERS_URL =
        "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md"

    private const val MAX_FETCH_BYTES = 4 * 1024 * 1024
    private const val FETCH_TIMEOUT_MS = 20_000

    /** A resolver or relay parsed from a stamp list. */
    data class Resolver(
        val name: String,
        val description: String,
        val stamp: DnsStamp,
    ) {
        val proto get() = stamp.proto
        /** True when we can carry queries over this stamp (DNSCrypt / DoH / DoT). */
        val usable: Boolean
            get() = proto == DnsStamp.Proto.DNSCRYPT || proto == DnsStamp.Proto.DOH || proto == DnsStamp.Proto.DOT
    }

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    // ---- settings (every value has a working default) ----

    /** DNSCrypt as the tunnel's upstream. Default OFF — the base app keeps its plaintext/DoT upstream. */
    fun isEnabled(ctx: Context): Boolean = prefs(ctx).getBoolean(K_ENABLED, false)
    fun setEnabled(ctx: Context, on: Boolean) = prefs(ctx).edit().putBoolean(K_ENABLED, on).apply()

    /** The selected resolver's stamp string. Blank ⇒ [selectedResolver] picks a sane default. */
    fun selectedStamp(ctx: Context): String = prefs(ctx).getString(K_SELECTED, "").orEmpty()
    fun setSelectedStamp(ctx: Context, stamp: String) =
        prefs(ctx).edit().putString(K_SELECTED, stamp.trim()).apply()

    /** Require the resolver to state a no-logging policy. Default ON (privacy-first base default). */
    fun requireNoLog(ctx: Context): Boolean = prefs(ctx).getBoolean(K_REQ_NOLOG, true)
    fun setRequireNoLog(ctx: Context, on: Boolean) = prefs(ctx).edit().putBoolean(K_REQ_NOLOG, on).apply()

    /** Require DNSSEC validation. Default ON. */
    fun requireDnssec(ctx: Context): Boolean = prefs(ctx).getBoolean(K_REQ_DNSSEC, true)
    fun setRequireDnssec(ctx: Context, on: Boolean) = prefs(ctx).edit().putBoolean(K_REQ_DNSSEC, on).apply()

    /** Require the resolver to NOT block/censor (no-filter). Default OFF (many good resolvers filter malware). */
    fun requireNoFilter(ctx: Context): Boolean = prefs(ctx).getBoolean(K_REQ_NOFILTER, false)
    fun setRequireNoFilter(ctx: Context, on: Boolean) = prefs(ctx).edit().putBoolean(K_REQ_NOFILTER, on).apply()

    fun lastRefreshMillis(ctx: Context): Long = prefs(ctx).getLong(K_LAST_REFRESH, 0L)

    // ---- list loading ----

    /** All usable resolvers matching the user's privacy requirements, name-sorted. */
    fun load(ctx: Context): List<Resolver> {
        val text = readResolversText(ctx)
        val all = parseMarkdown(text).filter { it.usable }
        return all.filter { r ->
            (!requireNoLog(ctx) || r.stamp.noLogs) &&
                (!requireDnssec(ctx) || r.stamp.dnssec) &&
                (!requireNoFilter(ctx) || r.stamp.noFilter)
        }.sortedBy { it.name }
    }

    /** DNSCrypt anonymization relays (for future anonymized-DNSCrypt routing / display). */
    fun relays(ctx: Context): List<Resolver> =
        runCatching { parseMarkdown(readAsset(ctx, ASSET_RELAYS)) }.getOrDefault(emptyList())

    /**
     * The currently selected resolver, or a sane default when nothing is chosen:
     * prefer a well-known no-log DNSSEC DNSCrypt resolver, else the first usable one.
     */
    fun selectedResolver(ctx: Context): Resolver? {
        val list = load(ctx)
        val sel = selectedStamp(ctx)
        if (sel.isNotBlank()) {
            list.firstOrNull { it.stamp.raw == sel }?.let { return it }
            // Selected stamp no longer in the (filtered) list — parse it directly so a
            // valid saved choice still works even if a filter would now hide it.
            DnsStamp.parse(sel)?.let { return Resolver("(saved resolver)", "", it) }
        }
        return defaultResolver(list)
    }

    /** The parsed stamp for the active resolver, ready for the upstream. */
    fun selectedStampParsed(ctx: Context): DnsStamp? = selectedResolver(ctx)?.stamp

    private val PREFERRED_NAMES = listOf("cloudflare", "quad9", "adguard", "mullvad", "cs-", "dnscry.pt")

    private fun defaultResolver(list: List<Resolver>): Resolver? {
        val dnscrypt = list.filter { it.proto == DnsStamp.Proto.DNSCRYPT }
        for (pref in PREFERRED_NAMES) {
            dnscrypt.firstOrNull { it.name.contains(pref, ignoreCase = true) }?.let { return it }
        }
        return dnscrypt.firstOrNull() ?: list.firstOrNull()
    }

    // ---- refresh from the canonical HTTPS source ----

    fun refresh(ctx: Context): String {
        return try {
            val conn = (URL(RESOLVERS_URL).openConnection() as HttpURLConnection).apply {
                connectTimeout = FETCH_TIMEOUT_MS
                readTimeout = FETCH_TIMEOUT_MS
                requestMethod = "GET"
                instanceFollowRedirects = true
            }
            val code = conn.responseCode
            if (code != HttpURLConnection.HTTP_OK) {
                conn.disconnect()
                return "Refresh failed (HTTP $code)."
            }
            var bytes = 0L
            val kept = StringBuilder()
            BufferedReader(InputStreamReader(conn.inputStream)).use { reader ->
                var line = reader.readLine()
                while (line != null) {
                    bytes += line.length + 1
                    if (bytes > MAX_FETCH_BYTES) break
                    kept.append(line).append('\n')
                    line = reader.readLine()
                }
            }
            conn.disconnect()
            ctx.openFileOutput(CACHE_RESOLVERS, Context.MODE_PRIVATE).use { it.write(kept.toString().toByteArray()) }
            prefs(ctx).edit().putLong(K_LAST_REFRESH, System.currentTimeMillis()).apply()
            val n = parseMarkdown(kept.toString()).count { it.usable }
            "Updated — $n usable resolvers loaded."
        } catch (t: Throwable) {
            Diagnostics.error(TAG, "refresh threw ${t.javaClass.simpleName}")
            "Refresh failed: ${t.javaClass.simpleName}"
        }
    }

    /** Delete the refreshed cache; fall back to the bundled snapshot. */
    fun clearRefreshed(ctx: Context): String {
        runCatching { ctx.deleteFile(CACHE_RESOLVERS) }
        prefs(ctx).edit().remove(K_LAST_REFRESH).apply()
        return "Cleared the refreshed list — using the bundled snapshot."
    }

    private fun readResolversText(ctx: Context): String {
        val cache = ctx.getFileStreamPath(CACHE_RESOLVERS)
        if (cache != null && cache.exists()) {
            runCatching { ctx.openFileInput(CACHE_RESOLVERS).bufferedReader().use { it.readText() } }
                .onSuccess { if (it.isNotBlank()) return it }
        }
        return readAsset(ctx, ASSET_RESOLVERS)
    }

    private fun readAsset(ctx: Context, asset: String): String =
        ctx.assets.open(asset).use { GZIPInputStream(it).bufferedReader().use { r -> r.readText() } }

    /**
     * Parse the DNSCrypt stamp-list markdown: `## name` header, free-text
     * description lines, then one or more `sdns://` stamp lines. Each stamp becomes
     * its own [Resolver] (a name with two stamps → two entries, "name" / "name #2").
     */
    fun parseMarkdown(text: String): List<Resolver> {
        val out = ArrayList<Resolver>()
        var name = ""
        val desc = StringBuilder()
        var stampIdx = 0
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            when {
                line.startsWith("## ") -> {
                    name = line.removePrefix("## ").trim()
                    desc.setLength(0)
                    stampIdx = 0
                }
                line.startsWith("sdns://") -> {
                    val stamp = DnsStamp.parse(line) ?: continue
                    stampIdx++
                    val label = if (stampIdx == 1) name else "$name #$stampIdx"
                    out.add(Resolver(label, desc.toString().trim(), stamp))
                }
                line.isNotEmpty() && !line.startsWith("#") && name.isNotEmpty() -> {
                    if (desc.length < 400) desc.append(line).append(' ')
                }
            }
        }
        return out
    }
}
