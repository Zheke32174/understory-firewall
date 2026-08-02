package com.understory.godwall.dns

import android.content.Context

/**
 * Persisted upstream-resolver configuration. Everything the DNS screen edits
 * lives here; [resolver] is the single place that turns it into a live
 * [UpstreamResolver], so the tunnel and the in-app upstream test can never
 * disagree about what is configured.
 */
object DnsSettings {

    private const val PREF = "godwall_dns"
    private const val K_MODE = "upstream_mode"
    private const val K_IP = "upstream_ip"
    private const val K_HOST = "upstream_hostname"
    private const val K_PATH = "upstream_doh_path"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    /** Default is DoT to Cloudflare: encrypted and verified out of the box. */
    fun mode(ctx: Context): UpstreamResolver.Mode = runCatching {
        UpstreamResolver.Mode.valueOf(p(ctx).getString(K_MODE, "") ?: "")
    }.getOrDefault(UpstreamResolver.Mode.DOT)

    fun setMode(ctx: Context, m: UpstreamResolver.Mode) {
        p(ctx).edit().putString(K_MODE, m.name).apply()
    }

    fun ip(ctx: Context): String = p(ctx).getString(K_IP, "1.1.1.1") ?: "1.1.1.1"

    fun setIp(ctx: Context, v: String) {
        p(ctx).edit().putString(K_IP, v.trim()).apply()
    }

    fun hostname(ctx: Context): String =
        p(ctx).getString(K_HOST, "cloudflare-dns.com") ?: "cloudflare-dns.com"

    fun setHostname(ctx: Context, v: String) {
        p(ctx).edit().putString(K_HOST, v.trim()).apply()
    }

    fun dohPath(ctx: Context): String = p(ctx).getString(K_PATH, "/dns-query") ?: "/dns-query"

    fun setDohPath(ctx: Context, v: String) {
        p(ctx).edit().putString(K_PATH, v.trim()).apply()
    }

    fun applyPreset(ctx: Context, ip: String, hostname: String) {
        p(ctx).edit().putString(K_IP, ip).putString(K_HOST, hostname).apply()
    }

    /** Build the live resolver from what is stored right now. */
    fun resolver(ctx: Context): UpstreamResolver = when (mode(ctx)) {
        UpstreamResolver.Mode.DOT -> UpstreamResolver.dot(ip(ctx), hostname(ctx))
        UpstreamResolver.Mode.DOH -> UpstreamResolver.doh(ip(ctx), hostname(ctx), dohPath(ctx))
        UpstreamResolver.Mode.PLAINTEXT -> UpstreamResolver.plaintext(ip(ctx))
    }

    /** One line describing the configured upstream, for the home + DNS screens. */
    fun describe(ctx: Context): String = resolver(ctx).describe()
}
