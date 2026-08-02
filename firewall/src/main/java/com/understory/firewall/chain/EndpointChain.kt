package com.understory.firewall.chain

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * The ordered egress chain: `[hop0, hop1, … hopN]`. Traffic off the firewall tun
 * enters hop0 and is forwarded hop-to-hop until the last hop egresses. Persisted
 * as a JSON array of [ProxyHop] in prefs. Order IS the route, so add/remove/move
 * are first-class.
 *
 * A well-formed chain is validated by [ProxyChainController]; storing a chain does
 * NOT establish it. An empty chain means "direct egress" (today's behavior).
 */
object EndpointChain {
    private const val PREF = "firewall_chain"
    private const val K_HOPS = "chain_hops_json"
    private const val K_ENABLED = "chain_enabled"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    /** Whether the chain should be applied to egress (vs direct). */
    fun isEnabled(ctx: Context): Boolean = p(ctx).getBoolean(K_ENABLED, false)
    fun setEnabled(ctx: Context, on: Boolean) = p(ctx).edit().putBoolean(K_ENABLED, on).apply()

    fun hops(ctx: Context): List<ProxyHop> {
        val raw = p(ctx).getString(K_HOPS, "") ?: ""
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull { ProxyHop.fromJson(arr.getJSONObject(it)) }
        }.getOrDefault(emptyList())
    }

    fun setHops(ctx: Context, hops: List<ProxyHop>) {
        val arr = JSONArray()
        hops.forEach { arr.put(it.toJson()) }
        p(ctx).edit().putString(K_HOPS, arr.toString()).apply()
    }

    fun add(ctx: Context, hop: ProxyHop) = setHops(ctx, hops(ctx) + hop)

    fun remove(ctx: Context, id: String) = setHops(ctx, hops(ctx).filterNot { it.id == id })

    /** Move the hop at [from] to [to] (chain order is the route). */
    fun move(ctx: Context, from: Int, to: Int) {
        val list = hops(ctx).toMutableList()
        if (from !in list.indices || to !in list.indices) return
        list.add(to, list.removeAt(from))
        setHops(ctx, list)
    }

    /** A fresh unique-ish id for a new hop (time-free: caller supplies a seed). */
    fun newId(seed: String): String = "hop-${seed.hashCode().toUInt().toString(16)}"

    fun describe(ctx: Context): String {
        val hs = hops(ctx)
        if (hs.isEmpty()) return "Direct egress (no chain)"
        return "tun → " + hs.joinToString(" → ") { it.label() } + " → internet"
    }

    fun toJsonString(ctx: Context): String =
        JSONObject().put("enabled", isEnabled(ctx)).put("hops", JSONArray(hops(ctx).map { it.toJson() })).toString()
}
