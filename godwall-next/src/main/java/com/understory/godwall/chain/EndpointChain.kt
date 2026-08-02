package com.understory.godwall.chain

import android.content.Context
import org.json.JSONArray

/**
 * The ordered egress chain. Order IS the route: hop0 is entered first and the
 * last hop egresses, so add / remove / move are the whole API. Persisted as a
 * JSON array of [ProxyHop].
 *
 * Storing a chain does not establish one — [ChainDialer] does that, per
 * connection, and refuses rather than partially establishing.
 */
object EndpointChain {

    private const val PREF = "godwall_chain"
    private const val K_HOPS = "hops_json"
    private const val K_ENABLED = "enabled"

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun isEnabled(ctx: Context): Boolean = p(ctx).getBoolean(K_ENABLED, false)

    fun setEnabled(ctx: Context, on: Boolean) {
        p(ctx).edit().putBoolean(K_ENABLED, on).apply()
    }

    fun hops(ctx: Context): List<ProxyHop> {
        val raw = p(ctx).getString(K_HOPS, "").orEmpty()
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

    /** Move the hop at [from] to index [to]. Out-of-range indices are ignored. */
    fun move(ctx: Context, from: Int, to: Int) {
        val list = hops(ctx).toMutableList()
        if (from !in list.indices || to !in list.indices) return
        list.add(to, list.removeAt(from))
        setHops(ctx, list)
    }

    /** A fresh id for a new hop. */
    fun newId(): String = "hop-" + java.util.UUID.randomUUID().toString().take(8)

    fun describe(ctx: Context): String {
        val hs = hops(ctx)
        if (hs.isEmpty()) return "Direct egress (no hops)"
        return "Godwall → " + hs.joinToString(" → ") { it.label() } + " → internet"
    }
}
