package com.understory.godwall.chain

import org.json.JSONObject

/**
 * One hop of Godwall's egress chain.
 *
 * There are exactly THREE hop types, and every one of them has a working
 * transport in this module: [Socks5] (RFC 1928/1929, [Socks5Client]),
 * [HttpConnect] (RFC 7231 CONNECT, [HttpConnectClient]) and [Direct] (the
 * chain terminator). The previous build offered WireGuard, Shadowsocks, Tor
 * and "Container" hops in the add-hop UI with no implementation behind any of
 * them; those are gone. A hop type you can pick is a hop type that carries
 * traffic.
 */
sealed interface ProxyHop {

    /** Stable per-hop id, so reorder/remove are unambiguous. */
    val id: String

    /** Short human label for the chain UI. */
    fun label(): String

    fun toJson(): JSONObject

    data class Socks5(
        override val id: String,
        val host: String,
        val port: Int,
        val username: String = "",
        val password: String = "",
    ) : ProxyHop {
        override fun label() = "SOCKS5 $host:$port"
        override fun toJson(): JSONObject = base(id, "socks5")
            .put("host", host).put("port", port)
            .put("username", username).put("password", password)
    }

    data class HttpConnect(
        override val id: String,
        val host: String,
        val port: Int,
        val username: String = "",
        val password: String = "",
    ) : ProxyHop {
        override fun label() = "HTTP CONNECT $host:$port"
        override fun toJson(): JSONObject = base(id, "http")
            .put("host", host).put("port", port)
            .put("username", username).put("password", password)
    }

    /** Egress leaves the chain here; hops after it are unreachable. */
    data class Direct(override val id: String) : ProxyHop {
        override fun label() = "Direct egress"
        override fun toJson(): JSONObject = base(id, "direct")
    }

    companion object {
        private fun base(id: String, type: String): JSONObject =
            JSONObject().put("type", type).put("id", id)

        fun fromJson(o: JSONObject): ProxyHop? {
            val id = o.optString("id").ifBlank { return null }
            return when (o.optString("type")) {
                "socks5" -> Socks5(
                    id, o.optString("host"), o.optInt("port"),
                    o.optString("username"), o.optString("password"),
                )
                "http" -> HttpConnect(
                    id, o.optString("host"), o.optInt("port"),
                    o.optString("username"), o.optString("password"),
                )
                "direct" -> Direct(id)
                else -> null
            }
        }
    }
}
