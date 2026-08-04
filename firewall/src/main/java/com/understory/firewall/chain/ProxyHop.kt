package com.understory.firewall.chain

import org.json.JSONObject

/** Base JSON for a hop (type + id); shared by every [ProxyHop.toJson]. */
private fun hopBase(id: String, type: String): JSONObject =
    JSONObject().put("type", type).put("id", id)

/**
 * One hop in Godwall's egress [EndpointChain]. Traffic leaving the firewall tun
 * is handed to the FIRST hop, which forwards to the next, and so on, until the
 * LAST hop egresses to the internet — a multi-hop proxy chain with heterogeneous
 * link types. Tailscale is one hop type ([Tailscale]): Godwall joins the tailnet
 * as a real node, then the chain can HOP ONWARD from the tailnet into other proxy
 * types. This is the "node + endpoint chain" model: be a mesh member and a
 * chainable egress orchestrator at once.
 *
 * Each hop declares which backend establishes it. Backends are seams
 * ([ProxyChainController]); a hop with no linked backend is stored and shown
 * honestly but does not carry traffic until its backend lands. Nothing here
 * fabricates a live link.
 */
sealed interface ProxyHop {
    /** Stable per-hop id so the chain can reorder/remove without ambiguity. */
    val id: String

    /** Short human label for the chain UI. */
    fun label(): String

    /** Backend family that would establish this hop. */
    fun backend(): Backend

    fun toJson(): JSONObject

    enum class Backend {
        /** Tailscale Go data plane (libtailscale) — mesh membership + optional exit node. */
        TAILSCALE,
        /** Userspace SOCKS5 client — implementable natively in-tunnel later. */
        SOCKS5,
        /** Userspace HTTP CONNECT client — implementable natively in-tunnel later. */
        HTTP_CONNECT,
        /** Userspace WireGuard (wireguard-go / kernel) — a raw WG hop, distinct from Tailscale. */
        WIREGUARD,
        /** Shadowsocks client. */
        SHADOWSOCKS,
        /** Tor SOCKS (via Orbot or an external tor). */
        TOR,
        /** I2P SOCKS/HTTP (via the I2P router app or i2pd). */
        I2P,
        /**
         * A hop served INSIDE a container server (an nspawn/stratum/proot container
         * on-device, or one exposed by a sibling app). The relay process runs in the
         * container; Godwall forwards into it. This is part of going beyond a normal
         * userspace Android VPN — the container can run a full proxy/routing stack.
         */
        CONTAINER,
        /** No proxy — egress directly from this point (chain terminator). */
        DIRECT,
    }

    /**
     * How a hop is established at the OS level. A normal Android VPN app is stuck at
     * [USERSPACE] (VpnService + in-process sockets). With the privilege brokers the
     * suite already ships (Yojimbo's Shizuku/root shell), a hop can instead be armed
     * at [KERNEL] level — real routing via network namespaces / nftables / policy
     * routing — or delegated to a [CONTAINER] server. Higher tiers degrade honestly
     * to USERSPACE when the privilege/container backend is absent.
     */
    enum class Transport { USERSPACE, KERNEL, CONTAINER }

    /**
     * Preferred establishment transport for this hop. Default USERSPACE so nothing
     * assumes privilege it doesn't have; a hop can request KERNEL/CONTAINER and the
     * controller reports honestly whether that tier is actually available.
     */
    fun transport(): Transport = Transport.USERSPACE

    /**
     * Join the tailnet as a node and (optionally) egress via [exitNode]. When this
     * hop is NOT last, the chain continues from the tailnet into the next hop —
     * "link Tailscale, then hop onward".
     */
    data class Tailscale(override val id: String, val exitNode: String = "") : ProxyHop {
        override fun label() = if (exitNode.isBlank()) "Tailscale (node)" else "Tailscale → $exitNode"
        override fun backend() = Backend.TAILSCALE
        override fun toJson() = hopBase(id, "tailscale").put("exitNode", exitNode)
    }

    data class Socks5(
        override val id: String,
        val host: String,
        val port: Int,
        val username: String = "",
        val password: String = "",
    ) : ProxyHop {
        override fun label() = "SOCKS5 $host:$port"
        override fun backend() = Backend.SOCKS5
        override fun toJson() = hopBase(id, "socks5")
            .put("host", host).put("port", port).put("username", username).put("password", password)
    }

    data class HttpConnect(
        override val id: String,
        val host: String,
        val port: Int,
        val username: String = "",
        val password: String = "",
    ) : ProxyHop {
        override fun label() = "HTTP $host:$port"
        override fun backend() = Backend.HTTP_CONNECT
        override fun toJson() = hopBase(id, "http")
            .put("host", host).put("port", port).put("username", username).put("password", password)
    }

    data class Wireguard(
        override val id: String,
        val name: String,
        val endpoint: String,
        val publicKey: String,
    ) : ProxyHop {
        override fun label() = "WireGuard ${name.ifBlank { endpoint }}"
        override fun backend() = Backend.WIREGUARD
        override fun toJson() = hopBase(id, "wireguard")
            .put("name", name).put("endpoint", endpoint).put("publicKey", publicKey)
    }

    data class Shadowsocks(
        override val id: String,
        val host: String,
        val port: Int,
        val method: String,
        val password: String,
    ) : ProxyHop {
        override fun label() = "Shadowsocks $host:$port"
        override fun backend() = Backend.SHADOWSOCKS
        override fun toJson() = hopBase(id, "shadowsocks")
            .put("host", host).put("port", port).put("method", method).put("password", password)
    }

    data class Tor(override val id: String) : ProxyHop {
        override fun label() = "Tor"
        override fun backend() = Backend.TOR
        override fun toJson() = hopBase(id, "tor")
    }

    /** I2P egress via the I2P router / i2pd SOCKS proxy (default 127.0.0.1:4447). */
    data class I2p(override val id: String) : ProxyHop {
        override fun label() = "I2P"
        override fun backend() = Backend.I2P
        override fun toJson() = hopBase(id, "i2p")
    }

    /**
     * A relay running inside a container server [container] (e.g. a stratum name),
     * forwarding to [innerTarget] ("host:port" the in-container relay listens on, or
     * a named upstream). Establishes at container transport — the defensive step
     * beyond a userspace VPN.
     */
    data class Container(
        override val id: String,
        val container: String,
        val innerTarget: String = "",
    ) : ProxyHop {
        override fun label() = "Container $container" + if (innerTarget.isBlank()) "" else " → $innerTarget"
        override fun backend() = Backend.CONTAINER
        override fun transport() = Transport.CONTAINER
        override fun toJson() = hopBase(id, "container").put("container", container).put("innerTarget", innerTarget)
    }

    data class Direct(override val id: String) : ProxyHop {
        override fun label() = "Direct egress"
        override fun backend() = Backend.DIRECT
        override fun toJson() = hopBase(id, "direct")
    }

    companion object {
        fun fromJson(o: JSONObject): ProxyHop? {
            val id = o.optString("id").ifBlank { return null }
            return when (o.optString("type")) {
                "tailscale" -> Tailscale(id, o.optString("exitNode"))
                "socks5" -> Socks5(id, o.optString("host"), o.optInt("port"), o.optString("username"), o.optString("password"))
                "http" -> HttpConnect(id, o.optString("host"), o.optInt("port"), o.optString("username"), o.optString("password"))
                "wireguard" -> Wireguard(id, o.optString("name"), o.optString("endpoint"), o.optString("publicKey"))
                "shadowsocks" -> Shadowsocks(id, o.optString("host"), o.optInt("port"), o.optString("method"), o.optString("password"))
                "tor" -> Tor(id)
                "i2p" -> I2p(id)
                "container" -> Container(id, o.optString("container"), o.optString("innerTarget"))
                "direct" -> Direct(id)
                else -> null
            }
        }
    }
}
