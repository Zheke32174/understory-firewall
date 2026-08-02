package com.understory.godwall.subsystem.tor

/**
 * Tor bridge configuration — obfs4 / meek / snowflake / vanilla — and the honest
 * gate in front of it.
 *
 * ## Why bridges are gated separately from tor itself
 *
 * A bridge that uses a pluggable transport (obfs4, meek, snowflake) needs a
 * SECOND binary beside tor: `obfs4proxy` (which provides both `obfs4` and
 * `meek_lite`) or `snowflake-client`. Those are their own per-ABI payloads
 * (docs/DONOR-ASSETS.md), absent by default. Telling tor `ClientTransportPlugin
 * obfs4 exec …/obfs4proxy` when that file is not there makes tor log an error and
 * fail the bridge — a dead control wearing an enabled face. So this object emits a
 * transport's lines ONLY when [Presence] says its binary is installed. When it is
 * not, the bridge surface reports absent and names the missing binary.
 *
 * ## Which transports need which binary
 *
 * - `obfs4`, `meek_lite`  → `usr/bin/obfs4proxy`
 * - `snowflake`           → `usr/bin/snowflake-client`
 * - `vanilla` (plain IP bridges, no PT) → needs no extra binary; tor speaks it itself.
 *
 * Pure functions of their inputs — no I/O, no Context. [Anonymity] probes the APK
 * for the transport binaries and hands the result in as [Presence]; the renderer
 * stays testable off-device.
 */
object TorBridges {

    /** The transport a bridge set uses. Mirrors InviZible's obfuscation-type selection. */
    enum class Transport {
        /** Bridges are off; tor connects directly. */
        NONE,

        /** Plain, un-obfuscated bridges — an IP:port + fingerprint, no PT binary. */
        VANILLA,

        /** obfs4 — the default obfuscation, from bridges.torproject.org. Needs obfs4proxy. */
        OBFS4,

        /** meek (domain-fronted via meek_lite). Needs obfs4proxy. */
        MEEK_LITE,

        /** Snowflake (WebRTC via a broker). Needs snowflake-client. */
        SNOWFLAKE,
    }

    /** Which pluggable-transport binaries are actually installed in the prefix. */
    data class Presence(val obfs4proxy: Boolean, val snowflakeClient: Boolean) {
        fun supports(t: Transport): Boolean = when (t) {
            Transport.NONE, Transport.VANILLA -> true
            Transport.OBFS4, Transport.MEEK_LITE -> obfs4proxy
            Transport.SNOWFLAKE -> snowflakeClient
        }
    }

    /** Prefix-relative path of the PT binary a transport needs, or null when it needs none. */
    fun ptBinary(t: Transport): String? = when (t) {
        Transport.OBFS4, Transport.MEEK_LITE -> "usr/bin/obfs4proxy"
        Transport.SNOWFLAKE -> "usr/bin/snowflake-client"
        Transport.NONE, Transport.VANILLA -> null
    }

    /**
     * The torrc lines for the active bridge set, or empty when bridges are off, the
     * transport's binary is absent, or no bridge lines are available. The caller
     * prepends `UseBridges 1` only when this is non-empty.
     *
     * @param transport the selected obfuscation.
     * @param ownLines the user's own `Bridge …` lines (InviZible "Use Bridges Own
     *   List"). For [Transport.OBFS4] and [Transport.VANILLA] these are required —
     *   obfs4 bridges are handed out per-request and cannot be shipped.
     * @param presence which PT binaries are installed.
     * @param prefix the absolute prefix root, for the ClientTransportPlugin exec path.
     */
    fun renderTorrcLines(
        transport: Transport,
        ownLines: List<String>,
        presence: Presence,
        prefix: String,
    ): List<String> {
        if (transport == Transport.NONE) return emptyList()
        if (!presence.supports(transport)) return emptyList()

        val bridges = bridgeLinesFor(transport, ownLines)
        if (bridges.isEmpty()) return emptyList()

        val out = ArrayList<String>(bridges.size + 1)
        when (transport) {
            Transport.OBFS4 ->
                out += "ClientTransportPlugin obfs4 exec $prefix/usr/bin/obfs4proxy"
            Transport.MEEK_LITE ->
                out += "ClientTransportPlugin meek_lite exec $prefix/usr/bin/obfs4proxy"
            Transport.SNOWFLAKE ->
                out += "ClientTransportPlugin snowflake exec $prefix/usr/bin/snowflake-client"
            Transport.VANILLA, Transport.NONE -> Unit
        }
        out += bridges
        return out
    }

    /** The bridge lines to use: the user's own if present, else a built-in default. */
    private fun bridgeLinesFor(transport: Transport, ownLines: List<String>): List<String> {
        val own = ownLines.map { it.trim() }.filter { it.isNotEmpty() }
        if (own.isNotEmpty()) return own.map { normalize(it) }
        return when (transport) {
            // obfs4 and vanilla bridges are per-user secrets from bridges.torproject.org;
            // there is nothing honest to ship as a default. The surface asks for own lines.
            Transport.OBFS4, Transport.VANILLA -> emptyList()
            Transport.MEEK_LITE -> MEEK_AZURE_DEFAULT
            Transport.SNOWFLAKE -> SNOWFLAKE_DEFAULT
            Transport.NONE -> emptyList()
        }
    }

    /** Ensure a user-pasted line begins with the `Bridge` keyword tor expects. */
    private fun normalize(line: String): String =
        if (line.startsWith("Bridge ", ignoreCase = true)) line else "Bridge $line"

    /**
     * Snowflake's long-standing built-in relay line (as shipped by Tor Browser).
     * Snowflake reaches a broker rather than a fixed relay, so this line changes
     * rarely; if it stops working the user supplies their own via the own-list flow.
     */
    val SNOWFLAKE_DEFAULT: List<String> = listOf(
        "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 " +
            "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 " +
            "url=https://1098762253.rsc.cdn77.org/ " +
            "fronts=www.cdn77.com,www.phpmyadmin.net " +
            "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478 " +
            "utls-imitate=hellorandomizedalpn",
    )

    /**
     * meek-azure built-in line. Domain-fronting fronts rotate as CDNs change their
     * terms, so this is best-effort; the own-list flow replaces it when it drifts.
     */
    val MEEK_AZURE_DEFAULT: List<String> = listOf(
        "Bridge meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 " +
            "url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
    )
}
