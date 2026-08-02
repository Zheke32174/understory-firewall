package com.understory.godwall.lan

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.understory.godwall.core.EngineState

/**
 * "Where am I, and how much should I trust it?" — captive-portal and hostile-network posture,
 * read entirely from platform APIs that need no permission and no privilege.
 *
 * ## What this can honestly report, and what it deliberately does not
 *
 * The donors' network-posture logic (RethinkDNS's connection-tracker banner, NetGuard's metered
 * handling) reduces to a handful of facts Android already publishes about the active network, and
 * every one is readable from an ordinary app process:
 *
 *  - transport ([NetworkCapabilities.TRANSPORT_WIFI] / cellular / ethernet / vpn),
 *  - validated ([NetworkCapabilities.NET_CAPABILITY_VALIDATED] — did Android's own probe reach the
 *    internet through this network),
 *  - captive portal ([NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL] — a sign-in wall is in
 *    the way),
 *  - metered ([NetworkCapabilities.NET_CAPABILITY_NOT_METERED] absent).
 *
 * What is deliberately NOT here: the SSID/BSSID, and whether the Wi-Fi link is open/unencrypted.
 * Both need `ACCESS_FINE_LOCATION` since Android 10, and a firewall taking the location permission
 * to name the network or grade its cipher would be a worse trade than the signal is worth. That
 * boundary is reported honestly as a gated capability on the LAN screen rather than guessed at
 * here — a posture card that never actually inspects the link must not imply that it does.
 *
 * ## Why "not validated" is a signal and not an error
 *
 * A network Android has not validated is either still coming up, behind a captive portal, or
 * actively broken/hostile — this bit alone cannot tell which, so the fact is reported ("Android
 * has not confirmed this network reaches the internet") and the captive-portal bit plus the user's
 * own context disambiguate. Reporting it as "safe" because a page loaded would be exactly the
 * inference this file exists to avoid.
 */
object NetworkPosture {

    enum class Transport { WIFI, CELLULAR, ETHERNET, VPN, OTHER, NONE }

    /**
     * A pure snapshot of the active network's trust-relevant facts, plus whether Godwall is
     * holding the VPN slot (which changes what an unvalidated or captive network can reach).
     */
    data class Posture(
        val transport: Transport,
        val validated: Boolean,
        val captivePortal: Boolean,
        val metered: Boolean,
        val hasNetwork: Boolean,
        val godwallArmed: Boolean,
    ) {
        /**
         * The findings, worst-first, as machine-readable kinds the UI maps to copy. Empty means
         * "nothing notable" — the UI says that in words rather than showing a blank, because an
         * empty posture card reads as a failure to load.
         */
        val findings: List<Finding> get() = buildList {
            if (!hasNetwork) {
                add(Finding.NO_NETWORK)
                return@buildList
            }
            if (captivePortal) add(Finding.CAPTIVE_PORTAL)
            if (!validated) add(Finding.NOT_VALIDATED)
            if (metered && transport == Transport.WIFI) add(Finding.METERED_WIFI)
        }

        /** True when at least one finding warrants caution — drives the card's tint. A metered
         *  Wi-Fi note is informational and does not, on its own, count as guarded. */
        val guarded: Boolean get() = findings.any { it != Finding.METERED_WIFI }
    }

    enum class Finding { NO_NETWORK, CAPTIVE_PORTAL, NOT_VALIDATED, METERED_WIFI }

    /**
     * Build a [Posture] from raw capability facts. Pure, so the finding logic is testable without
     * a device or a live network.
     */
    fun classify(
        transport: Transport,
        validated: Boolean,
        captivePortal: Boolean,
        metered: Boolean,
        hasNetwork: Boolean,
        godwallArmed: Boolean,
    ): Posture = Posture(
        transport = transport,
        validated = validated,
        captivePortal = captivePortal,
        metered = metered,
        hasNetwork = hasNetwork,
        godwallArmed = godwallArmed,
    )

    /**
     * Read the active network's posture from the platform. Touches [ConnectivityManager]; call off
     * the main thread with the rest of the LAN refresh.
     *
     * A device that returns null capabilities (no active network, or a transient during a network
     * switch) yields a `hasNetwork = false` posture rather than a thrown exception, so the caller
     * always gets an answer.
     */
    fun read(ctx: Context): Posture {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val net = cm?.activeNetwork
        val caps = net?.let { cm.getNetworkCapabilities(it) }
        if (caps == null) {
            return classify(
                transport = Transport.NONE,
                validated = false,
                captivePortal = false,
                metered = false,
                hasNetwork = false,
                godwallArmed = EngineState.armed,
            )
        }
        val transport = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Transport.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Transport.CELLULAR
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Transport.ETHERNET
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> Transport.VPN
            else -> Transport.OTHER
        }
        return classify(
            transport = transport,
            validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            captivePortal = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            hasNetwork = true,
            godwallArmed = EngineState.armed,
        )
    }
}
