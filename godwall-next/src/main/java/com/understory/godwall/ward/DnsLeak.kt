package com.understory.godwall.ward

import android.content.Context
import android.net.ConnectivityManager
import com.understory.godwall.core.AppPolicy
import com.understory.godwall.core.EngineState
import com.understory.godwall.core.GodwallVpnService

/**
 * The "leaks OK / FAIL" line on the DNS status card.
 *
 * ## What a leak test can honestly be, on-device
 *
 * The donors' leak tests are two different things wearing one name. RethinkDNS's
 * "prevent DNS leaks" checks that port 53 is actually being captured; InviZible's checks that the
 * system resolver is the local one rather than the network's. Neither can be answered by asking a
 * website what resolver it saw — that tells you about the *upstream*, not about whether this
 * device's apps are reaching it.
 *
 * So the check here is the local one, and it is a fact rather than an inference: while Godwall
 * holds the slot, the active network's `LinkProperties` must list Godwall's own resolver address
 * and nothing else. If another address is listed, some lookups are going somewhere Godwall does
 * not see, and that is exactly what "leak" should mean.
 *
 * Apps excluded from the tunnel are counted separately and reported as a **deliberate** leak.
 * They are excluded because the user asked; calling that a failure would train the user to
 * ignore the indicator, and calling it "OK" without saying so would be a lie of omission.
 */
object DnsLeak {

    enum class Verdict {
        /** Every resolver the platform advertises is ours. */
        OK,

        /** Godwall is holding the slot and something else is still resolving. */
        LEAK,

        /** Not armed — there is nothing to leak from. */
        NOT_ARMED,

        /** The platform did not tell us. Never reported as OK. */
        UNKNOWN,
    }

    data class Result(
        val verdict: Verdict,
        val detail: String,
        val servers: List<String>,
        val excludedApps: Int,
    ) {
        val ok: Boolean get() = verdict == Verdict.OK
    }

    /**
     * The rule, pure so it is testable without a device.
     *
     * @param servers the DNS server addresses the active network advertises.
     * @param expected Godwall's own resolver address inside the tun.
     * @param excludedApps how many apps the user removed from the tunnel.
     */
    fun classify(
        armed: Boolean,
        servers: List<String>,
        expected: String,
        excludedApps: Int,
    ): Result {
        if (!armed) {
            return Result(
                Verdict.NOT_ARMED,
                "Godwall is not holding the VPN slot, so every lookup on this device uses the " +
                    "network's own resolver.",
                servers,
                excludedApps,
            )
        }
        if (servers.isEmpty()) {
            return Result(
                Verdict.UNKNOWN,
                "Android did not report any resolver for the active network, so this could not " +
                    "be checked.",
                servers,
                excludedApps,
            )
        }
        val foreign = servers.filter { it != expected }
        return if (foreign.isEmpty()) {
            val note = if (excludedApps > 0) {
                " $excludedApps app(s) you excluded from the tunnel resolve outside it by design."
            } else {
                ""
            }
            Result(Verdict.OK, "Every resolver on the active network is Godwall's ($expected).$note", servers, excludedApps)
        } else {
            Result(
                Verdict.LEAK,
                "The active network still advertises ${foreign.joinToString(", ")}. Lookups sent " +
                    "there are not filtered or encrypted by Godwall.",
                servers,
                excludedApps,
            )
        }
    }

    /**
     * Read the platform and classify. Touches [ConnectivityManager]; call off the main thread
     * with the rest of the status refresh.
     */
    fun check(ctx: Context): Result {
        val servers = runCatching {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            val net = cm?.activeNetwork
            cm?.getLinkProperties(net)?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList()
        }.getOrDefault(emptyList())
        return classify(
            armed = EngineState.armed,
            servers = servers,
            expected = GodwallVpnService.DNS_ADDR,
            excludedApps = runCatching { AppPolicy.bypassed(ctx).size }.getOrDefault(0),
        )
    }
}
