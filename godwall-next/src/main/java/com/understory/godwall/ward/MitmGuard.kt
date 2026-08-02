package com.understory.godwall.ward

import java.security.KeyStore

/**
 * The MITM alert on the health banner.
 *
 * ## The donor's mechanism
 *
 * RethinkDNS raises a "MITM" notice when the device trusts a certificate authority the user (or
 * an MDM, or an interception proxy) installed, because that is the practical way TLS is read on
 * Android without root. The check is a walk of `AndroidCAStore`: aliases are prefixed `system:`
 * for the ROM's roots and `user:` for anything added afterwards. Counting the `user:` aliases is
 * the whole detection, and it needs no permission.
 *
 * That is reproduced exactly. What is deliberately NOT reproduced is any claim about who added
 * them or what they are doing — the alert states the fact and its consequence, and stops.
 *
 * Note the real-world caveat the copy carries: since Android 7 an app only trusts user CAs if its
 * own network security config opts in. Godwall itself never does (`network_security_config.xml`),
 * so this is a warning about *other* apps on the device, not about Godwall's own upstream.
 */
object MitmGuard {

    private const val USER_ALIAS_PREFIX = "user:"

    data class Result(val userCaCount: Int, val aliases: List<String>) {
        val clean: Boolean get() = userCaCount == 0
    }

    /** Walk the trust store. Blocking I/O on first load — call off the main thread. */
    fun scan(): Result = runCatching {
        val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null, null) }
        val user = java.util.Collections.list(ks.aliases())
            .filter { it.startsWith(USER_ALIAS_PREFIX) }
        Result(user.size, user)
    }.getOrElse { Result(0, emptyList()) }
}
