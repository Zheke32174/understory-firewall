package com.understory.godwall.subsystem.dns

import com.understory.godwall.subsystem.ServiceConfigFile
import com.understory.godwall.subsystem.ServiceHealthProbe
import com.understory.godwall.subsystem.ServiceSpec

/**
 * The DNS stack described as data: two daemons that run out of Godwall's own prefix at
 * uid 2000, and the pre-configured files they are seeded with.
 *
 * ## The topology, once
 *
 * ```
 *   Godwall's tun  ->  127.0.0.1:5353  ->  127.0.0.1:5354  ->  encrypted upstream
 *                      dnsmasq             dnscrypt-proxy      (DNSCrypt / DoH / ODoH)
 *                      cache + rebind      DNSSEC + no-log
 *                      guard, no leak      + no-filter floor
 * ```
 *
 * dnsmasq is the front door the tun handler dials. It caches, rejects DNS-rebinding answers,
 * and forwards EVERY query to dnscrypt-proxy. It has no plaintext upstream, so a query it
 * handles cannot silently egress in cleartext — the "fails, does not leak" property. Both are
 * plain socket listeners on loopback, which is why neither needs privilege: loopback is shared
 * across uids, so Godwall's own process (and the tun handler) can dial a daemon running at
 * uid 2000. That is the load-bearing insight of the whole subsystem, stated in [ServiceSpec].
 *
 * ## Why these are the InviZible architecture, not firestack's
 *
 * `docs/FIRESTACK-LINKING.md` notes firestack implements DNSCrypt/ODoH in Go and could answer
 * DNS inside the tun. That is a different consumer of the same tun fd and is wired elsewhere;
 * it is not yet in the build. This package is the native-daemon stack the WP-3 task specifies —
 * dnscrypt-proxy + dnsmasq supervised out of the prefix, exactly InviZible Pro's shape, done
 * natively. The two are alternative DNS engines, never both reading the tun at once.
 *
 * ## Honest gating lives in the foundation, not here
 *
 * The daemon ELFs are payload. A stock Termux bootstrap does not carry dnscrypt-proxy or
 * dnsmasq, and payloads are not committed, so on a clean checkout [ServiceSpec.binary] is not
 * in the prefix and the Supervisor reports the service ABSENT with a sentence — the control
 * stays disabled. Nothing here fakes a backend it does not have; the config files ship (they
 * are cheap text and always present), but a config without its binary is still ABSENT.
 */
internal object DnsServices {

    /** Prefix-relative directory the dnscrypt-proxy config and its cached lists live in. */
    const val DNSCRYPT_ETC = "usr/etc/dnscrypt-proxy"

    /** The port dnsmasq answers on — the front door the tun handler dials. */
    const val PORT_FRONTEND = 5353

    /** The port dnscrypt-proxy answers on — the encrypted upstream dnsmasq forwards to. */
    const val PORT_ENCRYPTED = 5354

    /** Stable service ids, also used as pid/log filenames and as capability backing keys. */
    const val ID_DNSCRYPT = "dnscrypt-proxy"
    const val ID_DNSMASQ = "dnsmasq"

    /**
     * dnscrypt-proxy: the encrypted upstream.
     *
     * Foreground by construction — invoked with `-config <toml>` and no `-service`, so it does
     * not double-fork and the Supervisor supervises the pid it launched (the contract in
     * [ServiceSpec]). Working directory is [DNSCRYPT_ETC] because the toml's `cache_file`
     * entries (public-resolvers.md, relays.md, …) are written relative to the process CWD, and
     * that directory is uid-2000-owned and writable.
     */
    val dnscryptProxy = ServiceSpec(
        id = ID_DNSCRYPT,
        label = "DNSCrypt resolver",
        binary = "usr/bin/dnscrypt-proxy",
        args = listOf(
            "-config",
            "${ServiceSpec.USR_TOKEN}/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
        ),
        workingDir = DNSCRYPT_ETC,
        configs = listOf(
            ServiceConfigFile(
                asset = "subsystem/dnscrypt-proxy.toml",
                destination = "$DNSCRYPT_ETC/dnscrypt-proxy.toml",
            ),
        ),
        health = listOf(
            ServiceHealthProbe.LocalPort(PORT_ENCRYPTED, "encrypted DNS"),
        ),
        reach = "answers name lookups on 127.0.0.1:$PORT_ENCRYPTED over DNSCrypt, DoH and " +
            "ODoH, requiring DNSSEC-validatable, no-log, no-filter resolvers; it serves only " +
            "the queries dnsmasq forwards to it and changes nothing about what other apps use.",
    )

    /**
     * dnsmasq: the caching front door and rebind guard.
     *
     * `--keep-in-foreground` is passed on the command line (not the config file) so it does not
     * daemonise; with it, dnsmasq writes no pid file and stays as the pid the Supervisor tracks.
     * Its single upstream is dnscrypt-proxy, so it never forwards in cleartext.
     */
    val dnsmasq = ServiceSpec(
        id = ID_DNSMASQ,
        label = "Local DNS cache",
        binary = "usr/bin/dnsmasq",
        args = listOf(
            "--keep-in-foreground",
            "--conf-file=${ServiceSpec.USR_TOKEN}/etc/dnsmasq.conf",
        ),
        workingDir = "usr/etc",
        configs = listOf(
            ServiceConfigFile(
                asset = "subsystem/dnsmasq.conf",
                destination = "usr/etc/dnsmasq.conf",
            ),
        ),
        health = listOf(
            ServiceHealthProbe.LocalPort(PORT_FRONTEND, "local cache + rebind guard"),
        ),
        reach = "answers name lookups on 127.0.0.1:$PORT_FRONTEND, caches them, rejects " +
            "rebinding answers that map a public name to a private address, and forwards every " +
            "query to the encrypted resolver on 127.0.0.1:$PORT_ENCRYPTED with no cleartext " +
            "fallback; it front-ends only the traffic Godwall's tun hands it.",
    )

    /** Both specs, in start order: the encrypted upstream first, then the front-end that needs it. */
    val all: List<ServiceSpec> = listOf(dnscryptProxy, dnsmasq)
}
