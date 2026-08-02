package com.understory.godwall.subsystem

import android.content.Context
import android.os.Build
import com.understory.security.Diagnostics
import java.io.IOException

/**
 * Godwall's OWN Termux-style userland — described here, not delegated to.
 *
 * ## The invariant this file exists to hold
 *
 * Masamune's Shell screen delegates to an *installed* Termux over
 * `com.termux.RUN_COMMAND` and shows a blocked empty state when Termux isn't
 * present — that is a documented, deliberate boundary for that app (see
 * `tools/donor-assets/fetch.sh fetch_termux_bootstrap`). Godwall does NOT do
 * that. Godwall bundles its own patched copy of the Termux prefix as an app
 * asset and runs it itself. The whole point of a Linux subsystem inside a
 * security suite is that dnscrypt-proxy, dnsmasq, tor, i2pd, sing-box and
 * v2ray need somewhere to run *unprivileged, per-app-isolated, and without
 * asking another app to host them* — reaching for an installed Termux would
 * be exactly the "has to ask the thing it replaces" failure this campaign
 * exists to correct.
 *
 * ## Where it lives, and why
 *
 * [PREFIX] is `/data/local/tmp/godwall/usr` — NOT the app's private data
 * dir. Since API 29, an app's own data directory is effectively noexec for
 * files the app itself wrote there (the W^X hardening: a file this process
 * created cannot also be mapped executable by this process). A binary
 * extracted into `/data/data/com.understory.firewall/...` therefore cannot
 * be exec'd at all, full stop, regardless of privilege. `/data/local/tmp` is
 * the writable-AND-executable path on stock Android, and it is owned by
 * **uid 2000 (shell)** — which is exactly the identity Yojimbo's privileged
 * shell already runs as. That is not a coincidence this file invented; it is
 * why WP-2's prefix installer asks Yojimbo to do the extraction rather than
 * writing the prefix itself as the app's own uid.
 *
 * Not proot: exec'ing directly as uid 2000 out of an exec-friendly prefix
 * has no ptrace interposition overhead and is what this suite ships, on the
 * strength of the same reasoning that makes tailscaled work unprivileged —
 * a socket listener or dialer needs no root. tor, i2pd, dnscrypt-proxy,
 * dnsmasq, v2ray, sing-box and shadowsocks are all that same shape: they
 * bind loopback and get dialled into. Rewriting the *kernel's* netfilter
 * tables or reaching into other apps' processes is a different, higher
 * privilege tier and is gated honestly elsewhere (see `subsystem/privileged`
 * doc references) — this file is only about standing up the userland that
 * needs socket-space privilege, which uid 2000 already grants.
 *
 * ## Why every binary needs surgery first
 *
 * A stock Termux bootstrap is linked against
 * `/data/data/com.termux/files/usr` ([UPSTREAM_PREFIX]) — that string is
 * baked into every executable's `PT_INTERP` (its dynamic loader path) and
 * every ELF's `DT_RUNPATH`/`DT_RPATH` (its library search path), because
 * that is the prefix Termux's own toolchain was configured with at build
 * time. Installing those bytes at a different path changes nothing about
 * what's written *inside* them — the loader still goes looking in
 * `/data/data/com.termux/...`, finds nothing there (this is Godwall, not
 * Termux, and that path is either absent or someone else's app-private
 * directory), and the exec fails. `tools/donor-assets/elf-repatch.py`
 * rewrites those two fields, in place, in every ELF in the bootstrap, before
 * it is ever packaged as an app asset — see that script's module docstring
 * for exactly how (program-header-driven, so it works even on binaries
 * stripped of section headers, and it never grows a string past its
 * original byte budget). `tools/donor-assets/bootstrap.sh` drives the whole
 * fetch → extract → repatch → repackage pipeline and drops the result at
 * the asset path [assetPath] resolves.
 *
 * ## What this object actually does
 *
 * Nothing privileged. This is the read side only: it knows the two prefix
 * constants, knows which per-ABI asset the APK is expected to carry, and
 * reports [State.LINKED] or [State.ABSENT] by checking whether that asset
 * is actually present for *this* device's ABI — never assumed, always
 * probed via [Context.getAssets]. Extracting the asset onto
 * `/data/local/tmp` as uid 2000 through Yojimbo, and supervising the
 * daemons that then run out of it, are separate concerns with their own
 * files (prefix installation + service supervision) — this object is the
 * thing they both read to find out what, if anything, is there to install.
 */
object Bootstrap {

    private const val TAG = "godwall.subsystem.Bootstrap"

    /**
     * What upstream Termux hardcodes at link time. Every asset this object
     * reports [State.LINKED] for has had every occurrence of this string,
     * in every ELF's `PT_INTERP`/`DT_RUNPATH`/`DT_RPATH`, rewritten to
     * [PREFIX] by `tools/donor-assets/elf-repatch.py`. Kept here — not just
     * in the shell script — because anything that reasons about "did this
     * binary actually get repatched" needs the same string the patcher used.
     */
    const val UPSTREAM_PREFIX = "/data/data/com.termux/files/usr"

    /**
     * Godwall's own prefix, post-repatch. Every `PT_INTERP`/`DT_RUNPATH`
     * value in the bundled bootstrap points here. MUST match `NEW_PREFIX` in
     * `tools/donor-assets/bootstrap.sh` — the two are declared separately
     * because a shell script and a Kotlin object cannot share a build-time
     * constant across that boundary; `docs/LINUX-SUBSYSTEM.md` is the
     * tie-breaker if they are ever found to disagree.
     */
    const val PREFIX = "/data/local/tmp/godwall/usr"

    /** The prefix's parent — where WP-2's installer creates `usr/`, plus any per-service run/log/var dirs, as uid 2000. */
    const val INSTALL_ROOT = "/data/local/tmp/godwall"

    /**
     * Android ABI tokens this object will look for an asset under. Mirrors
     * `all_abis()` in `tools/donor-assets/bootstrap.sh`. Order does not
     * imply preference; [primaryAbi] picks from [Build.SUPPORTED_ABIS]
     * instead, which IS ordered by the platform's own preference.
     */
    val SUPPORTED_ABIS: List<String> = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

    /** What the UI renders. One sentence per state — see [explain]. */
    enum class State {
        /** A repatched bootstrap asset exists in this APK for this device's ABI. */
        LINKED,

        /** No asset for any ABI this device can run. Nothing is bundled; nothing pretends to be. */
        ABSENT,
    }

    /** What's actually bundled for one ABI, read off the asset itself — never a hardcoded guess. */
    data class Manifest(
        val abi: String,
        val assetPath: String,
        val sizeBytes: Long,
    )

    /**
     * Where the per-ABI patched bootstrap lives inside `assets/`. MUST match
     * `$ASSET_DIR/<abi>.zip` in `tools/donor-assets/bootstrap.sh` — that
     * script is the only thing that writes to this path, and this function
     * is the only thing that reads its name back.
     */
    fun assetPath(abi: String): String = "subsystem/bootstrap/$abi.zip"

    /**
     * The first of this device's [Build.SUPPORTED_ABIS] that Godwall ships a
     * bootstrap for, in the PLATFORM's preference order — not ours. Null if
     * this device's ABI list has no overlap with [SUPPORTED_ABIS] at all
     * (e.g. a `riscv64`-only device), which is a real "nothing to install
     * here" case, not an error.
     */
    fun primaryAbi(): String? = Build.SUPPORTED_ABIS.firstOrNull { it in SUPPORTED_ABIS }

    /**
     * Probes `assets/` for this device's [primaryAbi]. Opens and immediately
     * closes the entry rather than trusting a cached flag, because the one
     * thing worse than an honest [State.ABSENT] is a stale [State.LINKED]
     * left over from a build that later stripped the asset out.
     */
    fun status(context: Context): State =
        if (manifest(context) != null) State.LINKED else State.ABSENT

    /**
     * The bundled asset's manifest for this device's [primaryAbi], or null
     * if there is no ABI match or no asset for the matched ABI. Blocking
     * (AssetManager I/O) — call off the main thread.
     */
    fun manifest(context: Context): Manifest? {
        val abi = primaryAbi() ?: return null
        return manifestFor(context, abi)
    }

    /** Same as [manifest] but for an explicit ABI, regardless of this device's own. Used by tooling/tests. */
    fun manifestFor(context: Context, abi: String): Manifest? {
        val path = assetPath(abi)
        return try {
            val size = context.assets.openFd(path).use { it.length }
            Manifest(abi = abi, assetPath = path, sizeBytes = size)
        } catch (_: IOException) {
            // AssetFileDescriptor.length only works on stored (uncompressed)
            // entries; fall back to a plain open+drain so a DEFLATEd asset
            // still reports present rather than a false ABSENT.
            try {
                context.assets.open(path).use { stream ->
                    var total = 0L
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = stream.read(buf)
                        if (n < 0) break
                        total += n
                    }
                    Manifest(abi = abi, assetPath = path, sizeBytes = total)
                }
            } catch (t: IOException) {
                Diagnostics.log(TAG, "no bootstrap asset for $abi at $path: ${t.javaClass.simpleName}")
                null
            }
        }
    }

    /**
     * One sentence for the UI. States the reach of what's bundled — never
     * claims a running subsystem, since this object only reports on the
     * asset, not on anything installed or executing from it.
     */
    fun explain(context: Context): String {
        val abi = primaryAbi()
        return when {
            abi == null -> "This device's ABI is not one Godwall ships a Linux subsystem bootstrap for " +
                "(${Build.SUPPORTED_ABIS.joinToString()}). The DNS filter, egress chain and mesh node do " +
                "not need it and still work; the daemon-backed services under Subsystem do not."
            else -> when (status(context)) {
                State.LINKED -> {
                    val m = manifest(context)
                    "A Linux subsystem bootstrap for $abi is bundled in this build " +
                        "(${m?.sizeBytes ?: 0} bytes, patched to run from $PREFIX). Nothing is installed or " +
                        "running yet — that step needs Yojimbo's privileged shell."
                }
                State.ABSENT -> "No Linux subsystem bootstrap is bundled in this build for $abi. " +
                    "Daemon-backed services (DNS resolvers, Tor/I2P, proxy backends) report absent " +
                    "rather than claiming a userland that isn't here."
            }
        }
    }
}
