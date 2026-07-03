package com.understory.elevation

/**
 * The three optional elevation tiers, ordered by "how we got the privilege"
 * NOT by power. [NONE] is the suite's default and every app is 100% functional
 * at [NONE]; the higher tiers only ever *light up* extra actions the user has
 * explicitly enabled by installing Shizuku/Dhizuku and granting this app.
 *
 * Ordinal order (NONE < SHIZUKU < DHIZUKU) is used only as a stable
 * "highest granted" tie-break in [Elevation.grantedTier]; it is not a claim
 * that Dhizuku is strictly more powerful than Shizuku. Feature code should ask
 * a capability predicate (canControlAppNetwork, …) rather than compare tiers.
 */
enum class ElevTier {
    /** Rootless. No Shizuku, no Dhizuku — the current, always-available suite behavior. */
    NONE,

    /** Shizuku bound and permission granted: privileged shell at the granted uid (typically 2000). */
    SHIZUKU,

    /** Dhizuku bound and permission granted: a delegated Device-Owner DevicePolicyManager. */
    DHIZUKU,
}

/**
 * Result of a privileged shell command run through [Elevation.runShell].
 * [exit] 0 conventionally means success. [out]/[err] are the captured streams.
 */
data class ShellResult(
    val exit: Int,
    val out: String,
    val err: String,
) {
    /** Convenience: exit code 0. */
    val ok: Boolean get() = exit == 0
}

/** Private DNS modes accepted by [Elevation.setPrivateDns]. */
enum class PrivateDnsMode(
    /** The `private_dns_mode` global-setting string the platform expects. */
    val settingValue: String,
) {
    OFF("off"),
    /** "Automatic" / opportunistic — the AOSP name for this value is `opportunistic`. */
    AUTOMATIC("opportunistic"),
    /** Strict mode; requires a hostname passed to [Elevation.setPrivateDns]. */
    HOSTNAME("hostname"),
}

/**
 * Thrown ONLY by [Elevation.runShell] when no shell-capable tier is granted.
 * runShell is the one low-level primitive that throws (callers that reach for a
 * raw shell are expected to have gated on [Elevation.canRunShell]); every
 * high-level helper instead returns an [Outcome] and never throws to the UI.
 */
class NotElevated(message: String = "No elevation tier is granted") : Exception(message)

/**
 * The result type every high-level helper returns. Deliberately a closed set so
 * a consuming app can `when`-branch exhaustively and render honest UI. NO helper
 * throws to the UI — a missing tier is [Unsupported], a failed privileged call
 * is [Failed], never an exception.
 */
sealed interface Outcome {
    /** The action succeeded. [detail] is an optional human line for a toast/log. */
    data class Success(val detail: String? = null) : Outcome

    /**
     * No granted tier can perform this action right now. [reason] explains why
     * (e.g. "needs Shizuku") so the UI can show the rootless fallback
     * instead of a dead button. This is the "degrade honestly" signal.
     */
    data class Unsupported(val reason: String) : Outcome

    /**
     * A granted tier attempted the action but it failed. [message] is a short
     * cause; [cause] is the underlying throwable when there was one (never
     * surfaced raw to the user).
     */
    data class Failed(val message: String, val cause: Throwable? = null) : Outcome
}
