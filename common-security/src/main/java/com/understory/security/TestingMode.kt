package com.understory.security

/**
 * Build-time flags for non-release behavior the suite wants to flip on
 * uniformly across all apps. Read by each Activity / Service to decide
 * whether to enable test-only conveniences.
 *
 * RELEASE-BLOCKER: every flag here is "true" in test builds and MUST be
 * "false" before publication. The release-blockers checklist references
 * this file; auditing for `TESTING = true` is part of the readiness sweep.
 *
 * Why a hand-flipped constant instead of `BuildConfig.DEBUG` or a gradle
 * flavor:
 *   - The suite ships from a single debug build right now; we don't have
 *     real release variants yet (no signed keystore, no published cert
 *     pin). When that lands, this file can be replaced with a
 *     BuildConfig-based check; for now it's an explicit manual switch.
 *   - Manual switching forces a deliberate lockstep audit before release,
 *     rather than relying on gradle to silently differ between builds.
 */
object TestingMode {

    /**
     * When true, Activities skip setting `WindowManager.LayoutParams.FLAG_SECURE`
     * so the user can take screenshots of the diagnostic surface (and
     * report-by-screenshot in general). Apps still set
     * `setHideOverlayWindows(true)` and `setRecentsScreenshotEnabled(false)`
     * separately; this only governs FLAG_SECURE.
     *
     * RELEASE-BLOCKER: must be false before publication. FLAG_SECURE is
     * what prevents screen-recording / screenshot of vault contents,
     * generated passwords, recovery keys, and TOTP codes.
     */
    const val ALLOW_SCREENSHOTS = false

    /**
     * When true, `onUserLeaveHint` skips both the vault lock and the
     * `finishAndRemoveTask` it would otherwise perform. Apps stay alive
     * in memory across switching to other apps and back, and the user
     * doesn't have to re-authenticate every time they navigate away.
     *
     * Why this matters for testing: the destroy-on-leave + lock-on-leave
     * pattern is correct for production (every backgrounding wipes the
     * unlocked vault and removes the activity), but it makes iterative
     * testing painful — the user has to re-authenticate every time they
     * check Diagnostics, switch back from a chat app to report a bug,
     * etc. With this flag true, the apps behave like normal Android
     * apps for the testing phase: switch away, switch back, same state.
     *
     * RELEASE-BLOCKER: must be false before publication. The lock-on-
     * leave + destroy-on-leave behavior is part of the suite's
     * "session-scoped, no persistent unlocked state" security posture.
     * Skipping it for production means a stolen device that's still
     * within the screen-lock grace period can resume unlocked vault.
     */
    const val KEEP_ALIVE_ON_LEAVE = false
}
