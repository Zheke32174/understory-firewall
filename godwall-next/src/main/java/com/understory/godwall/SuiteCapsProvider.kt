package com.understory.godwall

import com.understory.security.BaseCapabilityProvider

/**
 * Godwall's capability beacon for the suite registry.
 *
 * Version 2, not 1. The old `:firewall` module published version 1, which peers translate into
 * `NET_POSTURE_AUDIT` — "audits network posture and advises; never intercepts". That was an
 * accurate description of an app whose engine could not be armed on the reference device.
 *
 * This module actually holds the VPN slot and answers DNS, so continuing to advertise the
 * observe-only capability would understate it to every sibling that asks. The version bump is
 * the honest signal; peers that only know version 1 fall back to their unknown-peer handling
 * rather than mistaking the app for something it no longer is.
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 2
}
