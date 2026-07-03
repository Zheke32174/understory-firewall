package com.understory.firewall

/**
 * The single source of truth for which of the two app modes is active
 * (design-v2/firewall.md §1).
 *
 *   COMPANION  — default, permanent on any device with a VPN. Observe /
 *                advise only. No VpnService is ever prepared, started, or
 *                active. All value comes from rootless reads, OS deep-links,
 *                and the ADB-granted Private DNS applier.
 *
 *   STANDALONE — opt-in, default-off. The salvaged VpnService engine may
 *                run iff no other VPN holds the slot (the VpnSlotProbe
 *                guardrail). Reached only via an explicit settings flow
 *                behind a full-screen explainer.
 *
 * Mode is NOT "engine armed": STANDALONE is the *permission to arm*; the
 * arm/disarm toggle lives inside the Standalone hub and is itself
 * default-off. See the runtime-state table in §1.
 */
enum class FirewallMode { COMPANION, STANDALONE }
