package com.understory.net.engine

/**
 * FOR THE RECORD (design-v2/firewall.md §7 / A11): port-block discovery via
 * `/proc/net` was DROPPED and is deliberately NOT salvaged, because it is a
 * structural no-op on every supported device.
 *
 * On Android 10+ (API 29+), per-UID `/proc/net/{tcp,tcp6,udp,udp6}` socket
 * tables are unreadable by non-system apps: the kernel returns only the
 * caller's own sockets (SELinux + the hidden-uid patch). Firewall's minSdk
 * is 33, so 100% of installs are affected — a port scanner would always see
 * an empty foreign-socket table and derive nothing.
 *
 * The honest replacement is retrospective volume accounting via
 * NetworkStatsManager (Traffic by App), which names how much each app moved,
 * not which connections it opened. This file carries no code — only this
 * note, so the limitation survives the deletion.
 */
internal object PortBlockLimitation
