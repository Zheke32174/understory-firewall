package com.understory.firewall

import android.content.Context
import com.understory.security.Diagnostics
import org.json.JSONArray
import org.json.JSONObject

/**
 * Scheduled posture re-check (design-v2/firewall.md §5.4 / §5.1 composed into a
 * background watcher). A purely rootless, opt-in periodic job that re-runs the
 * facts the Overview already shows — tunnel/VPN-slot posture, DNS hardening, and
 * the remote-admin capability audit — captures them into a small on-device
 * [PostureSnapshot], and diffs the new capture against the last saved baseline.
 * When (and only when) something got WORSE — a newly-granted accessibility /
 * device-admin / notification-listener (etc.) holder appeared, Private DNS was
 * turned off, or a VPN-less state emerged — it raises one honest notification.
 *
 * DOCTRINE / HONESTY (design-v2/firewall.md §0):
 *  - This is OBSERVE + NOTIFY, never block. The notification's own copy says so.
 *  - Everything is opt-in: the watcher is off until the user enables it, and it
 *    degrades honestly (no crash, a plain in-app note) if the OS denies the
 *    POST_NOTIFICATIONS runtime permission or exact-alarm scheduling.
 *  - It reads only what the foreground screens already read (no new capability,
 *    no network, no PII beyond package names). The snapshot lives in the app's
 *    private SharedPreferences and never leaves the device.
 *  - It NEVER touches the VPN slot and is independent of Standalone mode.
 *
 * SCHEDULING: plain [android.app.AlarmManager] inexact windows via
 * [PostureWatchReceiver] — no WorkManager dependency is added to the classpath.
 * Inexact alarms are the correct, battery-friendly primitive for an
 * opportunistic security re-check; we deliberately do NOT request exact-alarm
 * privileges.
 */
object PostureWatch {

    // -----------------------------------------------------------------
    // Snapshot model
    // -----------------------------------------------------------------

    /**
     * One package that holds one confirmed remote-admin-class capability, as of
     * a capture. We store the (capability, package) pairs rather than whole
     * [AuditFinding]s because the diff cares about "did a NEW app gain a
     * high-power capability", which is exactly a set-difference over these pairs.
     * We intentionally record only CONFIRMED grants here (never the "unknown"
     * caps) so a flaky AppOps read can't manufacture a phantom "new finding"
     * alert on every run.
     */
    data class CapHolder(val capability: RiskCapability, val packageName: String, val label: String)

    /**
     * A single point-in-time posture capture. Every field traces to a rootless
     * read; anything unreadable degrades ([Tri.UNKNOWN] / null) exactly as the
     * foreground read-models do, and is treated as "no change" by the diff so an
     * inference gap never fires a false alert.
     */
    data class PostureSnapshot(
        val capturedAtMillis: Long,
        val aVpnIsUp: Tri,
        val dnsMode: String,          // "hostname" | "opportunistic" | "off"
        val capHolders: List<CapHolder>,
    ) {
        fun toJson(): JSONObject = JSONObject().apply {
            put(K_TS, capturedAtMillis)
            put(K_VPN, aVpnIsUp.name)
            put(K_DNS, dnsMode)
            put(K_CAPS, JSONArray().apply {
                for (h in capHolders) {
                    put(JSONObject().apply {
                        put(K_CAP, h.capability.name)
                        put(K_PKG, h.packageName)
                        put(K_LABEL, h.label)
                    })
                }
            })
        }

        companion object {
            private const val K_TS = "ts"
            private const val K_VPN = "vpn"
            private const val K_DNS = "dns"
            private const val K_CAPS = "caps"
            private const val K_CAP = "cap"
            private const val K_PKG = "pkg"
            private const val K_LABEL = "label"

            fun fromJson(o: JSONObject): PostureSnapshot? = runCatching {
                val caps = mutableListOf<CapHolder>()
                val arr = o.optJSONArray(K_CAPS) ?: JSONArray()
                for (i in 0 until arr.length()) {
                    val c = arr.optJSONObject(i) ?: continue
                    val cap = runCatching { RiskCapability.valueOf(c.getString(K_CAP)) }
                        .getOrNull() ?: continue    // drop caps removed in a future build
                    caps += CapHolder(
                        capability = cap,
                        packageName = c.optString(K_PKG),
                        label = c.optString(K_LABEL).ifBlank { c.optString(K_PKG) },
                    )
                }
                PostureSnapshot(
                    capturedAtMillis = o.optLong(K_TS, 0L),
                    aVpnIsUp = runCatching { Tri.valueOf(o.optString(K_VPN)) }.getOrDefault(Tri.UNKNOWN),
                    dnsMode = o.optString(K_DNS).ifBlank { "opportunistic" },
                    capHolders = caps,
                )
            }.getOrNull()
        }
    }

    /**
     * Capture the live posture off the main thread. Composes the SAME rootless
     * readers the foreground uses — [TunnelPosture.read], [PrivateDnsApplier.current],
     * and [RemoteAdminAudit.scan] — so the background verdict can never diverge
     * from what the user would see if they opened the app. Never throws.
     */
    fun capture(ctx: Context): PostureSnapshot {
        val tunnel = runCatching { TunnelPosture.read(ctx) }.getOrNull()
        val dns = runCatching { PrivateDnsApplier.current(ctx).mode }.getOrDefault("opportunistic")
        val findings = runCatching { RemoteAdminAudit.scan(ctx) }.getOrDefault(emptyList())
        val holders = findings.flatMap { f ->
            // Confirmed caps only — see CapHolder doc.
            f.capabilities.map { cap -> CapHolder(cap, f.packageName, f.label) }
        }
        return PostureSnapshot(
            capturedAtMillis = System.currentTimeMillis(),
            aVpnIsUp = tunnel?.aVpnIsUp ?: Tri.UNKNOWN,
            dnsMode = dns,
            capHolders = holders,
        )
    }

    // -----------------------------------------------------------------
    // Diff → honest "what got worse" lines
    // -----------------------------------------------------------------

    /**
     * A single change worth surfacing. Only REGRESSIONS are produced — a new
     * capability holder, DNS turning off, or a VPN dropping. Improvements (an app
     * losing a capability, DNS coming on) are NOT alerts; they're reflected in
     * the next baseline silently. [key] dedups repeat alerts across runs.
     */
    data class Change(val key: String, val summary: String, val severity: Int)

    /**
     * Diff [new] against [baseline], returning only regressions, most-severe
     * first. A null [baseline] (first ever run) yields NO changes — the first
     * capture just establishes the baseline, so enabling the watch never
     * immediately fires on the device's pre-existing state.
     */
    fun diff(baseline: PostureSnapshot?, new: PostureSnapshot): List<Change> {
        if (baseline == null) return emptyList()
        val changes = mutableListOf<Change>()

        // (1) Newly-granted remote-admin capabilities (the headline case).
        val oldPairs = baseline.capHolders.map { it.capability to it.packageName }.toHashSet()
        for (h in new.capHolders) {
            if ((h.capability to h.packageName) !in oldPairs) {
                changes += Change(
                    key = "cap:${h.capability.name}:${h.packageName}",
                    summary = "${h.label} gained \"${h.capability.display}\"",
                    severity = h.capability.severity,
                )
            }
        }

        // (2) Private DNS turned off (encrypted/opportunistic → off).
        if (baseline.dnsMode != "off" && new.dnsMode == "off") {
            changes += Change(
                key = "dns:off",
                summary = "Private DNS was turned off (DNS is now unencrypted)",
                severity = 60,
            )
        }

        // (3) A VPN that was up is now down. Only fire on a definite YES→NO
        //     transition; UNKNOWN on either side is an inference gap, not an
        //     event (CD-4d: never a false alert on a read we couldn't make).
        if (baseline.aVpnIsUp == Tri.YES && new.aVpnIsUp == Tri.NO) {
            changes += Change(
                key = "vpn:down",
                summary = "The VPN that was protecting this device is no longer up",
                severity = 60,
            )
        }

        return changes.sortedByDescending { it.severity }
    }

    // -----------------------------------------------------------------
    // Persistence (private SharedPreferences; never leaves the device)
    // -----------------------------------------------------------------

    private const val PREF = "posture_watch"
    private const val K_ENABLED = "enabled"
    private const val K_INTERVAL = "interval_hours"
    private const val K_BASELINE = "baseline_json"
    private const val K_LAST_RUN = "last_run_millis"
    private const val K_LAST_RESULT = "last_result"        // human one-liner
    private const val K_LAST_CHANGE_COUNT = "last_change_count"
    /** Keys of changes already surfaced, so a persistent regression isn't
     *  re-notified on every run — only the FIRST time it appears. */
    private const val K_NOTIFIED_KEYS = "notified_keys"

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    fun isEnabled(ctx: Context): Boolean = prefs(ctx).getBoolean(K_ENABLED, false)

    fun setEnabled(ctx: Context, enabled: Boolean) {
        prefs(ctx).edit().putBoolean(K_ENABLED, enabled).apply()
    }

    /** Re-check cadence in hours. Default 24h; the picker offers 6/12/24/72. */
    fun getIntervalHours(ctx: Context): Int =
        prefs(ctx).getInt(K_INTERVAL, DEFAULT_INTERVAL_HOURS)

    fun setIntervalHours(ctx: Context, hours: Int) {
        prefs(ctx).edit().putInt(K_INTERVAL, hours.coerceIn(MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS)).apply()
    }

    fun getBaseline(ctx: Context): PostureSnapshot? {
        val raw = prefs(ctx).getString(K_BASELINE, null) ?: return null
        return runCatching { PostureSnapshot.fromJson(JSONObject(raw)) }.getOrNull()
    }

    fun saveBaseline(ctx: Context, snapshot: PostureSnapshot) {
        prefs(ctx).edit().putString(K_BASELINE, snapshot.toJson().toString()).apply()
    }

    fun getLastRunMillis(ctx: Context): Long = prefs(ctx).getLong(K_LAST_RUN, 0L)

    fun getLastResult(ctx: Context): String? = prefs(ctx).getString(K_LAST_RESULT, null)

    fun getLastChangeCount(ctx: Context): Int = prefs(ctx).getInt(K_LAST_CHANGE_COUNT, 0)

    private fun getNotifiedKeys(ctx: Context): Set<String> =
        prefs(ctx).getStringSet(K_NOTIFIED_KEYS, emptySet())?.toSet() ?: emptySet()

    private fun setNotifiedKeys(ctx: Context, keys: Set<String>) {
        prefs(ctx).edit().putStringSet(K_NOTIFIED_KEYS, keys).apply()
    }

    fun recordRun(ctx: Context, resultLine: String, changeCount: Int) {
        prefs(ctx).edit()
            .putLong(K_LAST_RUN, System.currentTimeMillis())
            .putString(K_LAST_RESULT, resultLine)
            .putInt(K_LAST_CHANGE_COUNT, changeCount)
            .apply()
    }

    /**
     * Clear all watcher state (called when the user turns the watch off). Leaves
     * the enabled flag alone — the caller sets that — but drops the baseline,
     * history line, and the notified-keys dedup memory so a later re-enable
     * starts clean.
     */
    fun clearState(ctx: Context) {
        prefs(ctx).edit()
            .remove(K_BASELINE)
            .remove(K_LAST_RUN)
            .remove(K_LAST_RESULT)
            .remove(K_LAST_CHANGE_COUNT)
            .remove(K_NOTIFIED_KEYS)
            .apply()
    }

    // -----------------------------------------------------------------
    // The one background pass (called from the receiver, off main thread)
    // -----------------------------------------------------------------

    /**
     * Run a single background re-check: capture, diff against the baseline,
     * notify on genuinely-new regressions, then adopt the new capture as the
     * baseline. Returns a short human summary (also persisted as the last
     * result). Never throws — a failed run degrades to an honest note.
     *
     * De-dup: a regression key already in [K_NOTIFIED_KEYS] is folded into the
     * baseline WITHOUT re-notifying, so a standing issue alerts once. When a
     * previously-flagged regression is later resolved (its key no longer diffs),
     * its key ages out of the memory so a future recurrence would re-alert.
     */
    fun runOnce(ctx: Context): String {
        val baseline = getBaseline(ctx)
        val snapshot = capture(ctx)
        val allChanges = diff(baseline, snapshot)

        val alreadyNotified = getNotifiedKeys(ctx)
        val fresh = allChanges.filter { it.key !in alreadyNotified }

        if (fresh.isNotEmpty()) {
            PostureWatchNotifier.notifyChanges(ctx, fresh)
        }

        // Adopt the new snapshot as the baseline, and remember every key that is
        // CURRENTLY a regression (fresh + still-standing) so it isn't re-fired;
        // keys no longer present drop out and could re-alert on recurrence.
        saveBaseline(ctx, snapshot)
        setNotifiedKeys(ctx, allChanges.map { it.key }.toHashSet())

        val summary = when {
            baseline == null -> "Baseline recorded. Future changes will be compared to it."
            fresh.isNotEmpty() -> "${fresh.size} new change(s) found and notified."
            allChanges.isNotEmpty() -> "No new changes (previously-flagged items still present)."
            else -> "Checked — no changes since last time."
        }
        recordRun(ctx, summary, fresh.size)
        Diagnostics.log("firewall.PostureWatch", "runOnce: $summary")
        return summary
    }

    const val DEFAULT_INTERVAL_HOURS = 24
    const val MIN_INTERVAL_HOURS = 6
    const val MAX_INTERVAL_HOURS = 72

    /** The cadence choices offered in the UI (hours). */
    val INTERVAL_CHOICES = listOf(6, 12, 24, 72)
}
