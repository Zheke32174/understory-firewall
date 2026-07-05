package com.understory.firewall.policy

import android.content.Context
import com.understory.security.Diagnostics
import org.json.JSONArray
import org.json.JSONObject

/**
 * Stage-3 persistence for the slot-free policy engine: the global
 * [DefaultPolicy], the per-app screen-off / background flags, and the named
 * [PolicyProfile] snapshots. Lives in the SAME `firewall_policy` prefs file as
 * [BackendManager]'s blocked set (they are one policy), under distinct keys.
 *
 * All values are plain preferences (which apps the user chose, what mode) — not
 * credentials — so plain SharedPreferences is correct, mirroring
 * [com.understory.firewall.FirewallSettings].
 *
 * HONESTY: nothing here enforces anything on its own. It only records intent;
 * [BackendManager]/[EffectivePolicy] compute the effective blocked set and the
 * backend applies it via the Shizuku shell. The exemption gate ([UidExemptions])
 * still wins over every value stored here, at apply time.
 */
object PolicyStore {

    private const val TAG = "firewall.policy.PolicyStore"

    // Shared prefs file — the same one BackendManager persists the blocked set in.
    private const val PREF = "firewall_policy"

    private const val K_DEFAULT_POLICY = "policy_default"
    private const val K_SCREEN_OFF = "policy_screen_off_pkgs"
    private const val K_BACKGROUND = "policy_background_pkgs"
    private const val K_PROFILES = "policy_profiles_json"

    // BackendManager owns this key; PolicyStore reads/writes it only when
    // snapshotting or restoring a profile (a profile carries the block set too).
    private const val K_BLOCKED = "policy_blocked_packages"

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    // ---------------------------------------------------------------
    // Default policy (whitelist vs blacklist)
    // ---------------------------------------------------------------

    /**
     * The global default. [DefaultPolicy.ALLOW_ALL] (blacklist — everything
     * reachable unless explicitly blocked) is the Stage-1 behavior and the
     * default. [DefaultPolicy.BLOCK_ALL] (whitelist — every non-exempt app
     * blocked unless explicitly allowed) is the opt-in lockdown posture.
     */
    fun getDefaultPolicy(ctx: Context): DefaultPolicy {
        val raw = prefs(ctx).getString(K_DEFAULT_POLICY, null)
        return runCatching { DefaultPolicy.valueOf(raw ?: "") }
            .getOrDefault(DefaultPolicy.ALLOW_ALL)
    }

    fun setDefaultPolicy(ctx: Context, policy: DefaultPolicy) {
        prefs(ctx).edit().putString(K_DEFAULT_POLICY, policy.name).apply()
        Diagnostics.log(TAG, "defaultPolicy → $policy")
    }

    // ---------------------------------------------------------------
    // Per-app conditional flags
    // ---------------------------------------------------------------

    /** Packages set to block WHILE THE SCREEN IS OFF (the screen-state monitor drives apply). */
    fun getScreenOffPackages(ctx: Context): Set<String> =
        prefs(ctx).getStringSet(K_SCREEN_OFF, emptySet())?.toSet() ?: emptySet()

    /** Packages set to block WHILE IN THE BACKGROUND (approximated by screen-off; see EffectivePolicy). */
    fun getBackgroundPackages(ctx: Context): Set<String> =
        prefs(ctx).getStringSet(K_BACKGROUND, emptySet())?.toSet() ?: emptySet()

    /** Set/clear the screen-off flag for [pkg]. Use `applyScreenOff`, not a `setX` beside a property. */
    fun applyScreenOff(ctx: Context, pkg: String, enabled: Boolean) {
        val cur = getScreenOffPackages(ctx).toMutableSet()
        if (enabled) cur += pkg else cur -= pkg
        prefs(ctx).edit().putStringSet(K_SCREEN_OFF, cur).apply()
    }

    /** Set/clear the background flag for [pkg]. */
    fun applyBackground(ctx: Context, pkg: String, enabled: Boolean) {
        val cur = getBackgroundPackages(ctx).toMutableSet()
        if (enabled) cur += pkg else cur -= pkg
        prefs(ctx).edit().putStringSet(K_BACKGROUND, cur).apply()
    }

    // ---------------------------------------------------------------
    // Named profiles
    // ---------------------------------------------------------------

    /**
     * All saved profiles, newest-first insertion order preserved. Corrupt JSON
     * yields an empty list (never a throw into the UI) — a malformed store just
     * reads as "no profiles", it can never brick the app.
     */
    fun getProfiles(ctx: Context): List<PolicyProfile> {
        val raw = prefs(ctx).getString(K_PROFILES, null) ?: return emptyList()
        return runCatching {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull { i ->
                arr.optJSONObject(i)?.let { PolicyProfile.fromJson(it) }
            }
        }.getOrElse {
            Diagnostics.error(TAG, "getProfiles parse failed: ${it.javaClass.simpleName}")
            emptyList()
        }
    }

    /** Look up one profile by exact name, or null. */
    fun getProfile(ctx: Context, name: String): PolicyProfile? =
        getProfiles(ctx).firstOrNull { it.name == name }

    /**
     * Persist the whole profile list. Kept private-ish: callers use
     * [saveProfile] / [deleteProfile] so the JSON round-trip is centralized.
     */
    private fun writeProfiles(ctx: Context, profiles: List<PolicyProfile>) {
        val arr = JSONArray()
        for (p in profiles) arr.put(p.toJson())
        prefs(ctx).edit().putString(K_PROFILES, arr.toString()).apply()
    }

    /**
     * Save (or overwrite by name) [profile]. Overwrite-by-name is deliberate:
     * "save current as Home" twice updates Home rather than duplicating it.
     */
    fun saveProfile(ctx: Context, profile: PolicyProfile) {
        val others = getProfiles(ctx).filter { it.name != profile.name }
        writeProfiles(ctx, others + profile)
        Diagnostics.log(TAG, "profile saved: ${profile.name} (${profile.blocked.size} blocked)")
    }

    /** Delete the named profile if present. */
    fun deleteProfile(ctx: Context, name: String) {
        val remaining = getProfiles(ctx).filter { it.name != name }
        writeProfiles(ctx, remaining)
        Diagnostics.log(TAG, "profile deleted: $name")
    }

    /**
     * Capture the CURRENT persisted policy (default policy + blocked set +
     * per-app flags) into a named [PolicyProfile] value. Does not persist it —
     * the caller passes it to [saveProfile]. Reads only persisted state, so it
     * is safe to call off the main thread without touching a backend.
     */
    fun snapshotCurrent(ctx: Context, name: String): PolicyProfile = PolicyProfile(
        name = name,
        defaultPolicy = getDefaultPolicy(ctx),
        blocked = readBlocked(ctx),
        screenOff = getScreenOffPackages(ctx),
        background = getBackgroundPackages(ctx),
    )

    /**
     * Restore [profile] into the persisted policy: default policy, per-app
     * flags, and the blocked set are all overwritten. This mutates persistence
     * ONLY; the caller must then re-apply through [BackendManager] so the device
     * matches. The blocked set is written filtered through nothing here — the
     * apply path re-asserts [UidExemptions], so an exempt package that somehow
     * lived in a saved profile still can't sever Tailscale.
     */
    fun restoreInto(ctx: Context, profile: PolicyProfile) {
        prefs(ctx).edit()
            .putString(K_DEFAULT_POLICY, profile.defaultPolicy.name)
            .putStringSet(K_BLOCKED, profile.blocked)
            .putStringSet(K_SCREEN_OFF, profile.screenOff)
            .putStringSet(K_BACKGROUND, profile.background)
            .apply()
        Diagnostics.log(TAG, "profile restored into store: ${profile.name}")
    }

    // The blocked set is BackendManager's key; expose a read here only so a
    // snapshot can capture it. Writes to it go through BackendManager or a
    // full profile restore, never a piecemeal PolicyStore mutation.
    private fun readBlocked(ctx: Context): Set<String> =
        prefs(ctx).getStringSet(K_BLOCKED, emptySet())?.toSet() ?: emptySet()
}

/**
 * Global default-policy mode.
 *
 *   ALLOW_ALL  — blacklist. Everything reachable unless a package is in the
 *                explicit blocked set. This is the Stage-1 default and behavior.
 *   BLOCK_ALL  — whitelist / "lockdown". Every non-exempt installed app is
 *                blocked unless it is an explicit allow (i.e. absent from the
 *                blocked set has no effect; presence in the allow list does).
 *
 * Exemptions ([UidExemptions]) ALWAYS win: BLOCK_ALL never blocks a VPN provider
 * or system-critical package, so Tailscale is never severed.
 */
enum class DefaultPolicy { ALLOW_ALL, BLOCK_ALL }

/**
 * A named, restorable snapshot of the whole slot-free policy. Serialized to JSON
 * inside the profiles preference. [allow] carries the explicit-allow set used in
 * BLOCK_ALL (whitelist) mode; [blocked] carries the explicit-block set used in
 * ALLOW_ALL (blacklist) mode. Both are persisted so switching default policy
 * inside a profile is lossless.
 */
data class PolicyProfile(
    val name: String,
    val defaultPolicy: DefaultPolicy,
    val blocked: Set<String>,
    val screenOff: Set<String>,
    val background: Set<String>,
    /**
     * Explicit-allow set (the whitelist "holes" in BLOCK_ALL). Optional for
     * back-compat with profiles saved before this field existed; empty means
     * "no explicit allowances", i.e. a true full lockdown of non-exempt apps.
     */
    val allow: Set<String> = emptySet(),
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name)
        put("defaultPolicy", defaultPolicy.name)
        put("blocked", JSONArray(blocked.toList()))
        put("screenOff", JSONArray(screenOff.toList()))
        put("background", JSONArray(background.toList()))
        put("allow", JSONArray(allow.toList()))
    }

    companion object {
        fun fromJson(o: JSONObject): PolicyProfile? {
            val name = o.optString("name").takeIf { it.isNotBlank() } ?: return null
            val policy = runCatching { DefaultPolicy.valueOf(o.optString("defaultPolicy")) }
                .getOrDefault(DefaultPolicy.ALLOW_ALL)
            return PolicyProfile(
                name = name,
                defaultPolicy = policy,
                blocked = jsonToSet(o.optJSONArray("blocked")),
                screenOff = jsonToSet(o.optJSONArray("screenOff")),
                background = jsonToSet(o.optJSONArray("background")),
                allow = jsonToSet(o.optJSONArray("allow")),
            )
        }

        private fun jsonToSet(arr: JSONArray?): Set<String> {
            if (arr == null) return emptySet()
            val out = HashSet<String>(arr.length())
            for (i in 0 until arr.length()) {
                arr.optString(i).takeIf { it.isNotBlank() }?.let { out += it }
            }
            return out
        }
    }
}
