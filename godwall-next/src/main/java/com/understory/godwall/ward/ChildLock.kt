package com.understory.godwall.ward

import android.content.Context
import android.util.Base64
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Child lock — InviZible Pro's PIN gate, ported.
 *
 * InviZible keeps a "child lock" that stops the controls being changed until a PIN is entered:
 * the modules keep running, only the controls freeze. That distinction is the whole point of the
 * feature and it is kept here — arming state, the mode, lockdown and pause are all frozen while
 * the lock is engaged, and **the engine keeps doing whatever it was already doing**. A lock that
 * stopped protection would be a way to turn protection off without the PIN.
 *
 * ## What is stored
 *
 * Never the PIN. A 16-byte random salt and a PBKDF2-HMAC-SHA256 digest at [ITERATIONS] rounds,
 * both base64 in SharedPreferences. Verification is constant-time over the digest. This is a
 * deterrent against a person holding the phone, not against someone with the file — that threat
 * is the platform's keystore's job, and claiming otherwise would overstate the reach.
 */
object ChildLock {

    private const val PREF = "godwall_ward"
    private const val K_SALT = "childlock_salt"
    private const val K_HASH = "childlock_hash"
    private const val K_ENGAGED = "childlock_engaged"

    private const val ITERATIONS = 120_000
    private const val KEY_BITS = 256
    const val MIN_PIN_LENGTH = 4

    private fun p(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    /** True when a PIN has been set at all. */
    fun isConfigured(ctx: Context): Boolean =
        !p(ctx).getString(K_HASH, null).isNullOrBlank()

    /** True when the controls are currently frozen. */
    fun isEngaged(ctx: Context): Boolean =
        isConfigured(ctx) && p(ctx).getBoolean(K_ENGAGED, false)

    /**
     * Set (or replace) the PIN and engage the lock. Blocking — PBKDF2 at [ITERATIONS] rounds is
     * deliberately slow, so this belongs on `Bg.cpu`.
     *
     * @return false when the PIN is too short; nothing is stored in that case.
     */
    fun setPin(ctx: Context, pin: String): Boolean {
        if (pin.length < MIN_PIN_LENGTH) return false
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val hash = derive(pin, salt)
        p(ctx).edit()
            .putString(K_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(K_HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
            .putBoolean(K_ENGAGED, true)
            .apply()
        return true
    }

    /** Re-engage an already-configured lock. No-op when no PIN is set. */
    fun engage(ctx: Context): Boolean {
        if (!isConfigured(ctx)) return false
        p(ctx).edit().putBoolean(K_ENGAGED, true).apply()
        return true
    }

    /** Verify and, on success, release the freeze. Blocking (PBKDF2). */
    fun unlock(ctx: Context, pin: String): Boolean {
        if (!verify(ctx, pin)) return false
        p(ctx).edit().putBoolean(K_ENGAGED, false).apply()
        return true
    }

    /** Verify and, on success, forget the PIN entirely. Blocking (PBKDF2). */
    fun clear(ctx: Context, pin: String): Boolean {
        if (!verify(ctx, pin)) return false
        p(ctx).edit().remove(K_SALT).remove(K_HASH).remove(K_ENGAGED).apply()
        return true
    }

    private fun verify(ctx: Context, pin: String): Boolean {
        val salt = p(ctx).getString(K_SALT, null)?.let { Base64.decode(it, Base64.NO_WRAP) }
            ?: return false
        val stored = p(ctx).getString(K_HASH, null)?.let { Base64.decode(it, Base64.NO_WRAP) }
            ?: return false
        return constantTimeEquals(stored, derive(pin, salt))
    }

    /** PBKDF2-HMAC-SHA256. Exposed for the round-trip test; it is not a secret. */
    fun derive(pin: String, salt: ByteArray): ByteArray =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, KEY_BITS))
            .encoded

    /** Length-independent compare, so a wrong PIN takes the same time as a right one. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}
