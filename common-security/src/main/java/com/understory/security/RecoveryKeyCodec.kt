package com.understory.security

/**
 * Encodes / decodes the [VaultRecovery.RecoveryKey] between raw bytes and the
 * two human-transferable text forms:
 *
 *   - **base64-no-pad** (~43 chars for 32 bytes) — the compact form, matches
 *     [Crypto.generateMasterPassword]'s existing base64-url alphabet so the
 *     suite has one recovery-string shape. Best for copy/paste and SAF export.
 *   - **grouped transcription form** — the same base64 broken into
 *     [GROUP_LEN]-char groups joined by a space (e.g.
 *     `k9Fh 2mQ0 ...`). Easier to read aloud or copy onto paper without losing
 *     place; the spaces are cosmetic. A space separator (not `-`) is required
 *     because the URL-safe base64 alphabet itself contains `-` as a data
 *     character, so a `-` separator would be ambiguous and corrupt the
 *     round-trip; whitespace never appears in base64 and is collision-proof.
 *
 * The canonical stored/derived form is base64-no-pad (URL-safe alphabet). The
 * grouped form is purely presentational: [normalize] strips the grouping back
 * to canonical, so a user may paste either form on a new device.
 *
 * No new dependency: base64 is `android.util.Base64` (already used by
 * [Crypto.generateMasterPassword]).
 */
object RecoveryKeyCodec {

    /** Characters per hyphen-separated group in the transcription form. */
    const val GROUP_LEN: Int = 4

    private const val B64_FLAGS =
        android.util.Base64.NO_PADDING or
            android.util.Base64.NO_WRAP or
            android.util.Base64.URL_SAFE

    /**
     * Encode [raw] to the canonical base64-no-pad char form. The caller owns
     * [raw] and must wipe it; the returned CharArray is owned by the resulting
     * [VaultRecovery.RecoveryKey].
     */
    fun encode(raw: ByteArray): CharArray {
        val b64 = android.util.Base64.encodeToString(raw, B64_FLAGS)
        return b64.toCharArray()
    }

    /**
     * Decode canonical (or grouped) [chars] back to raw bytes. Throws
     * [IllegalArgumentException] on a malformed key. Caller must wipe both the
     * input reference it owns and the returned bytes.
     */
    fun decode(chars: CharArray): ByteArray {
        val canonical = normalize(chars)
        try {
            val s = String(canonical)
            return android.util.Base64.decode(s, B64_FLAGS)
        } finally {
            Crypto.wipe(canonical)
        }
    }

    // NOTE: there is intentionally NO grouped()/display formatter. A recovery
    // key is never rendered on screen (threat model: the screen is the enemy) —
    // it is generated, stored, and moved only as an opaque file (RecoveryFile).

    /**
     * Strip grouping (all whitespace) from a user-entered key, returning the
     * canonical base64 char form. Only whitespace is stripped — NOT `-`, which
     * is a data character in the URL-safe base64 alphabet. Idempotent for
     * already-canonical input. The caller owns [chars]; the returned array is a
     * fresh copy the caller must wipe.
     */
    fun normalize(chars: CharArray): CharArray {
        // Count kept chars first so we allocate exactly once (no intermediate
        // String that would linger the secret on the heap).
        var kept = 0
        for (c in chars) if (!isSeparator(c)) kept++
        val out = CharArray(kept)
        var j = 0
        for (c in chars) if (!isSeparator(c)) out[j++] = c
        return out
    }

    private fun isSeparator(c: Char): Boolean = c.isWhitespace()
}
