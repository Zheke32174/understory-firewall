package com.understory.security

import android.net.Uri

/**
 * Parser + builder for `otpauth://` URIs — the de-facto standard format
 * authenticator apps emit and consume in QR codes.
 *
 *   otpauth://totp/Issuer:Account?secret=BASE32&issuer=Issuer&digits=6&period=30&algorithm=SHA1
 *   otpauth://hotp/Issuer:Account?secret=BASE32&issuer=Issuer&digits=6&counter=0
 *
 * The label can be `Issuer:Account` (canonical), just `Account`, or
 * URL-encoded versions. Issuer parameter takes precedence over label
 * issuer when both are present (per Google's spec).
 *
 * This module is pure — no Android UI, no I/O. Both add-via-QR (gallery
 * decoded by ZXing) and add-manually flows feed strings here.
 */
data class OtpAuthEntry(
    val type: Type,
    val issuer: String,
    val account: String,
    val secret: ByteArray,
    val digits: Int = 6,
    val period: Int = 30,
    val counter: Long = 0,
    val algorithm: Algorithm = Algorithm.SHA1,
) {
    enum class Type { TOTP, HOTP }
    enum class Algorithm { SHA1, SHA256, SHA512 }

    /** Wipe the secret bytes when this entry is no longer needed. */
    fun wipeSecret() {
        for (i in secret.indices) secret[i] = 0
    }

    /** Build the canonical otpauth:// URI. */
    fun toUri(): String {
        val secretB32 = HotpSecret.encodeBase32(secret)
        val labelEnc = "${urlEncode(issuer)}:${urlEncode(account)}"
        val typeStr = if (type == Type.TOTP) "totp" else "hotp"
        val params = buildList {
            add("secret=$secretB32")
            add("issuer=${urlEncode(issuer)}")
            add("digits=$digits")
            add("algorithm=${algorithm.name}")
            when (type) {
                Type.TOTP -> add("period=$period")
                Type.HOTP -> add("counter=$counter")
            }
        }.joinToString("&")
        return "otpauth://$typeStr/$labelEnc?$params"
    }

    companion object {
        /**
         * Parse a string. Accepts:
         *   - Raw `otpauth://` URI (typical QR contents)
         *   - Just the base32 secret (manual entry — caller fills in
         *     issuer/account separately, this returns a TOTP with empty
         *     issuer/account)
         */
        fun parse(input: String): OtpAuthEntry {
            val trimmed = input.trim()
            if (trimmed.startsWith("otpauth://", ignoreCase = true)) {
                return parseUri(trimmed)
            }
            // Treat as a raw base32 secret. Caller must fill in issuer/account.
            return OtpAuthEntry(
                type = Type.TOTP,
                issuer = "",
                account = "",
                secret = HotpSecret.decodeBase32(trimmed),
            )
        }

        private fun parseUri(uriStr: String): OtpAuthEntry {
            val uri = Uri.parse(uriStr)
            require(uri.scheme.equals("otpauth", ignoreCase = true)) {
                "not an otpauth URI"
            }
            val typeStr = uri.host?.lowercase()
                ?: throw IllegalArgumentException("missing TYPE in otpauth URI")
            val type = when (typeStr) {
                "totp" -> Type.TOTP
                "hotp" -> Type.HOTP
                else -> throw IllegalArgumentException("unknown otpauth type: $typeStr")
            }

            // Path is "/Issuer:Account" or "/Account" — strip leading slash.
            // Uri.getPath() already percent-decodes; decoding again with
            // URLDecoder would turn a literal '+' into a space.
            val labelRaw = uri.path?.removePrefix("/") ?: ""
            val (labelIssuer, account) = splitLabel(labelRaw)

            val secretB32 = uri.getQueryParameter("secret")
                ?: throw IllegalArgumentException("missing secret param")
            val secret = HotpSecret.decodeBase32(secretB32)

            // Issuer query param takes precedence over label issuer.
            val issuer = uri.getQueryParameter("issuer")?.takeIf { it.isNotEmpty() }
                ?: labelIssuer

            val digits = uri.getQueryParameter("digits")?.toIntOrNull() ?: 6
            val period = uri.getQueryParameter("period")?.toIntOrNull() ?: 30
            val counter = uri.getQueryParameter("counter")?.toLongOrNull() ?: 0L
            val algorithm = when (uri.getQueryParameter("algorithm")?.uppercase()) {
                "SHA256" -> Algorithm.SHA256
                "SHA512" -> Algorithm.SHA512
                else -> Algorithm.SHA1
            }

            return OtpAuthEntry(
                type = type,
                issuer = issuer,
                account = account,
                secret = secret,
                digits = digits,
                period = period,
                counter = counter,
                algorithm = algorithm,
            )
        }

        private fun splitLabel(label: String): Pair<String, String> {
            val idx = label.indexOf(':')
            return if (idx < 0) "" to label else {
                label.substring(0, idx).trim() to label.substring(idx + 1).trim()
            }
        }

        private fun urlEncode(s: String): String =
            java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")
    }
}
