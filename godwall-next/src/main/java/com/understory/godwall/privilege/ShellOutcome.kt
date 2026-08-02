package com.understory.godwall.privilege

import android.os.Parcel
import android.os.Parcelable

/**
 * Result of one privileged argv: the exit status and both streams.
 *
 * Flattened by hand rather than via kotlin-parcelize so this module needs no
 * extra Gradle plugin — the AIDL surface stays small enough that hand-writing
 * the flattener is cheaper than another build dependency.
 */
data class ShellOutcome(
    val exit: Int,
    val out: String,
    val err: String,
) : Parcelable {

    val ok: Boolean get() = exit == 0

    /** One-line summary safe to show a user: never longer than [SUMMARY_CHARS]. */
    fun summary(): String {
        val stream = if (ok) out else err.ifBlank { out }
        val trimmed = stream.trim().replace('\n', ' ')
        return if (trimmed.length <= SUMMARY_CHARS) trimmed else trimmed.take(SUMMARY_CHARS) + "…"
    }

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(exit)
        dest.writeString(out)
        dest.writeString(err)
    }

    companion object {
        private const val SUMMARY_CHARS = 160

        /** Synthesised outcome for "we never reached a privileged process". */
        fun unavailable(reason: String) = ShellOutcome(exit = -1, out = "", err = reason)

        @JvmField
        val CREATOR: Parcelable.Creator<ShellOutcome> = object : Parcelable.Creator<ShellOutcome> {
            override fun createFromParcel(source: Parcel): ShellOutcome = ShellOutcome(
                exit = source.readInt(),
                out = source.readString() ?: "",
                err = source.readString() ?: "",
            )

            override fun newArray(size: Int): Array<ShellOutcome?> = arrayOfNulls(size)
        }
    }
}
