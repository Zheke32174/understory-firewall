package com.understory.elevation

import android.os.Parcel
import android.os.Parcelable

/**
 * AIDL-marshalable carrier for a shell command result. Implements [Parcelable]
 * by hand (rather than via the kotlin-parcelize plugin) to keep this module's
 * plugin set identical to the rest of :common — no extra Gradle plugin just for
 * one parcel.
 *
 * This is the wire type crossing the Shizuku UserService binder. The broker
 * translates it into the public [ShellResult] before handing it to callers, so
 * app code never sees this internal parcel.
 */
class ShellResultParcel(
    @JvmField val exit: Int,
    @JvmField val out: String,
    @JvmField val err: String,
) : Parcelable {

    private constructor(p: Parcel) : this(
        exit = p.readInt(),
        out = p.readString() ?: "",
        err = p.readString() ?: "",
    )

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(exit)
        dest.writeString(out)
        dest.writeString(err)
    }

    override fun describeContents(): Int = 0

    companion object {
        @JvmField
        val CREATOR: Parcelable.Creator<ShellResultParcel> =
            object : Parcelable.Creator<ShellResultParcel> {
                override fun createFromParcel(source: Parcel): ShellResultParcel =
                    ShellResultParcel(source)

                override fun newArray(size: Int): Array<ShellResultParcel?> =
                    arrayOfNulls(size)
            }
    }
}
