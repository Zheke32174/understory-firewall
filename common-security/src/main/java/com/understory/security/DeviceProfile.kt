package com.understory.security

import android.os.Build

/**
 * OEM detection. Used for surfacing manufacturer-specific guidance and
 * adjusting the UI flow — not for any security decision. Tamper / hardening
 * code paths run identically on every device.
 */
object DeviceProfile {

    fun isSamsung(): Boolean = matches("samsung")
    fun isXiaomi(): Boolean = matches("xiaomi") || matches("redmi") || matches("poco")
    fun isPixel(): Boolean = matches("google")
    fun isHuawei(): Boolean = matches("huawei") || matches("honor")
    fun isOnePlus(): Boolean = matches("oneplus")
    fun isMotorola(): Boolean = matches("motorola") || matches("lenovo")

    private fun matches(name: String): Boolean =
        Build.MANUFACTURER.equals(name, ignoreCase = true) ||
            Build.BRAND.equals(name, ignoreCase = true)

    /**
     * True on devices known to expose a primary + additional autofill slot pair
     * in their system settings. Samsung One UI does this; stock Android does not.
     */
    fun supportsDualAutofillSlots(): Boolean = isSamsung()
}
