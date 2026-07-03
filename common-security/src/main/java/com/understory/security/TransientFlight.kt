package com.understory.security

/**
 * Process-wide flag for "we're round-tripping through another activity
 * (typically a SAF picker) and the lifecycle hooks should treat this as
 * transient flight, not as backgrounding the user."
 *
 * Used by activities to suppress on-resume hardening re-checks (Tamper,
 * SuiteAttestation) that can self-inflict a denial-of-service when one of
 * the probes transiently misreports during a foreground transition. The
 * onCreate check is the authoritative gate; resume-time re-checks are a
 * defense-in-depth that should yield to the picker round-trip.
 *
 * Usage from the launcher caller:
 *
 *     SecureButton(onClick = {
 *         TransientFlight.begin()
 *         runCatching { picker.launch(...) }
 *             .onFailure { TransientFlight.end() }
 *     }) { Text("Pick file") }
 *
 *     val picker = rememberLauncherForActivityResult(...) { result ->
 *         TransientFlight.end()
 *         // ... handle result
 *     }
 *
 * The pattern is symmetric with passgen / aegis's per-vault transient-
 * flight counters but lives in common-security because it's about
 * activity-lifecycle hardening, not vault state.
 */
object TransientFlight {

    @Volatile
    private var counter: Int = 0

    /** Increment the in-flight counter. Symmetric with [end]. */
    fun begin() {
        synchronized(this) { counter++ }
    }

    /** Decrement the in-flight counter. Safe to call when not in flight
     *  (clamps at zero) so cancellation and double-end paths converge. */
    fun end() {
        synchronized(this) {
            if (counter > 0) counter--
        }
    }

    /** True iff at least one SAF round-trip (or equivalent) is in flight. */
    fun isActive(): Boolean = counter > 0
}
