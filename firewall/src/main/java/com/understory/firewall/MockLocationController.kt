package com.understory.firewall

import android.content.Context
import android.location.Location
import android.location.LocationManager
import android.os.SystemClock
import com.understory.elevation.Elevation
import com.understory.elevation.NotElevated
import com.understory.elevation.Outcome
import com.understory.security.Diagnostics
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.cos
import kotlin.random.Random

/**
 * Location-privacy tool (NOT a network control). Feeds a fixed (optionally
 * jittered) GPS point to the OS via the LocationManager test-provider API, so
 * apps that read location see the coordinate you chose instead of your real
 * position.
 *
 * HONEST BY CONSTRUCTION:
 *  - This only works while THIS app holds the single OS "mock location app"
 *    slot. That slot is granted either from Developer Options ("Select mock
 *    location app") or by the `appops set … android:mock_location allow` shell
 *    (Shizuku). Exactly one app can hold it at a time.
 *  - Every entry point tolerates failure and returns a typed result or a plain
 *    boolean; NOTHING here throws to the UI. When the slot isn't held,
 *    [addTestProvider] raises SecurityException, which [isEnabled] reports as
 *    "not selected" and [start] surfaces as [StartResult.NotMockApp].
 *  - The feed is a coroutine loop that re-pushes the point on a fixed cadence
 *    (some consumers drop a provider that goes quiet). The foreground
 *    [MockLocationService] owns the loop's lifetime so it survives the screen
 *    being backgrounded; this object holds the mechanism.
 *
 * State (the running feed job + its params) lives only in-process here and is
 * never persisted or sent anywhere.
 */
object MockLocationController {

    private const val TAG = "firewall.MockLocationController"

    /** The two providers we drive. GPS is the one most apps read; NETWORK is
     *  pushed too so coarse-location consumers agree with the fine fix. */
    private val PROVIDERS = listOf(
        LocationManager.GPS_PROVIDER,
        LocationManager.NETWORK_PROVIDER,
    )

    /** How often the feed re-pushes the (jittered) point. */
    private const val PUSH_INTERVAL_MS = 1_000L

    /** ~metres-per-degree of latitude; longitude is scaled by cos(lat). Used to
     *  convert a metres jitter radius into a lat/lon offset. */
    private const val METERS_PER_DEG_LAT = 111_320.0

    private val feeding = AtomicBoolean(false)
    @Volatile private var feedScope: CoroutineScope? = null
    @Volatile private var feedJob: Job? = null

    /** True while a feed loop is actively pushing points. */
    val isFeeding: Boolean get() = feeding.get()

    /** The typed result of [start]. */
    sealed interface StartResult {
        /** The feed is running; the OS is now seeing the mock point. */
        data object Started : StartResult
        /** This app is not the selected mock-location app (SecurityException on
         *  addTestProvider). The UI must route the user to enable the slot. */
        data object NotMockApp : StartResult
        /** Coordinates were out of range; nothing was started. */
        data class InvalidCoordinates(val reason: String) : StartResult
        /** A provider call failed for another reason. */
        data class Failed(val message: String) : StartResult
    }

    /**
     * Probe whether this app currently holds the mock-location slot, without
     * starting a feed. Attempts [addTestProvider]; a SecurityException means the
     * slot is NOT held (Developer Options / appop not set). Any provider added
     * as a side effect is removed again so this stays a pure probe.
     */
    fun isEnabled(ctx: Context): Boolean {
        // Non-destructive: if a feed is already live we self-evidently hold the
        // slot, and probing (add+removeTestProvider) would tear down the running
        // GPS test provider mid-feed. Short-circuit before touching any provider.
        if (feeding.get()) return true
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return false
        val probe = LocationManager.GPS_PROVIDER
        return try {
            addProvider(lm, probe)
            // Success => we hold the slot. Clean the probe up.
            runCatching { lm.removeTestProvider(probe) }
            true
        } catch (_: SecurityException) {
            false
        } catch (t: Throwable) {
            // A provider that already exists (IllegalArgumentException) still
            // proves we hold the slot; only SecurityException means "not us".
            Diagnostics.log(TAG, "isEnabled probe non-security throwable: ${t.javaClass.simpleName}")
            true
        }
    }

    /**
     * Begin (or restart) feeding [lat]/[lon] to the OS. Validates ranges, adds +
     * enables the test providers, then launches the repeating push loop applying
     * +/- [jitterM] metres of noise when [jitterM] > 0. Never throws.
     *
     * @param accuracyM reported horizontal accuracy of each fix, in metres.
     * @param jitterM   jitter radius in metres; 0 disables jitter (a perfectly
     *                  static point, which can itself look synthetic).
     */
    fun start(
        ctx: Context,
        lat: Double,
        lon: Double,
        accuracyM: Float,
        jitterM: Float,
    ): StartResult {
        if (lat < -90.0 || lat > 90.0) {
            return StartResult.InvalidCoordinates("Latitude must be between -90 and 90.")
        }
        if (lon < -180.0 || lon > 180.0) {
            return StartResult.InvalidCoordinates("Longitude must be between -180 and 180.")
        }
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return StartResult.Failed("Location service unavailable.")

        // Stop any existing feed first so params can't overlap.
        stop(ctx)

        val safeAccuracy = if (accuracyM.isFinite() && accuracyM > 0f) accuracyM else 5f
        val safeJitter = if (jitterM.isFinite() && jitterM >= 0f) jitterM else 0f

        try {
            for (p in PROVIDERS) {
                addProvider(lm, p)
                lm.setTestProviderEnabled(p, true)
            }
        } catch (_: SecurityException) {
            // Not the selected mock app. Roll back any half-added providers.
            safeRemoveAll(lm)
            return StartResult.NotMockApp
        } catch (t: Throwable) {
            safeRemoveAll(lm)
            return StartResult.Failed(t.message ?: t.javaClass.simpleName)
        }

        val scope = CoroutineScope(Dispatchers.Default)
        feedScope = scope
        feeding.set(true)
        feedJob = scope.launch {
            while (isActive) {
                for (p in PROVIDERS) {
                    val loc = buildLocation(p, lat, lon, safeAccuracy, safeJitter)
                    try {
                        lm.setTestProviderLocation(p, loc)
                    } catch (_: SecurityException) {
                        // Slot revoked mid-feed (user changed mock app). Stop
                        // cleanly rather than spin failing forever.
                        feeding.set(false)
                        Diagnostics.log(TAG, "feed lost slot mid-push; stopping")
                        return@launch
                    } catch (t: Throwable) {
                        Diagnostics.log(TAG, "setTestProviderLocation threw: ${t.javaClass.simpleName}")
                    }
                }
                delay(PUSH_INTERVAL_MS)
            }
        }
        Diagnostics.log(TAG, "feed started lat=$lat lon=$lon acc=$safeAccuracy jitter=$safeJitter")
        return StartResult.Started
    }

    /**
     * Stop the feed and remove the test providers. Idempotent and exception-
     * tolerant: safe to call when nothing is running.
     */
    fun stop(ctx: Context) {
        feeding.set(false)
        runCatching { feedJob?.cancel() }
        feedJob = null
        feedScope = null
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as? LocationManager ?: return
        for (p in PROVIDERS) {
            runCatching { lm.setTestProviderEnabled(p, false) }
            runCatching { lm.removeTestProvider(p) }
        }
        Diagnostics.log(TAG, "feed stopped")
    }

    /**
     * Enable the mock-location slot for THIS app via the Shizuku shell, for users
     * who prefer it over toggling Developer Options:
     *   `appops set <pkg> android:mock_location allow`
     * Mapped to [Outcome]; never throws. When no Shizuku shell is granted this
     * returns [Outcome.Unsupported] so the UI can keep showing the Developer
     * Options path.
     */
    suspend fun enableViaShizuku(ctx: Context): Outcome {
        if (!Elevation.canRunShell(ctx)) {
            return Outcome.Unsupported(
                "Enabling the mock-location slot from inside the app needs Shizuku. " +
                    "Without it, use Developer Options.",
            )
        }
        return try {
            val r = Elevation.runShell(
                ctx,
                listOf("appops", "set", ctx.packageName, "android:mock_location", "allow"),
            )
            if (r.ok) {
                Outcome.Success("This app is now the mock-location app.")
            } else {
                Outcome.Failed("appops set failed (exit ${r.exit}): ${r.err.trim().take(160)}")
            }
        } catch (e: NotElevated) {
            Outcome.Unsupported(e.message ?: "not elevated")
        } catch (t: Throwable) {
            Outcome.Failed("Enabling via Shizuku failed: ${t.message ?: t.javaClass.simpleName}", t)
        }
    }

    // ---- internals ----------------------------------------------------------

    /** addTestProvider across API levels. Throws SecurityException when this app
     *  does NOT hold the mock-location slot — that is the signal callers key on. */
    private fun addProvider(lm: LocationManager, provider: String) {
        // A provider may already be registered from a prior run; treat that as
        // success (the caller's setTestProviderEnabled/Location still works).
        try {
            @Suppress("DEPRECATION")
            lm.addTestProvider(
                provider,
                false, // requiresNetwork
                false, // requiresSatellite
                false, // requiresCell
                false, // hasMonetaryCost
                true,  // supportsAltitude
                true,  // supportsSpeed
                true,  // supportsBearing
                android.location.Criteria.POWER_LOW,
                android.location.Criteria.ACCURACY_FINE,
            )
        } catch (e: SecurityException) {
            throw e
        } catch (_: IllegalArgumentException) {
            // Already added — fine.
        }
    }

    private fun safeRemoveAll(lm: LocationManager) {
        for (p in PROVIDERS) {
            runCatching { lm.setTestProviderEnabled(p, false) }
            runCatching { lm.removeTestProvider(p) }
        }
    }

    /** Build a fully-populated [Location] for [provider], applying jitter. */
    private fun buildLocation(
        provider: String,
        lat: Double,
        lon: Double,
        accuracyM: Float,
        jitterM: Float,
    ): Location {
        var useLat = lat
        var useLon = lon
        if (jitterM > 0f) {
            // Uniform offset within a jitterM-radius box, converted metres→deg.
            val dLat = (Random.nextDouble(-1.0, 1.0) * jitterM) / METERS_PER_DEG_LAT
            val cosLat = cos(Math.toRadians(lat)).let { if (it == 0.0) 1e-6 else it }
            val dLon = (Random.nextDouble(-1.0, 1.0) * jitterM) / (METERS_PER_DEG_LAT * cosLat)
            useLat = (lat + dLat).coerceIn(-90.0, 90.0)
            useLon = (lon + dLon).coerceIn(-180.0, 180.0)
        }
        return Location(provider).apply {
            latitude = useLat
            longitude = useLon
            accuracy = accuracyM
            altitude = 0.0
            speed = 0f
            bearing = 0f
            time = System.currentTimeMillis()
            elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos()
        }
    }
}
