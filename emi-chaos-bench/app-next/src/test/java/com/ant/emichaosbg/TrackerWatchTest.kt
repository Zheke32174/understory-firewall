package com.ant.emichaosbg

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/**
 * The follow heuristic decides whether to tell someone they are being tracked. Getting it wrong
 * in either direction is costly — a false negative misses a real stalker, a false positive
 * accuses someone's own earbuds — so the thresholds are tested directly rather than inferred
 * from the UI. SecureLog is not exercised here; append failures are swallowed by design, so the
 * verdicts in stats() are what these assert against.
 */
class TrackerWatchTest {

    private fun dev(addr: String, mfgId: String? = null, hex: String = "", rssi: Int = -60): JSONObject {
        val o = JSONObject().put("address", addr).put("rssi", rssi)
        if (mfgId != null) o.put("mfg", JSONObject().put(mfgId, hex))
        return o
    }

    private fun batch(vararg d: JSONObject) = JSONArray().apply { d.forEach { put(it) } }.toString()

    /** Roughly 1.1km north per 0.01 degrees of latitude. */
    private fun lat(base: Double, km: Double) = base + km / 111.0

    /** Collects findings instead of writing them, so assertions can read them directly. */
    private val found = ArrayList<Triple<Int, String, String>>()
    private fun watch() = TrackerWatch { s, m, b -> found.add(Triple(s, m, b)) }

    @Test
    fun `a stationary beacon passed once is not a follower`() {
        val w = watch()
        // Seen many times, but the phone never moved.
        repeat(10) { w.ingest(batch(dev("AA:1", "76", "12ff")), 51.5000, -0.1200) }
        val s = JSONObject(w.stats())
        val c = s.getJSONArray("candidates")
        assertTrue("should be tracked", c.length() >= 1)
        assertFalse("no displacement => not following", c.getJSONObject(0).getBoolean("following"))
    }

    @Test
    fun `a device seen once far away is not a follower`() {
        val w = watch()
        w.ingest(batch(dev("BB:1", "76", "12aa")), 51.5000, -0.12)
        w.ingest(batch(dev("BB:1", "76", "12aa")), lat(51.5000, 5.0), -0.12)
        val c = JSONObject(w.stats()).getJSONArray("candidates")
        // Only two sessions — displacement alone must not be enough.
        if (c.length() > 0) assertFalse("2 sessions => not following", c.getJSONObject(0).getBoolean("following"))
    }

    @Test
    fun `persistent AND displaced is a follower`() {
        val w = watch()
        // Eight sessions while travelling several km.
        for (i in 0 until 8) w.ingest(batch(dev("CC:1", "76", "12bb")), lat(51.5, i * 0.4), -0.12)
        val c = JSONObject(w.stats()).getJSONArray("candidates")
        assertEquals(1, c.length())
        val o = c.getJSONObject(0)
        assertTrue("both thresholds met => following", o.getBoolean("following"))
        assertEquals("Apple Find My / AirTag", o.getString("label"))
        assertTrue("displacement recorded", o.getInt("movedM") > 500)
    }

    @Test
    fun `MAC rotation is correlated by payload, not address`() {
        val w = watch()
        // Same payload, a different address every time — what a real tracker does.
        for (i in 0 until 8) w.ingest(batch(dev("DD:$i", "76", "12cc")), lat(51.5, i * 0.4), -0.12)
        val c = JSONObject(w.stats()).getJSONArray("candidates")
        assertEquals("rotation must collapse to ONE identity, not eight", 1, c.length())
        val o = c.getJSONObject(0)
        assertEquals(8, o.getInt("addresses"))
        assertTrue("still detected as following through rotation", o.getBoolean("following"))
    }

    @Test
    fun `devices with no payload stay separate identities`() {
        val w = watch()
        // No manufacturer data — cannot be correlated, so each address is its own identity.
        for (i in 0 until 4) w.ingest(batch(dev("EE:$i")), 51.5, -0.12)
        val s = JSONObject(w.stats())
        assertEquals(4, s.getInt("tracked"))
    }

    @Test
    fun `vendor fingerprints are read from manufacturer data`() {
        val w = watch()
        for (i in 0 until 6) w.ingest(batch(dev("FF:1", "117", "abcd")), lat(51.5, i * 0.4), -0.12)
        val c = JSONObject(w.stats()).getJSONArray("candidates")
        assertEquals("Samsung SmartTag", c.getJSONObject(0).getString("label"))
    }

    @Test
    fun `a whole sweep counts as one session, not many sightings`() {
        val w = watch()
        // One sweep reporting the same device repeatedly must not inflate persistence.
        val many = JSONArray().apply { repeat(20) { put(dev("GG:1", "76", "12dd")) } }.toString()
        w.ingest(many, 51.5, -0.12)
        val c = JSONObject(w.stats()).getJSONArray("candidates")
        if (c.length() > 0) assertEquals("one ingest == one session", 1, c.getJSONObject(0).getInt("sessions"))
    }

    @Test
    fun `no location fix still tracks but never claims a follow`() {
        val w = watch()
        for (i in 0 until 10) w.ingest(batch(dev("HH:1", "76", "12ee")), Double.NaN, Double.NaN)
        val c = JSONObject(w.stats()).getJSONArray("candidates")
        assertTrue(c.length() >= 1)
        assertFalse("no fix => displacement unknown => never 'following'",
            c.getJSONObject(0).getBoolean("following"))
    }
}
