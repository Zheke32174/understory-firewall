package com.ant.emichaosbg

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/**
 * AuditFusion is pure — subsystem JSON in, graded posture out, no Android — so its judgement is
 * asserted here against fabricated inputs on a plain JVM, the same discipline TrackerWatchTest
 * uses. These lock down the properties that matter: a non-run check is never an all-clear, the
 * worst finding leads, and a broken evidence chain is itself critical.
 */
class AuditFusionTest {

    private fun clean(): HashMap<String, String?> = hashMapOf(
        AuditFusion.IN_CELL to JSONObject().put("ok", true).put("security", "ok")
            .put("carrier", "Test").put("gen", "5G").toString(),
        AuditFusion.IN_WIFI to JSONObject().put("running", true).put("findings", 0)
            .put("wifiScans", 3).put("networks", 5).put("locationEnabled", true).toString(),
        AuditFusion.IN_NET to JSONObject().put("duplicateMacs", org.json.JSONArray())
            .put("httpProxy", "").put("captivePortal", false).put("vpn", true).toString(),
        AuditFusion.IN_INTEGRITY to JSONObject().put("ran", true).put("clean", true)
            .put("mapCount", 400).toString(),
        AuditFusion.IN_TRACKERS to JSONObject().put("tracked", 2)
            .put("candidates", org.json.JSONArray()).toString(),
        AuditFusion.IN_EVIDENCE to JSONObject().put("chainIntact", true).put("headMatches", true)
            .put("records", 12).put("strongBox", true).toString(),
        AuditFusion.IN_MASKING to JSONObject().put("running", true).toString(),
        AuditFusion.IN_BLE to JSONObject().put("running", true).toString()
    )

    @Test
    fun `an all-clear set grades clear at full score`() {
        val r = AuditFusion.fuse(clean(), 1000L)
        assertTrue("fusion should report ok", r.optBoolean("ok"))
        assertEquals("grade should be clear", "clear", r.optString("grade"))
        assertEquals("worst severity should be 0", 0, r.optInt("worstSev"))
        assertEquals("score should be a perfect 100", 100, r.optInt("score"))
        assertEquals("no coverage gaps", 0, r.optJSONArray("coverageGaps").length())
        assertEquals("no findings", 0, r.optJSONArray("topFindings").length())
    }

    @Test
    fun `a tracker travelling with you is critical and leads the findings`() {
        val inputs = clean()
        inputs[AuditFusion.IN_TRACKERS] = JSONObject().put("tracked", 3).put("candidates",
            org.json.JSONArray().put(JSONObject().put("following", true).put("label", "AirTag"))
        ).toString()
        val r = AuditFusion.fuse(inputs, 1000L)
        assertEquals("critical", r.optString("grade"))
        assertEquals(3, r.optInt("worstSev"))
        assertEquals("one critical counted", 1, r.optJSONObject("counts").optInt("critical"))
        val top = r.optJSONArray("topFindings").optJSONObject(0)
        assertEquals("the follower must lead the findings", "trackers", top.optString("category"))
        assertTrue("score must fall below 100", r.optInt("score") < 100)
    }

    @Test
    fun `a check that did not run is a coverage gap, never a clean pass`() {
        val inputs = clean()
        inputs.remove(AuditFusion.IN_CELL)          // absent entirely
        inputs[AuditFusion.IN_WIFI] = JSONObject().put("running", false)
            .put("why", "location off").toString()  // present but not observing
        val r = AuditFusion.fuse(inputs, 1000L)
        val gaps = r.optJSONArray("coverageGaps")
        assertEquals("two subsystems could not run", 2, gaps.length())
        assertTrue("gaps must not be counted as clean-passing checks",
            r.optInt("score") < 100)
        // A gap must never surface as a severity finding.
        val findings = r.optJSONArray("topFindings")
        for (i in 0 until findings.length())
            assertNotEquals("cell", findings.optJSONObject(i).optString("category"))
        // The gap category row must be marked not-run.
        val cats = r.optJSONArray("categories")
        var cellRan = true
        for (i in 0 until cats.length())
            if (cats.optJSONObject(i).optString("key") == "cell")
                cellRan = cats.optJSONObject(i).optBoolean("ran")
        assertFalse("the cell category must be marked as not run", cellRan)
    }

    @Test
    fun `a broken evidence chain is itself a critical finding`() {
        val inputs = clean()
        inputs[AuditFusion.IN_EVIDENCE] = JSONObject().put("chainIntact", false)
            .put("headMatches", false).put("records", 12)
            .put("likelyCause", "truncation").toString()
        val r = AuditFusion.fuse(inputs, 1000L)
        assertEquals("critical", r.optString("grade"))
        assertFalse("status must report the chain as broken",
            r.optJSONObject("status").optBoolean("evidenceChainIntact"))
    }

    @Test
    fun `an HTTP proxy on the network is treated as critical interception surface`() {
        val inputs = clean()
        inputs[AuditFusion.IN_NET] = JSONObject().put("duplicateMacs", org.json.JSONArray())
            .put("httpProxy", "10.0.0.1:8080").put("captivePortal", false)
            .put("vpn", false).toString()
        val r = AuditFusion.fuse(inputs, 1000L)
        assertEquals(3, r.optInt("worstSev"))
    }

    @Test
    fun `the result carries a versioned format tag and the injected timestamp`() {
        val r = AuditFusion.fuse(clean(), 987654L)
        assertEquals(AuditFusion.FORMAT, r.optString("format"))
        assertEquals("timestamp is injected for determinism", 987654L, r.optLong("at"))
    }
}
