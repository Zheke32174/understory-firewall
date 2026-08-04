package com.ant.emichaosbg

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/**
 * CaseReport is pure (strings in, strings out), so the two properties that make it trustworthy —
 * it EMBEDS the vault's own verify() rather than re-deriving an integrity claim, and it escapes
 * attacker-influenceable finding text before it reaches the HTML — are asserted here on the JVM.
 */
class CaseReportTest {

    private fun meta() = JSONObject().put("app", "EMI Chaos Bench")
        .put("appVersion", "3.9-audit").put("device", "Test Model").put("sdk", 34)

    private fun posture() = JSONObject()
        .put("ok", true).put("grade", "elevated").put("score", 74)
        .put("counts", JSONObject().put("critical", 0).put("warning", 1).put("info", 0).put("gaps", 1))
        .put("categories", JSONArray().put(JSONObject()
            .put("key", "wifi").put("title", "Wi-Fi").put("ran", true).put("sev", 2)
            .put("status", "1 heuristic flag(s) raised").put("detail", "3 scans")))
        .put("topFindings", JSONArray())
        .put("coverageGaps", JSONArray())
        .toString()

    @Test
    fun `json bundle carries the format tag and embeds the vault verification verbatim`() {
        val verify = JSONObject().put("chainIntact", true).put("headMatches", true)
            .put("records", 9).put("likelyCause", "TOKEN_UNIQUE_MARKER").toString()
        val out = CaseReport.buildJson(posture(), verify, meta(), 1000L)
        val o = JSONObject(out)
        assertEquals(CaseReport.FORMAT, o.optString("format"))
        assertTrue("the report must embed the vault's OWN verify() output, not a re-derived claim",
            o.optJSONObject("integrity").optString("likelyCause") == "TOKEN_UNIQUE_MARKER")
        assertTrue("a bundle without a redaction statement is not safe to hand over",
            o.optString("redaction").contains("location-free"))
        assertNotNull("the posture must be embedded too", o.optJSONObject("posture"))
    }

    @Test
    fun `html report states the integrity verdict from the embedded verification`() {
        val verify = JSONObject().put("chainIntact", true).put("headMatches", true)
            .put("records", 9).put("strongBox", true).toString()
        val html = CaseReport.buildHtml(posture(), verify, meta(), 1000L)
        assertTrue("a verified chain must read VERIFIED", html.contains("VERIFIED"))
        assertTrue("the grade must appear in the report", html.contains("elevated"))
        assertTrue("the app version must appear", html.contains("3.9-audit"))
    }

    @Test
    fun `a broken chain reads BROKEN in the html report`() {
        val verify = JSONObject().put("chainIntact", false).put("headMatches", false)
            .put("records", 9).put("likelyCause", "truncation").toString()
        val html = CaseReport.buildHtml(posture(), verify, meta(), 1000L)
        assertTrue("a broken chain must read BROKEN, not verified", html.contains("BROKEN"))
    }

    @Test
    fun `attacker-influenceable finding text is html-escaped`() {
        // A scanned SSID or /proc path can carry markup; it must never reach the document raw.
        val hostile = "<script>alert('x')</script>"
        val p = JSONObject(posture())
        p.put("topFindings", JSONArray().put(JSONObject()
            .put("sev", 2).put("category", "wifi").put("text", hostile)))
        val html = CaseReport.buildHtml(p.toString(),
            JSONObject().put("chainIntact", true).put("headMatches", true).toString(), meta(), 1000L)
        assertFalse("hostile markup must not appear raw in the report", html.contains(hostile))
        assertTrue("hostile markup must appear escaped", html.contains("&lt;script&gt;"))
    }
}
