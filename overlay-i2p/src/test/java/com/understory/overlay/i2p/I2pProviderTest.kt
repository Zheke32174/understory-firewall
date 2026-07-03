package com.understory.overlay.i2p

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the curated [I2pProvider] catalog. Same role and shape as
 * firewall/DnsProvider — these are the entries the UI offers, so the
 * catalog's structural invariants matter for the UX:
 *   - byId fallback to a safe default when an unknown id is stored
 *   - all entries have unique ids (UI keys assume uniqueness)
 *   - reseed URLs are HTTPS (cleartext reseed leaks router fingerprint)
 *   - the no-outproxy variants honestly carry empty outproxyHost
 */
class I2pProviderTest {

    @Test
    fun all_containsExpectedEntries() {
        val ids = I2pProvider.ALL.map { it.id }.toSet()
        // The catalog is intentionally short; pin the current set so a
        // future addition or removal forces an update of UI documentation.
        assertEquals(
            setOf("eepsites_only", "stormycloud", "diva", "i2p_projekt", "custom"),
            ids,
        )
    }

    @Test
    fun all_idsAreUnique() {
        val ids = I2pProvider.ALL.map { it.id }
        assertEquals("ids must be unique across catalog", ids.size, ids.toSet().size)
    }

    @Test
    fun all_namesAreNonEmpty() {
        for (p in I2pProvider.ALL) {
            assertTrue("provider ${p.id} has empty name", p.name.isNotBlank())
        }
    }

    @Test
    fun byId_returnsExactMatch() {
        for (p in I2pProvider.ALL) {
            assertSame("byId(${p.id}) should return same instance", p, I2pProvider.byId(p.id))
        }
    }

    @Test
    fun byId_unknownFallsBackToEepsitesOnly() {
        // Safe-default contract: if a stored id is no longer in the
        // catalog (e.g. user upgrades and we removed an entry), the UI
        // must not crash; it falls back to the safest entry (no
        // outproxy, no exit-operator trust required).
        assertSame(I2pProvider.EEPSITES_ONLY, I2pProvider.byId("nonexistent"))
        assertSame(I2pProvider.EEPSITES_ONLY, I2pProvider.byId(""))
    }

    @Test
    fun reseedUrls_areHttps() {
        // A cleartext reseed leaks the fact that the device is bringing
        // up an I2P router — the whole point of overlay anonymity is
        // undermined if the bootstrap is observable. Pin HTTPS.
        for (p in I2pProvider.ALL) {
            // CUSTOM is a placeholder; the user fills in their own URL.
            // Skip it from the HTTPS check — it's documented power-user
            // surface and the entry text says "you're responsible."
            if (p.id == "custom") continue
            assertTrue(
                "${p.id} reseed must be HTTPS, got ${p.reseedUrl}",
                p.reseedUrl.startsWith("https://"),
            )
        }
    }

    @Test
    fun noOutproxyVariants_haveEmptyOutproxyHost() {
        // The "no outproxy" providers (eepsites only, i2p-projekt) must
        // carry empty outproxyHost — that's how the consumer code
        // decides whether to wire an outproxy at all. If a future edit
        // accidentally fills these in, eepsites-only mode would silently
        // start exiting traffic through someone's relay.
        assertEquals("", I2pProvider.EEPSITES_ONLY.outproxyHost)
        assertEquals("", I2pProvider.PROJEKT.outproxyHost)
    }

    @Test
    fun outproxyVariants_haveNonEmptyHost() {
        assertNotEquals("", I2pProvider.STORMYCLOUD.outproxyHost)
        assertNotEquals("", I2pProvider.DIVA_EXCHANGE.outproxyHost)
    }

    @Test
    fun privacyNotes_areNonEmpty() {
        // The privacyNote is what the UI shows below each row — empty
        // would be a posture-honesty regression. Keep this on lock.
        for (p in I2pProvider.ALL) {
            assertNotNull("provider ${p.id} privacyNote null", p.privacyNote)
            assertTrue("provider ${p.id} privacyNote blank", p.privacyNote.isNotBlank())
        }
    }

    @Test
    fun eepsitesOnly_isFirstInDisplayOrder() {
        // Display order matters: the safest entry should be first so a
        // user picking blindly lands on it.
        assertSame(I2pProvider.EEPSITES_ONLY, I2pProvider.ALL.first())
    }
}
