package com.understory.security.nav

import androidx.compose.runtime.mutableStateListOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The back contract, pinned. These are the three defects that were reported on device, written
 * as tests so they cannot come back silently:
 *
 *  - back from a sub-sub-menu must step up ONE level, not jump to main
 *  - back at a side tab must go home, not leave the app
 *  - back at the home root must minimize, never finish
 *
 * [SuiteNav]'s internal constructor takes a nullable Activity, so the whole contract is
 * exercisable off-device: a null activity makes [SuiteNav.minimize] a no-op, and "did we reach
 * minimize?" is observable as "the stack stopped changing while at the home root".
 */
class SuiteNavTest {

    private fun nav(home: String = "HOME", vararg rest: String): SuiteNav {
        val stack = mutableStateListOf(home).apply { addAll(rest) }
        return SuiteNav(stack, home = home, activity = null, tag = "test.nav")
    }

    // ---- defect 2: "it returns to its main menu from every menu. even sub sub menus." ----

    @Test
    fun `back from a sub-sub-menu pops exactly one level`() {
        val n = nav("HOME", "APPS", "INSPECTOR", "ELEVATION")

        n.back()
        assertEquals("INSPECTOR", n.current)
        n.back()
        assertEquals("APPS", n.current)
        n.back()
        assertEquals("HOME", n.current)
    }

    @Test
    fun `push then back is an identity round trip at any depth`() {
        val n = nav()
        listOf("A", "B", "C", "D", "E").forEach { n.push(it) }
        assertEquals(6, n.depth)
        repeat(5) { n.back() }
        assertEquals("HOME", n.current)
        assertEquals(1, n.depth)
    }

    // ---- defect 1: "many close when exited instead of minimizing" ----

    @Test
    fun `back at the home root does not pop and does not change the stack`() {
        val n = nav()
        assertTrue(n.atHomeRoot)

        n.back() // would be minimize() on a real Activity; must never mutate the stack

        assertEquals("HOME", n.current)
        assertEquals(1, n.depth)
        assertTrue(n.atHomeRoot)
    }

    @Test
    fun `pop reports false at a tab root so the host can fall through to minimize`() {
        val n = nav()
        assertFalse(n.canPop)
        assertFalse(n.pop())
    }

    // ---- bottom-nav semantics ----

    @Test
    fun `back at a side tab root returns to home rather than leaving the app`() {
        val n = nav()
        n.selectTab("FLEET")
        assertEquals("FLEET", n.current)
        assertEquals(1, n.depth)

        n.back()

        assertEquals("HOME", n.current)
        assertTrue(n.atHomeRoot)
    }

    @Test
    fun `selecting a tab replaces the stack instead of extending it`() {
        val n = nav()
        n.push("APPS")
        n.push("INSPECTOR")
        assertEquals(3, n.depth)

        n.selectTab("LEDGER")

        // A lateral move: the old descent is gone, so back from here means "home", not
        // "retrace three screens of a tab the user already left".
        assertEquals(1, n.depth)
        assertEquals("LEDGER", n.current)
    }

    @Test
    fun `deep inside a side tab, back walks up that tab before returning home`() {
        val n = nav()
        n.selectTab("PATCH")
        n.push("PATCH_DETAIL")
        n.push("PATCH_APPLY")

        n.back()
        assertEquals("PATCH_DETAIL", n.current)
        n.back()
        assertEquals("PATCH", n.current)
        n.back()
        assertEquals("HOME", n.current) // only now does it leave the tab
        assertTrue(n.atHomeRoot)
    }

    // ---- guards ----

    @Test
    fun `re-pushing the current route is a no-op so a double tap cannot stack duplicates`() {
        val n = nav()
        n.push("APPS")
        n.push("APPS")
        n.push("APPS")
        assertEquals(2, n.depth)

        n.back()
        assertEquals("HOME", n.current)
    }

    @Test
    fun `re-selecting the current tab at its root is a no-op`() {
        val n = nav()
        n.selectTab("HOME")
        assertEquals(1, n.depth)
        assertEquals("HOME", n.current)
    }

    @Test
    fun `re-selecting the current tab from a descendant returns to that tab root`() {
        val n = nav()
        n.selectTab("APPS")
        n.push("INSPECTOR")

        n.selectTab("APPS") // tapping the active tab again is the standard "go to top" gesture

        assertEquals(1, n.depth)
        assertEquals("APPS", n.current)
    }

    @Test
    fun `popTo collapses to an ancestor`() {
        val n = nav("HOME", "APPS", "INSPECTOR", "ELEVATION")
        n.popTo("APPS")
        assertEquals("APPS", n.current)
        assertEquals(2, n.depth)
    }

    @Test
    fun `popTo an absent route leaves the stack untouched`() {
        val n = nav("HOME", "APPS", "INSPECTOR")
        n.popTo("NOT_ON_STACK")
        assertEquals("INSPECTOR", n.current)
        assertEquals(3, n.depth)
    }

    @Test
    fun `popTo the current route is a no-op rather than dropping it`() {
        val n = nav("HOME", "APPS")
        n.popTo("APPS")
        assertEquals("APPS", n.current)
        assertEquals(2, n.depth)
    }

    @Test
    fun `trail exposes the descent oldest-first for breadcrumbs`() {
        val n = nav()
        n.selectTab("APPS")
        n.push("INSPECTOR")
        assertEquals(listOf("APPS", "INSPECTOR"), n.trail)
    }

    @Test
    fun `currentAs resolves a typed route and returns null for an unknown name`() {
        val n = nav()
        n.push(Fixture.SECOND)
        assertEquals(Fixture.SECOND, n.currentAs<Fixture>())

        n.push("A_ROUTE_FROM_A_FUTURE_VERSION")
        assertEquals(null, n.currentAs<Fixture>())
    }

    private enum class Fixture { FIRST, SECOND }
}
