package com.ant.emichaosbg

import android.content.Context
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * PRIVILEGE-ESCALATION AND CODE-INJECTION DETECTION, scoped to this process.
 *
 * WHAT THIS IS FOR. Not "refuse to run on a rooted phone" — that is a different and mostly
 * useless thing, it punishes the owner for controlling their own device and stops no attacker.
 * This looks for the opposite situation: someone ELSE escalating against this app. Code
 * injected into our address space, a tracer attached to our process, the sandbox not being
 * enforced, a payload loaded from memory with no file on disk. That last case is what
 * "obfuscated rootkit" actually looks like in practice, and it is the one a signature scan
 * never finds.
 *
 * EVERYTHING HERE READS ONLY OUR OWN PROCESS. the /proc/self entries, our own package metadata, our own
 * mounts. It never inspects other apps, and on modern Android it could not anyway — hidepid
 * makes other processes' /proc unreadable. That limit is also the correct scope: the question
 * is "has anything got inside THIS app", not "what else is on the phone".
 *
 * IT REPORTS AND NEVER BLOCKS. No self-kill, no feature lockout, no "integrity failed, exiting".
 * Retaliation is trivially bypassed by anyone who has already achieved injection, and a false
 * positive would brick a masking session the user may be relying on. A finding costs a
 * notification and a line in the encrypted log. That is the whole response, deliberately.
 *
 * WHY NATIVE. Same reason the scan engine moved: these checks are worthless if the thing being
 * attacked can be told to stop reporting. They run in Kotlin, commit findings straight to
 * [SecureLog], and hand the WebView a read-only view.
 *
 * HONEST LIMITS, stated because a security readout that overstates itself is worse than none:
 * an attacker with kernel-level control can defeat every check below — they can lie about
 * /proc, hide mappings, and forge the answers. This raises the cost of a QUIET compromise; it
 * does not prove absence of one. Each finding says what was observed rather than asserting a
 * verdict, because several of these have legitimate causes.
 */
class EscalationGuard(private val ctx: Context, private val log: SecureLog) {

    private var lastReport: JSONObject? = null
    private var lastRunAt = 0L
    private val raised = HashMap<String, Long>()
    private val COALESCE_MS = 10 * 60_000L      // findings here are sticky; don't re-log every scan

    /** Runs every check and commits anything notable. Cheap enough to call on a slow cadence. */
    @Synchronized
    fun scan(): String {
        val o = JSONObject()
        val findings = JSONArray()
        fun flag(sev: Int, key: String, what: String) {
            findings.put(JSONObject().put("sev", sev).put("key", key).put("what", what))
            val now = System.currentTimeMillis()
            val prev = raised[key]
            if (prev != null && now - prev < COALESCE_MS) return
            raised[key] = now
            try { log.append(sev, what, "escalation", "native") } catch (_: Throwable) {}
        }

        // ---- 1. Tracer attached to our process -------------------------------------------
        // A non-zero TracerPid means something is ptrace-attached RIGHT NOW: a debugger, or an
        // injector using ptrace to write into our memory. Normal for a dev build under a
        // debugger; on a user's device it is not expected.
        val tracer = readTracerPid()
        o.put("tracerPid", tracer)
        if (tracer > 0) flag(3, "tracer",
            "Another process is ptrace-attached to this app (TracerPid $tracer). That is the " +
            "mechanism a debugger or a code injector uses to read and write this app's memory. " +
            "Expected only if you attached a debugger yourself.")

        // ---- 2. Address-space inspection --------------------------------------------------
        val maps = readMaps()
        o.put("mapCount", maps.size)

        // W^X: a page that is BOTH writable and executable. Normal Android code never needs
        // this — the linker maps code r-xp. It is how injected shellcode and JIT-ed payloads
        // live. The ART JIT does produce some, so this is reported with that caveat, not
        // asserted as compromise.
        val wx = maps.filter { it.perms.startsWith("rwx") }
        o.put("wxRegions", wx.size)
        if (wx.isNotEmpty()) {
            val sample = wx.take(3).joinToString(", ") { it.path.ifBlank { "[anonymous]" } }
            flag(2, "wx",
                "${wx.size} memory region(s) mapped writable AND executable ($sample). Normal " +
                "code is mapped read-execute; writable-executable pages are how injected code " +
                "runs. The ART JIT can legitimately produce some, so this is a pointer to look " +
                "closer rather than proof of injection.")
        }

        // Executable mappings with NO file behind them, or backed by memfd/deleted files. This
        // is the obfuscated-rootkit shape: code that was never written to disk, so nothing can
        // scan it as a file and nothing survives to be found afterwards.
        val ghost = maps.filter {
            it.perms.contains('x') &&
                (it.path.startsWith("memfd:") || it.path.endsWith("(deleted)") ||
                 it.path.contains("/dev/ashmem"))
        }
        o.put("fileless", ghost.size)
        if (ghost.isNotEmpty()) flag(3, "fileless",
            "${ghost.size} executable memory region(s) have no file on disk behind them " +
            "(${ghost.take(2).joinToString(", ") { it.path }}). Code loaded from memory leaves " +
            "nothing to scan and nothing behind afterwards, which is the usual shape of an " +
            "in-memory implant.")

        // Native libraries loaded from paths an app's own libraries never come from. Our .so
        // files live in the APK or in /data/app/<us>/lib. Anything executable out of
        // /data/local/tmp, /sdcard or another package's directory was put there to be injected.
        val foreign = maps.filter { m ->
            m.perms.contains('x') && m.path.endsWith(".so") && SUSPECT_LIB_DIRS.any { m.path.startsWith(it) }
        }.map { it.path }.distinct()
        o.put("foreignLibs", JSONArray(foreign))
        if (foreign.isNotEmpty()) flag(3, "foreign-lib",
            "Native librar${if (foreign.size == 1) "y" else "ies"} loaded into this app from a " +
            "location apps do not load from: ${foreign.take(3).joinToString(", ")}. Libraries " +
            "staged in world-writable or shell-owned directories are the standard way to inject " +
            "a hook into another process.")

        // Known zygote-injection frameworks, by the traces they leave in OUR address space.
        // Their presence means arbitrary code can be run inside this app by design.
        val hooks = maps.map { it.path }.filter { p ->
            HOOK_MARKERS.any { p.contains(it, ignoreCase = true) }
        }.distinct()
        o.put("hookFrameworks", JSONArray(hooks))
        if (hooks.isNotEmpty()) flag(3, "hook-framework",
            "A code-injection framework is mapped into this app " +
            "(${hooks.take(3).joinToString(", ")}). Frameworks of this kind exist to run " +
            "arbitrary code inside other applications, so anything this app reports — including " +
            "these checks — can be altered by whatever is using it.")

        // ---- 3. Is the sandbox even being enforced? ---------------------------------------
        // /sys/fs/selinux/enforce is not world-readable on many builds, so a bare "unknown"
        // was the common answer and told the user nothing. Fall back to this process's own
        // security context, which IS readable: a context like u:r:untrusted_app:s0 proves
        // SELinux is present and labelling us even when the enforce node is not readable.
        // "Not readable" and "not enforcing" are very different claims and must not collapse
        // into one word.
        val se = readText("/sys/fs/selinux/enforce")?.trim()
        val selfCtx = readText("/proc/self/attr/current")?.trim()?.trim('\u0000')
        o.put("selinuxContext", selfCtx ?: "")
        o.put("selinux", when {
            se == "1" -> "enforcing"
            se == "0" -> "permissive"
            !selfCtx.isNullOrBlank() && selfCtx.contains(":r:") ->
                "labelled (enforce flag not readable)"
            else -> "not readable"
        })
        if (se == "0") flag(3, "selinux",
            "SELinux is PERMISSIVE. The kernel is logging policy violations instead of blocking " +
            "them, so the isolation that normally keeps other apps out of this one's data is " +
            "not being enforced.")

        // ---- 4. Our own code: is it the code we shipped? -----------------------------------
        // If sourceDir is not under /data/app, something has substituted the running package.
        val src = try { ctx.applicationInfo.sourceDir } catch (_: Throwable) { null }
        o.put("sourceDir", src ?: "unknown")
        if (src != null && !src.startsWith("/data/app/") && !src.startsWith("/system/")) flag(3, "apk-path",
            "This app is running from an unexpected location ($src) rather than the normal " +
            "install path. That is what a substituted or overlaid package looks like.")

        // Writable APK: our own code should never be writable by us at runtime.
        if (src != null) {
            val w = try { File(src).canWrite() } catch (_: Throwable) { false }
            o.put("apkWritable", w)
            if (w) flag(3, "apk-writable",
                "This app's own APK is writable by the running process. Installed code is " +
                "read-only on a healthy device; a writable one can be modified in place.")
        }

        // ---- 5. Mount-level hiding ---------------------------------------------------------
        // An overlay or bind mount landing on system paths is how a rootkit presents a
        // different filesystem to some processes than to others.
        val sus = readLines("/proc/self/mounts").filter { line ->
            val parts = line.split(' ')
            val fs = parts.getOrNull(2) ?: return@filter false
            val at = parts.getOrNull(1) ?: return@filter false
            if (fs != "overlay" && fs != "tmpfs") return@filter false
            if (!SENSITIVE_MOUNTS.any { at.startsWith(it) }) return@filter false
            // EXCLUDE THE UNIVERSAL ONES. /apex is tmpfs on every modern Android device by
            // design — that is how APEX modules are mounted — so flagging it means flagging
            // stock Android. A detector that fires on an unmodified phone teaches the user to
            // ignore the panel, which costs more than the check was ever worth.
            !BENIGN_MOUNTS.any { at == it || at.startsWith("$it/") }
        }
        o.put("suspiciousMounts", sus.size)
        if (sus.isNotEmpty()) flag(2, "mount",
            "${sus.size} overlay/tmpfs mount(s) are covering system paths " +
            "(${sus.take(2).joinToString("; ") { it.take(70) }}). Overlaying system directories " +
            "lets a process be shown a different filesystem than the real one. Some custom ROMs " +
            "and module systems do this legitimately; it is reported, not judged.")

        o.put("findings", findings)
        o.put("count", findings.length())
        o.put("checkedAt", System.currentTimeMillis())
        o.put("clean", findings.length() == 0)
        o.put("ran", true)
        o.put("note", "Reports only. Nothing here blocks, kills or degrades the app. An attacker " +
            "with kernel control can defeat every check above — this raises the cost of a quiet " +
            "compromise, it does not prove there isn't one.")
        lastReport = o
        lastRunAt = System.currentTimeMillis()
        return o.toString()
    }

    /**
     * NEVER-RUN IS NOT CLEAN.
     *
     * `ran:false, clean:false` — a detector that has made ZERO observations of tracer
     * attachment, W^X pages, fileless execution, injected libraries or hook frameworks must not
     * be renderable as an all-clear. The Device screen branches on `ran` and says "not yet run"
     * in those words.
     */
    fun cached(): String = (lastReport ?: JSONObject()
        .put("ran", false)
        .put("clean", false)
        .put("ok", false)
        .put("count", 0)
        .put("reason", "not yet run")
        .put("note", "This check has not run yet. That is NOT an all-clear — nothing has been " +
            "looked at. Open Device > Process integrity and press Scan now, or leave the "+
            "sentinel running and it will run on its own timer.")).toString()

    // ------------------------------------------------------------------ helpers

    private data class MapEntry(val perms: String, val path: String)

    private fun readMaps(): List<MapEntry> = try {
        File("/proc/self/maps").useLines { seq ->
            seq.mapNotNull { line ->
                // addr perms offset dev inode  path
                val p = line.split(Regex("\\s+"), limit = 6)
                if (p.size < 5) null
                else MapEntry(p[1], if (p.size >= 6) p[5].trim() else "")
            }.toList()
        }
    } catch (_: Throwable) { emptyList() }

    private fun readTracerPid(): Int = try {
        File("/proc/self/status").useLines { seq ->
            seq.firstOrNull { it.startsWith("TracerPid:") }
                ?.substringAfter(':')?.trim()?.toIntOrNull() ?: 0
        }
    } catch (_: Throwable) { 0 }

    private fun readText(path: String): String? =
        try { File(path).takeIf { it.canRead() }?.readText() } catch (_: Throwable) { null }

    private fun readLines(path: String): List<String> =
        try { File(path).takeIf { it.canRead() }?.readLines() ?: emptyList() }
        catch (_: Throwable) { emptyList() }

    companion object {
        private val SUSPECT_LIB_DIRS = listOf(
            "/data/local/tmp", "/sdcard", "/storage/emulated", "/data/misc", "/tmp", "/cache"
        )
        // Matched against paths already mapped into THIS process, not scanned for on disk —
        // the question is whether one is inside us, not whether one exists on the device.
        private val HOOK_MARKERS = listOf(
            "frida", "gadget", "substrate", "xposed", "lsposed", "riru", "zygisk",
            "edxposed", "dobby", "shadowhook", "whale"
        )
        private val SENSITIVE_MOUNTS = listOf("/system", "/vendor", "/apex", "/product")
        /** Mount points that are tmpfs/overlay on stock Android and therefore say nothing. */
        private val BENIGN_MOUNTS = listOf("/apex", "/system/apex")
    }
}
