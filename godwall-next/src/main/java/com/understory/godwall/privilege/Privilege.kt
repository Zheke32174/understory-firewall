package com.understory.godwall.privilege

import android.content.Context
import android.content.pm.PackageManager
import android.os.IBinder
import com.understory.security.Diagnostics

/**
 * Godwall's ONE privileged path, and it goes to Yojimbo.
 *
 * There is no Shizuku client here, no Dhizuku client, no `dev.rikka.shizuku`
 * dependency, no `moe.shizuku.*` permission and no `rikka.shizuku.ShizukuProvider`
 * in the manifest. Yojimbo is the suite's privilege broker; Godwall asks Yojimbo
 * and nothing else.
 *
 * Direction of the handshake (this is why there is a provider and not a
 * bindService): the privileged side is the one that owns the binder, so YOJIMBO
 * pushes it to us by calling [YojimboPrivilegeProvider]. Godwall never starts,
 * launches, or foregrounds Yojimbo to make that happen — if the binder has not
 * arrived, every privileged control in the UI says so plainly and stays disabled.
 * Nothing in Godwall's core function depends on it: the DNS filter, the encrypted
 * upstream, the per-app DNS blackhole, the egress chain and the mesh node all run
 * unprivileged.
 */
object Privilege {

    private const val TAG = "godwall.privilege"

    /** The suite app that brokers privilege. Ours — not a third-party manager. */
    const val YOJIMBO_PACKAGE = "com.understory.yojimbo"

    /** What the UI renders. Each value maps to one honest sentence. */
    enum class State {
        /** A live privileged shell is attached and answering. */
        ATTACHED,

        /** Yojimbo is installed but has not attached a shell to Godwall. */
        NOT_ATTACHED,

        /** Yojimbo is not installed on this device. */
        BROKER_ABSENT,
    }

    @Volatile
    private var shell: IPrivilegedShell? = null

    /** Set when a caller was rejected, so the UI can explain a failed handshake. */
    @Volatile
    private var lastRejection: String? = null

    private val deathRecipient = IBinder.DeathRecipient {
        Diagnostics.warn(TAG, "privileged shell died — dropping it")
        shell = null
    }

    /**
     * Accept a binder pushed by Yojimbo. Called ONLY from
     * [YojimboPrivilegeProvider], which has already verified the caller.
     */
    internal fun attach(binder: IBinder) {
        val iface = IPrivilegedShell.Stub.asInterface(binder)
        runCatching { binder.linkToDeath(deathRecipient, 0) }
            .onFailure { Diagnostics.warn(TAG, "linkToDeath refused: ${it.javaClass.simpleName}") }
        shell = iface
        lastRejection = null
        Diagnostics.log(TAG, "privileged shell attached by Yojimbo")
    }

    internal fun reject(reason: String) {
        lastRejection = reason
        Diagnostics.error(TAG, "privilege handshake REJECTED: $reason")
    }

    /** True when a shell is attached and its process is still alive. */
    fun isAvailable(): Boolean {
        val s = shell ?: return false
        val alive = runCatching { s.asBinder().isBinderAlive }.getOrDefault(false)
        if (!alive) shell = null
        return alive
    }

    fun state(context: Context): State = when {
        isAvailable() -> State.ATTACHED
        !brokerInstalled(context) -> State.BROKER_ABSENT
        else -> State.NOT_ATTACHED
    }

    /**
     * One sentence for the UI. Never instructs the user to install anything we
     * replaced, and never blames them.
     */
    fun explain(context: Context): String = when (state(context)) {
        State.ATTACHED -> "Privileged shell attached from Yojimbo."
        State.NOT_ATTACHED -> lastRejection?.let { "Yojimbo's handshake was refused: $it" }
            ?: "Yojimbo is installed but has not attached a privileged shell to Godwall. " +
            "Everything below that does not need one still works."
        State.BROKER_ABSENT -> "Yojimbo is not installed, so there is no privileged shell. " +
            "Godwall's DNS filter, encrypted upstream, per-app DNS blackhole, egress chain " +
            "and mesh node all run without one."
    }

    fun brokerInstalled(context: Context): Boolean = runCatching {
        context.packageManager.getPackageInfo(YOJIMBO_PACKAGE, 0)
        true
    }.getOrDefault(false)

    /**
     * Run [argv] at privilege. Returns an outcome ALWAYS — a missing shell is
     * reported as [ShellOutcome.unavailable], never as a thrown exception and
     * never as a silent success.
     *
     * Blocking: call off the main thread.
     */
    fun exec(argv: List<String>, timeoutMs: Long = 15_000L): ShellOutcome {
        val s = shell ?: return ShellOutcome.unavailable("No privileged shell attached.")
        return runCatching { s.exec(argv.toTypedArray(), timeoutMs) }
            .getOrElse {
                Diagnostics.error(TAG, "exec threw ${it.javaClass.simpleName}: ${it.message}")
                shell = null
                ShellOutcome.unavailable("Privileged shell call failed: ${it.javaClass.simpleName}")
            }
            ?: ShellOutcome.unavailable("Privileged shell returned nothing.")
    }

    /**
     * True iff [caller] is Yojimbo AND signed by the same certificate as us.
     * Both halves matter: the package name alone is spoofable by anything that
     * gets installed first on a device where Yojimbo is not, and a signature
     * match alone would let any suite app inject a shell.
     */
    fun callerIsYojimbo(context: Context, caller: String?): Boolean {
        if (caller != YOJIMBO_PACKAGE) return false
        val match = runCatching {
            context.packageManager.checkSignatures(caller, context.packageName)
        }.getOrDefault(PackageManager.SIGNATURE_UNKNOWN_PACKAGE)
        return match == PackageManager.SIGNATURE_MATCH
    }
}
