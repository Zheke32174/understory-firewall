package com.understory.elevation.shizuku

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.os.IBinder
import com.understory.elevation.IShellService
import com.understory.elevation.ShellResult
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import rikka.shizuku.Shizuku

/**
 * Owns the bound Shizuku [ShellUserService] connection for the process and
 * exposes a single suspend [exec]. Binding is lazy and cached: the first
 * privileged command triggers a bind, subsequent commands reuse the live
 * binder. A [Mutex] serializes bind attempts so concurrent callers don't spawn
 * duplicate services.
 *
 * All of this is inert unless Shizuku is installed, running, and this app's
 * Shizuku permission is granted — the [Elevation] broker gates on that before
 * ever calling here.
 */
internal object ShizukuShell {

    private const val BIND_TIMEOUT_MS = 10_000L

    private val bindMutex = Mutex()

    @Volatile
    private var service: IShellService? = null

    @Volatile
    private var pendingBind: CompletableDeferred<IShellService?>? = null

    private val userServiceArgs: Shizuku.UserServiceArgs
        get() = Shizuku.UserServiceArgs(
            ComponentName(appPackage, ShellUserService::class.java.name),
        )
            .daemon(false)
            .processNameSuffix("elev-shell")
            .version(1)
            .debuggable(false)

    // Captured at first use so the args can name the correct app package.
    @Volatile
    private var appPackage: String = ""

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val svc = binder?.let {
                if (it.pingBinder()) IShellService.Stub.asInterface(it) else null
            }
            service = svc
            pendingBind?.complete(svc)
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            service = null
        }
    }

    /**
     * Run [cmd] through the bound shell service, binding on first use.
     * [timeoutMs] bounds the command itself (0 = no command timeout). Returns
     * null only if the service could not be bound within [BIND_TIMEOUT_MS].
     */
    suspend fun exec(ctx: Context, cmd: List<String>, timeoutMs: Long): ShellResult? {
        appPackage = ctx.packageName
        val svc = ensureBound() ?: return null
        val parcel = svc.runCommand(cmd.toTypedArray(), timeoutMs)
        return ShellResult(parcel.exit, parcel.out, parcel.err)
    }

    private suspend fun ensureBound(): IShellService? {
        service?.let { if (it.asBinder().pingBinder()) return it }
        return bindMutex.withLock {
            service?.let { if (it.asBinder().pingBinder()) return it }
            val deferred = CompletableDeferred<IShellService?>()
            pendingBind = deferred
            try {
                Shizuku.bindUserService(userServiceArgs, connection)
            } catch (t: Throwable) {
                deferred.complete(null)
                return null
            }
            withTimeoutOrNull(BIND_TIMEOUT_MS) { deferred.await() }
        }
    }
}
