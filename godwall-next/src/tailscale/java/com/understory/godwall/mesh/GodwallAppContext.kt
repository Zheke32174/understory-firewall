package com.understory.godwall.mesh

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import com.understory.security.Diagnostics
import libtailscale.AppContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * The app-services half of the bridge: everything Go asks the host platform for.
 *
 * Two groups of methods here, and the distinction is the whole point:
 *
 *  - **Load-bearing, implemented for real.** The state store
 *    ([encryptToPref]/[decryptFromPref]/[getStateStoreKeysJSON]) is where tailscaled
 *    persists its node key and machine identity — if it silently no-ops, the node
 *    re-registers on every start and nothing works. Same for [bindSocketToNetwork]
 *    and the interface enumeration.
 *  - **Genuinely unsupported, and honest about it.** Hardware attestation and MDM
 *    syspolicy have no Godwall equivalent. They report "unsupported"/empty rather
 *    than inventing a value — Go treats those as absent features, which is correct.
 *    Returning fake data here would make Go behave as if a capability existed.
 *
 * Storage note: prefs are used because that is the contract Go expects — the method
 * names are literally `encryptToPref` and `decryptFromPref`. The values are
 * already-encrypted blobs
 * produced by tailscaled, so this layer stores opaque ciphertext — it is not adding
 * or claiming an encryption layer of its own.
 */
internal class GodwallAppContext(
    private val ctx: Context,
) : AppContext {

    private val prefs by lazy { ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE) }

    // ---- state store (load-bearing: this is tailscaled's identity) ----

    override fun encryptToPref(key: String, value: String) {
        prefs.edit().putString(key, value).apply()
    }

    override fun decryptFromPref(key: String): String? = prefs.getString(key, null)

    override fun getStateStoreKeysJSON(): String {
        val arr = JSONArray()
        prefs.all.keys.forEach { arr.put(it) }
        return arr.toString()
    }

    // ---- platform facts ----

    override fun getOSVersion(): String = Build.VERSION.RELEASE ?: ""
    override fun getSDKInt(): Long = Build.VERSION.SDK_INT.toLong()
    /**
     * The name this node reports to the tailnet. Set from the Mesh screen's
     * hostname field before the node boots (see LibtailscaleBackend.start), which
     * is what makes that field a real setting rather than stored text.
     */
    override fun getDeviceName(): String =
        deviceName.ifBlank { "${Build.MANUFACTURER} ${Build.MODEL}".trim() }
    override fun isChromeOS(): Boolean =
        ctx.packageManager.hasSystemFeature("org.chromium.arc") ||
            ctx.packageManager.hasSystemFeature("org.chromium.arc.device_management")

    /** Sideloaded by design — this is not a store build, and saying otherwise would be a lie. */
    override fun getInstallSource(): String = ""

    override fun log(tag: String, message: String) {
        Diagnostics.log("tailscale/$tag", message)
    }

    override fun isClientLoggingEnabled(): Boolean = false

    // ---- networking ----

    /**
     * Pin a socket to the underlying network so the tailnet's own traffic does not
     * loop back through our tun. Returns false (rather than throwing) when there is
     * no active network, which Go handles as "not bound".
     */
    override fun bindSocketToNetwork(fd: Int): Boolean = runCatching {
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return false
        val network = cm.activeNetwork ?: return false
        val pfd = android.os.ParcelFileDescriptor.adoptFd(fd)
        try {
            network.bindSocket(pfd.fileDescriptor)
            true
        } finally {
            // adoptFd took ownership; detach so the fd's real owner keeps it.
            pfd.detachFd()
        }
    }.getOrElse {
        Diagnostics.error(TAG, "bindSocketToNetwork failed: ${it.javaClass.simpleName}: ${it.message}")
        false
    }

    override fun getInterfacesAsJson(): String {
        val arr = JSONArray()
        runCatching {
            java.net.NetworkInterface.getNetworkInterfaces()?.toList()?.forEach { nif ->
                val addrs = JSONArray()
                nif.interfaceAddresses.forEach { ia ->
                    ia.address?.hostAddress?.let { addrs.put("$it/${ia.networkPrefixLength}") }
                }
                arr.put(
                    JSONObject()
                        .put("name", nif.name)
                        .put("index", nif.index)
                        .put("mtu", runCatching { nif.mtu }.getOrDefault(0))
                        .put("up", runCatching { nif.isUp }.getOrDefault(false))
                        .put("addrs", addrs),
                )
            }
        }.onFailure {
            Diagnostics.error(TAG, "getInterfacesAsJson failed: ${it.message}")
        }
        return arr.toString()
    }

    /**
     * Godwall runs its OWN DNS filter and encrypted upstream, so we deliberately do
     * not hand Go a platform DNS config to override it with. Empty = "no platform
     * config", which is true from the tailnet's point of view.
     */
    override fun getPlatformDNSConfig(): String = ""

    override fun shouldUseGoogleDNSFallback(): Boolean = false

    /** No user-added CA store here; an empty PEM set is the accurate answer. */
    override fun getUserCACertsPEM(): ByteArray = ByteArray(0)

    // ---- MDM syspolicy: no policy source, so report absent rather than invent ----

    override fun getSyspolicyBooleanValue(key: String): Boolean = false
    override fun getSyspolicyStringValue(key: String): String = ""
    override fun getSyspolicyStringArrayJSONValue(key: String): String = ""

    // ---- hardware attestation: unsupported, and it says so ----

    override fun hardwareAttestationKeySupported(): Boolean = false

    override fun hardwareAttestationKeyCreate(): String =
        throw UnsupportedOperationException("hardware attestation not implemented in Godwall")

    override fun hardwareAttestationKeyLoad(id: String): Unit =
        throw UnsupportedOperationException("hardware attestation not implemented in Godwall")

    override fun hardwareAttestationKeyPublic(id: String): ByteArray =
        throw UnsupportedOperationException("hardware attestation not implemented in Godwall")

    override fun hardwareAttestationKeyRelease(id: String): Unit =
        throw UnsupportedOperationException("hardware attestation not implemented in Godwall")

    override fun hardwareAttestationKeySign(id: String, data: ByteArray): ByteArray =
        throw UnsupportedOperationException("hardware attestation not implemented in Godwall")

    companion object {
        /** Set before the Go side boots; read back by [getDeviceName]. */
        @Volatile
        private var deviceName: String = ""

        fun setDeviceName(name: String) {
            deviceName = name.trim()
        }

        const val TAG = "godwall.mesh.AppContext"
        const val PREFS = "godwall_mesh_state"
    }
}
