package com.understory.firewall

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * Minimal place-name geocoding via the public OSM Nominatim API — no key, no
 * SDK. Used by the mock-location map picker so the user can type a place and
 * jump the map there. Best-effort: any failure returns null and the caller
 * keeps the current view.
 *
 * PRIVACY: the query string is sent to the Nominatim server over the network.
 * The screen makes the network nature of the map picker explicit.
 */
object NominatimSearch {
    private const val UA = "UnderstoryFirewall/1.0 (Understory mock-location map picker)"

    data class Hit(val lat: Double, val lon: Double, val label: String)

    suspend fun search(query: String): Hit? {
        val q = query.trim()
        if (q.isEmpty()) return null
        return withContext(Dispatchers.IO) {
            try {
                val enc = URLEncoder.encode(q, "UTF-8")
                val con = (URL("https://nominatim.openstreetmap.org/search?format=json&limit=1&q=$enc")
                    .openConnection() as HttpURLConnection).apply {
                    setRequestProperty("User-Agent", UA)
                    connectTimeout = 8000
                    readTimeout = 8000
                }
                val body = try {
                    con.inputStream.use { it.readBytes().decodeToString() }
                } finally {
                    con.disconnect()
                }
                val arr = JSONArray(body)
                if (arr.length() == 0) return@withContext null
                val o = arr.getJSONObject(0)
                Hit(
                    lat = o.getString("lat").toDouble(),
                    lon = o.getString("lon").toDouble(),
                    label = o.optString("display_name", q),
                )
            } catch (_: Throwable) {
                null
            }
        }
    }
}
