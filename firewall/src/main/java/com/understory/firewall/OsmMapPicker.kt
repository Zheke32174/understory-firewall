package com.understory.firewall

import android.graphics.BitmapFactory
import android.util.LruCache
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableDoubleStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import kotlin.math.PI
import kotlin.math.atan
import kotlin.math.ceil
import kotlin.math.cos
import kotlin.math.floor
import kotlin.math.ln
import kotlin.math.sinh
import kotlin.math.tan

/**
 * A tiny self-contained OpenStreetMap "slippy map" location picker — no
 * third-party map SDK, no API key. Renders raster OSM tiles on a Compose
 * [Canvas], supports drag-to-pan and +/- zoom, and reports the map CENTRE
 * (marked by a fixed crosshair) as the selected coordinate.
 *
 * PRIVACY: tile requests go to the public OSM tile server over the network, so
 * using the picker reveals the area you are browsing to that server. The screen
 * hosting this makes that explicit; the picker itself only fetches tiles for the
 * visible viewport. It sends a descriptive User-Agent per the OSM tile policy.
 *
 * @param target the point the map should CENTRE on; change it (preset / search)
 *   to recentre. Panning does NOT feed back into [target], so no update loop.
 * @param onCenterChanged called with the live centre (lat, lon) as the user pans.
 */
@Composable
fun OsmMapPicker(
    target: MapTarget,
    onCenterChanged: (Double, Double) -> Unit,
    modifier: Modifier = Modifier,
) {
    var zoom by remember { mutableIntStateOf(13) }
    var centerLat by remember { mutableDoubleStateOf(target.lat) }
    var centerLon by remember { mutableDoubleStateOf(target.lon) }
    // External recentre (preset/search) — reset the internal centre when target changes.
    LaunchedEffect(target) {
        centerLat = target.lat
        centerLon = target.lon
    }
    val tiles = remember { mutableStateMapOf<String, ImageBitmap>() }
    val scope = rememberCoroutineScope()

    BoxWithConstraints(modifier) {
        val wPx = constraints.maxWidth.toFloat().coerceAtLeast(1f)
        val hPx = constraints.maxHeight.toFloat().coerceAtLeast(1f)

        // Fetch the visible tiles whenever the viewport changes.
        LaunchedEffect(centerLat, centerLon, zoom, wPx, hPx) {
            val n = 1 shl zoom
            val cxTile = lonToTileX(centerLon, zoom)
            val cyTile = latToTileY(centerLat, zoom)
            val firstX = floor(cxTile - (wPx / 2) / TILE).toInt()
            val firstY = floor(cyTile - (hPx / 2) / TILE).toInt()
            val cols = ceil(wPx / TILE).toInt() + 2
            val rows = ceil(hPx / TILE).toInt() + 2
            for (ix in 0 until cols) for (iy in 0 until rows) {
                val ty = firstY + iy
                if (ty < 0 || ty >= n) continue
                val wx = ((firstX + ix) % n + n) % n
                val key = "$zoom/$wx/$ty"
                if (tiles.containsKey(key)) continue
                scope.launch {
                    TileCache.fetch(zoom, wx, ty)?.let { tiles[key] = it }
                }
            }
        }

        Canvas(
            modifier = Modifier
                .fillMaxSize()
                .pointerInput(zoom) {
                    detectDragGestures { change, drag ->
                        change.consume()
                        val cx = lonToTileX(centerLon, zoom) - drag.x / TILE
                        val cy = latToTileY(centerLat, zoom) - drag.y / TILE
                        val n = (1 shl zoom).toDouble()
                        centerLon = tileXToLon(cx, zoom)
                        centerLat = tileYToLat(cy.coerceIn(0.0, n - 1e-6), zoom)
                        onCenterChanged(centerLat, centerLon)
                    }
                },
        ) {
            val n = 1 shl zoom
            val cxTile = lonToTileX(centerLon, zoom)
            val cyTile = latToTileY(centerLat, zoom)
            val originX = cxTile - (size.width / 2) / TILE
            val originY = cyTile - (size.height / 2) / TILE
            val firstX = floor(originX).toInt()
            val firstY = floor(originY).toInt()
            val offX = ((firstX - originX) * TILE).toFloat()
            val offY = ((firstY - originY) * TILE).toFloat()
            val cols = ceil(size.width / TILE).toInt() + 2
            val rows = ceil(size.height / TILE).toInt() + 2
            for (ix in 0 until cols) for (iy in 0 until rows) {
                val ty = firstY + iy
                val left = offX + ix * TILE.toFloat()
                val top = offY + iy * TILE.toFloat()
                if (ty < 0 || ty >= n) {
                    drawRect(EMPTY, Offset(left, top), Size(TILE.toFloat(), TILE.toFloat()))
                    continue
                }
                val wx = ((firstX + ix) % n + n) % n
                val bmp = tiles["$zoom/$wx/$ty"]
                if (bmp != null) {
                    drawImage(bmp, topLeft = Offset(left, top))
                } else {
                    drawRect(EMPTY, Offset(left, top), Size(TILE.toFloat(), TILE.toFloat()))
                }
            }
            // Centre crosshair — the selected point.
            val cx = size.width / 2f
            val cy = size.height / 2f
            drawLine(Color.White, Offset(cx - 16f, cy), Offset(cx + 16f, cy), 3f)
            drawLine(Color.White, Offset(cx, cy - 16f), Offset(cx, cy + 16f), 3f)
            drawCircle(Color.White, 7f, Offset(cx, cy), style = Stroke(2.5f))
        }

        Column(
            modifier = Modifier.align(Alignment.TopEnd).padding(8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            FilledTonalIconButton(onClick = { zoom = (zoom + 1).coerceAtMost(19) }) {
                Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.mock_map_zoom_in))
            }
            FilledTonalIconButton(onClick = { zoom = (zoom - 1).coerceAtLeast(2) }) {
                Icon(Icons.Filled.Remove, contentDescription = stringResource(R.string.mock_map_zoom_out))
            }
        }
    }
}

/** A point the [OsmMapPicker] should centre on. */
data class MapTarget(val lat: Double, val lon: Double)

private const val TILE = 256.0
private val EMPTY = Color(0xFF23272E)
private const val UA = "UnderstoryFirewall/1.0 (Understory mock-location map picker)"

// ---- Web-Mercator slippy-map tile math ------------------------------------
private fun lonToTileX(lon: Double, z: Int): Double = (lon + 180.0) / 360.0 * (1 shl z)

private fun latToTileY(lat: Double, z: Int): Double {
    val r = Math.toRadians(lat.coerceIn(-85.05112878, 85.05112878))
    return (1.0 - ln(tan(r) + 1.0 / cos(r)) / PI) / 2.0 * (1 shl z)
}

private fun tileXToLon(x: Double, z: Int): Double = x / (1 shl z) * 360.0 - 180.0

private fun tileYToLat(y: Double, z: Int): Double {
    val nn = PI - 2.0 * PI * y / (1 shl z)
    return Math.toDegrees(atan(sinh(nn)))
}

/** In-memory OSM tile cache + fetcher. Failures are swallowed (tile stays blank). */
private object TileCache {
    private val mem = LruCache<String, ImageBitmap>(160)

    fun cached(key: String): ImageBitmap? = mem.get(key)

    suspend fun fetch(z: Int, x: Int, y: Int): ImageBitmap? {
        val key = "$z/$x/$y"
        mem.get(key)?.let { return it }
        return try {
            val bmp = withContext(Dispatchers.IO) {
                val con = (URL("https://tile.openstreetmap.org/$z/$x/$y.png")
                    .openConnection() as HttpURLConnection).apply {
                    setRequestProperty("User-Agent", UA)
                    connectTimeout = 8000
                    readTimeout = 8000
                }
                try {
                    con.inputStream.use { BitmapFactory.decodeStream(it) }?.asImageBitmap()
                } finally {
                    con.disconnect()
                }
            }
            if (bmp != null) mem.put(key, bmp)
            bmp
        } catch (_: Throwable) {
            null
        }
    }
}
