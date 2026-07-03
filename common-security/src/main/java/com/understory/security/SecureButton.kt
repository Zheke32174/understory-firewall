package com.understory.security

import android.view.MotionEvent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInteropFilter
import androidx.compose.ui.platform.LocalView

/**
 * Tap-jacking defenses that go beyond Android's built-in
 * [android.view.View.filterTouchesWhenObscured] (which only catches FULLY
 * obscured windows). We additionally reject:
 *
 *  - [MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED]: a small overlay just
 *    over the button is enough to defeat the standard filter; we don't allow it.
 *  - Touches received while [android.view.View.hasWindowFocus] is false: the
 *    OS revoked our focus (typically because something is on top of us).
 *
 * Wrap any button whose tap performs a security-sensitive action in
 * [SecureButton] / [SecureOutlinedButton]. The button visually depresses but
 * the click is silently dropped if any of the above are true.
 */
private object TouchSafety {
    fun isObscured(ev: MotionEvent): Boolean {
        val mask = MotionEvent.FLAG_WINDOW_IS_OBSCURED or
            MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED
        return (ev.flags and mask) != 0
    }
}

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun SecureButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    colors: ButtonColors = ButtonDefaults.buttonColors(),
    content: @Composable androidx.compose.foundation.layout.RowScope.() -> Unit,
) {
    val view = LocalView.current
    var blocked by remember { mutableStateOf(false) }

    val safetyMod = Modifier.pointerInteropFilter { ev ->
        when (ev.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                blocked = TouchSafety.isObscured(ev) || !view.hasWindowFocus()
            }
            MotionEvent.ACTION_MOVE -> {
                if (TouchSafety.isObscured(ev)) blocked = true
            }
        }
        false
    }

    Button(
        onClick = {
            if (blocked) return@Button
            if (!view.hasWindowFocus()) return@Button
            onClick()
        },
        modifier = modifier.then(safetyMod),
        enabled = enabled,
        colors = colors,
        content = content,
    )
}

/**
 * Arbitrary clickable surface with the same tap-jacking defenses as
 * SecureButton. Drop-in replacement for [androidx.compose.foundation.clickable]:
 *
 *   modifier = Modifier.secureClickable { onTap() }
 *
 * Same partial-obscured + focus-loss filters; click silently dropped if
 * either trips. Useful for list-row taps, image taps, etc.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun Modifier.secureClickable(onClick: () -> Unit): Modifier {
    val view = LocalView.current
    var blocked by remember { mutableStateOf(false) }
    return this
        .pointerInteropFilter { ev ->
            when (ev.actionMasked) {
                MotionEvent.ACTION_DOWN ->
                    blocked = TouchSafety.isObscured(ev) || !view.hasWindowFocus()
                MotionEvent.ACTION_MOVE ->
                    if (TouchSafety.isObscured(ev)) blocked = true
            }
            false
        }
        .clickable {
            if (blocked) return@clickable
            if (!view.hasWindowFocus()) return@clickable
            onClick()
        }
}

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun SecureOutlinedButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    content: @Composable androidx.compose.foundation.layout.RowScope.() -> Unit,
) {
    val view = LocalView.current
    var blocked by remember { mutableStateOf(false) }

    val safetyMod = Modifier.pointerInteropFilter { ev ->
        when (ev.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                blocked = TouchSafety.isObscured(ev) || !view.hasWindowFocus()
            }
            MotionEvent.ACTION_MOVE -> {
                if (TouchSafety.isObscured(ev)) blocked = true
            }
        }
        false
    }

    OutlinedButton(
        onClick = {
            if (blocked) return@OutlinedButton
            if (!view.hasWindowFocus()) return@OutlinedButton
            onClick()
        },
        modifier = modifier.then(safetyMod),
        enabled = enabled,
        content = content,
    )
}
