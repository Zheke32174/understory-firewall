package com.understory.security.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

/**
 * Suite shape scale. Maps the ad-hoc `RoundedCornerShape(3/4/6/…dp)` corners
 * scattered through the apps onto Material3 shape roles:
 *   extraSmall — Diagnostics event rows (was 4.dp)
 *   small      — the status-footer container (was 6.dp)
 *   medium     — cards ([com.understory.security.ui.components.SuiteCard])
 *   large      — dialogs / large surfaces
 */
val UnderstoryShapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),   // cards — softer, more modern
    large = RoundedCornerShape(20.dp),    // dialogs / large surfaces
    extraLarge = RoundedCornerShape(28.dp),
)
