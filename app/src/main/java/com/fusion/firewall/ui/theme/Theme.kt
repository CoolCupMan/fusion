package com.fusion.firewall.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Accent = Color(0xFF3DDC97)
private val AccentDark = Color(0xFF1F9E6E)
private val Danger = Color(0xFFFF5C6C)
private val Background = Color(0xFF0B0F14)
private val Surface = Color(0xFF141B24)

private val DarkColors = darkColorScheme(
    primary = Accent,
    onPrimary = Color(0xFF07130D),
    secondary = Color(0xFF6FE3FF),
    background = Background,
    surface = Surface,
    surfaceVariant = Color(0xFF1E2833),
    error = Danger,
    onBackground = Color(0xFFE6EDF3),
    onSurface = Color(0xFFE6EDF3),
)

private val LightColors = lightColorScheme(
    primary = AccentDark,
    secondary = Color(0xFF0A7EA4),
    error = Danger,
)

@Composable
fun FusionTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = Typography(),
        content = content,
    )
}
