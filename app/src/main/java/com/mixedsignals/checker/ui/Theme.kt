package com.mixedsignals.checker.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.mixedsignals.checker.domain.model.ConfidenceLevel
import com.mixedsignals.checker.domain.model.Severity

private val Navy = Color(0xFF1E3A5F)

@Composable
fun AppTheme(content: @Composable () -> Unit) {
    val scheme = if (isSystemInDarkTheme()) {
        darkColorScheme(primary = Color(0xFF9CC3F0), secondary = Color(0xFFFFC857))
    } else {
        lightColorScheme(primary = Navy, secondary = Color(0xFF8A5A00))
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

fun severityColor(s: Severity): Color = when (s) {
    Severity.HIGH -> Color(0xFFD32F2F)
    Severity.MEDIUM -> Color(0xFFE08A00)
    Severity.LOW -> Color(0xFF1E88E5)
    Severity.INFO -> Color(0xFF78909C)
}

fun levelColor(l: ConfidenceLevel): Color = when (l) {
    ConfidenceLevel.CLEAR -> Color(0xFF2E7D32)
    ConfidenceLevel.AMBIGUOUS -> Color(0xFFE08A00)
    ConfidenceLevel.UNCLEAR -> Color(0xFFD32F2F)
}

val MissingColor = Color(0xFFD32F2F)
