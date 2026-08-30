package com.mume.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.LineHeightStyle
import androidx.compose.ui.unit.sp
import com.mume.core.model.Severity

/**
 * Colours resolved for the active theme.
 *
 * Dark mode is a first-class theme rather than an inversion (design gate
 * checklist): the severity ramp uses different, lighter values on dark so that
 * every one still clears 4.5:1, which a straight inversion would not achieve.
 */
data class MumeColors(
    val paper: Color,
    val surface: Color,
    val surfaceSunk: Color,
    val ink: Color,
    val inkMuted: Color,
    val inkFaint: Color,
    val hairline: Color,
    val kelp: Color,
    val kelpTint: Color,
    val critical: Color,
    val high: Color,
    val medium: Color,
    val low: Color,
    val info: Color,
    val pass: Color,
    val notChecked: Color
) {
    /**
     * Colour is the THIRD channel for severity, after the label and the weight
     * (DD-03). Nothing in the UI may use this without also rendering
     * [severityLabel].
     */
    fun forSeverity(severity: Severity): Color = when (severity) {
        Severity.CRITICAL -> critical
        Severity.HIGH -> high
        Severity.MEDIUM -> medium
        Severity.LOW -> low
        Severity.INFO -> info
    }
}

/** The redundant text channel. Always rendered next to a severity colour. */
fun severityLabel(severity: Severity): String = when (severity) {
    Severity.CRITICAL -> "CRITICAL"
    Severity.HIGH -> "HIGH"
    Severity.MEDIUM -> "MEDIUM"
    Severity.LOW -> "LOW"
    Severity.INFO -> "INFO"
}

/**
 * The redundant shape channel, for anyone who sees neither colour difference
 * nor reads the label first. Matches the prototype exactly.
 */
fun severityGlyph(severity: Severity): String = when (severity) {
    Severity.CRITICAL -> "◆"   // filled diamond
    Severity.HIGH -> "▲"       // filled triangle
    Severity.MEDIUM -> "■"     // filled square
    Severity.LOW -> "●"        // filled circle
    Severity.INFO -> "○"       // hollow circle
}

private val LightColors = MumeColors(
    paper = MumeTokens.Light.paper,
    surface = MumeTokens.Light.surface,
    surfaceSunk = MumeTokens.Light.surfaceSunk,
    ink = MumeTokens.Light.ink,
    inkMuted = MumeTokens.Light.inkMuted,
    inkFaint = MumeTokens.Light.inkFaint,
    hairline = MumeTokens.Light.hairline,
    kelp = MumeTokens.Brand.kelp,
    kelpTint = MumeTokens.Brand.kelpTint,
    critical = MumeTokens.Severity.critical,
    high = MumeTokens.Severity.high,
    medium = MumeTokens.Severity.medium,
    low = MumeTokens.Severity.low,
    info = MumeTokens.Severity.info,
    pass = MumeTokens.Severity.pass,
    notChecked = MumeTokens.Severity.notChecked
)

private val DarkColors = MumeColors(
    paper = MumeTokens.Dark.paper,
    surface = MumeTokens.Dark.surface,
    surfaceSunk = MumeTokens.Dark.surfaceSunk,
    ink = MumeTokens.Dark.ink,
    inkMuted = MumeTokens.Dark.inkMuted,
    inkFaint = MumeTokens.Dark.inkFaint,
    hairline = MumeTokens.Dark.hairline,
    kelp = MumeTokens.Severity.passOnDark,
    kelpTint = MumeTokens.Dark.surface,
    critical = MumeTokens.Severity.criticalOnDark,
    high = MumeTokens.Severity.highOnDark,
    medium = MumeTokens.Severity.mediumOnDark,
    low = MumeTokens.Severity.lowOnDark,
    info = MumeTokens.Severity.infoOnDark,
    pass = MumeTokens.Severity.passOnDark,
    notChecked = MumeTokens.Severity.notCheckedOnDark
)

val LocalMumeColors = staticCompositionLocalOf { LightColors }

/**
 * Type scale from `design/tokens.json`, on the platform face.
 *
 * Sizes are `sp`, never `dp`, so the whole app scales with the user's font-size
 * setting. Finding body text sits at [MumeTokens.TypeScale.body] and is never
 * reduced to fit more on screen (DD-09).
 */
private val MumeTypography = Typography().run {
    val lineHeightStyle = LineHeightStyle(
        alignment = LineHeightStyle.Alignment.Center,
        trim = LineHeightStyle.Trim.None
    )
    copy(
        displayLarge = displayLarge.copy(
            fontSize = MumeTokens.TypeScale.score,
            lineHeight = MumeTokens.TypeScale.score,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = (-0.03).sp,
            lineHeightStyle = lineHeightStyle
        ),
        headlineMedium = headlineMedium.copy(
            fontSize = MumeTokens.TypeScale.title1,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = (-0.02).sp
        ),
        titleLarge = titleLarge.copy(
            fontSize = MumeTokens.TypeScale.title3,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = (-0.01).sp
        ),
        titleMedium = titleMedium.copy(
            fontSize = MumeTokens.TypeScale.callout,
            fontWeight = FontWeight.SemiBold
        ),
        bodyLarge = bodyLarge.copy(fontSize = MumeTokens.TypeScale.body, lineHeight = 24.sp),
        bodyMedium = bodyMedium.copy(fontSize = MumeTokens.TypeScale.footnote, lineHeight = 20.sp),
        labelSmall = labelSmall.copy(
            fontSize = MumeTokens.TypeScale.caption,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.4.sp
        )
    )
}

@Composable
fun MumeTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colors = if (darkTheme) DarkColors else LightColors

    // Material3 scheme is supplied so stock components inherit sensible values,
    // but Mume's own surfaces read from LocalMumeColors, which is the token
    // pipeline's output and therefore the single source of truth.
    val scheme = if (darkTheme) {
        darkColorScheme(
            primary = colors.kelp, onPrimary = colors.paper,
            background = colors.paper, onBackground = colors.ink,
            surface = colors.surface, onSurface = colors.ink,
            error = colors.critical
        )
    } else {
        lightColorScheme(
            primary = colors.kelp, onPrimary = Color.White,
            background = colors.paper, onBackground = colors.ink,
            surface = colors.surface, onSurface = colors.ink,
            error = colors.critical
        )
    }

    CompositionLocalProvider(LocalMumeColors provides colors) {
        MaterialTheme(colorScheme = scheme, typography = MumeTypography, content = content)
    }
}

/** Monospaced, tabular style for anything the user might add up. */
val LedgerNumberStyle: TextStyle
    @Composable get() = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold)
