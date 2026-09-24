package com.blanktick.app.ui

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
import com.blanktick.core.model.Severity

/**
 * Colours resolved for the active theme.
 *
 * Dark mode is a first-class theme rather than an inversion (design gate
 * checklist): the severity ramp uses different, lighter values on dark so that
 * every one still clears 4.5:1, which a straight inversion would not achieve.
 */
data class BlanktickColors(
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

private val LightColors = BlanktickColors(
    paper = BlanktickTokens.Light.paper,
    surface = BlanktickTokens.Light.surface,
    surfaceSunk = BlanktickTokens.Light.surfaceSunk,
    ink = BlanktickTokens.Light.ink,
    inkMuted = BlanktickTokens.Light.inkMuted,
    inkFaint = BlanktickTokens.Light.inkFaint,
    hairline = BlanktickTokens.Light.hairline,
    kelp = BlanktickTokens.Brand.kelp,
    kelpTint = BlanktickTokens.Brand.kelpTint,
    critical = BlanktickTokens.Severity.critical,
    high = BlanktickTokens.Severity.high,
    medium = BlanktickTokens.Severity.medium,
    low = BlanktickTokens.Severity.low,
    info = BlanktickTokens.Severity.info,
    pass = BlanktickTokens.Severity.pass,
    notChecked = BlanktickTokens.Severity.notChecked
)

private val DarkColors = BlanktickColors(
    paper = BlanktickTokens.Dark.paper,
    surface = BlanktickTokens.Dark.surface,
    surfaceSunk = BlanktickTokens.Dark.surfaceSunk,
    ink = BlanktickTokens.Dark.ink,
    inkMuted = BlanktickTokens.Dark.inkMuted,
    inkFaint = BlanktickTokens.Dark.inkFaint,
    hairline = BlanktickTokens.Dark.hairline,
    kelp = BlanktickTokens.Severity.passOnDark,
    kelpTint = BlanktickTokens.Dark.surface,
    critical = BlanktickTokens.Severity.criticalOnDark,
    high = BlanktickTokens.Severity.highOnDark,
    medium = BlanktickTokens.Severity.mediumOnDark,
    low = BlanktickTokens.Severity.lowOnDark,
    info = BlanktickTokens.Severity.infoOnDark,
    pass = BlanktickTokens.Severity.passOnDark,
    notChecked = BlanktickTokens.Severity.notCheckedOnDark
)

val LocalBlanktickColors = staticCompositionLocalOf { LightColors }

/**
 * Type scale from `design/tokens.json`, on the platform face.
 *
 * Sizes are `sp`, never `dp`, so the whole app scales with the user's font-size
 * setting. Finding body text sits at [BlanktickTokens.TypeScale.body] and is never
 * reduced to fit more on screen (DD-09).
 */
private val BlanktickTypography = Typography().run {
    val lineHeightStyle = LineHeightStyle(
        alignment = LineHeightStyle.Alignment.Center,
        trim = LineHeightStyle.Trim.None
    )
    copy(
        displayLarge = displayLarge.copy(
            fontSize = BlanktickTokens.TypeScale.score,
            lineHeight = BlanktickTokens.TypeScale.score,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = (-0.03).sp,
            lineHeightStyle = lineHeightStyle
        ),
        headlineMedium = headlineMedium.copy(
            fontSize = BlanktickTokens.TypeScale.title1,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = (-0.02).sp
        ),
        titleLarge = titleLarge.copy(
            fontSize = BlanktickTokens.TypeScale.title3,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = (-0.01).sp
        ),
        titleMedium = titleMedium.copy(
            fontSize = BlanktickTokens.TypeScale.callout,
            fontWeight = FontWeight.SemiBold
        ),
        bodyLarge = bodyLarge.copy(fontSize = BlanktickTokens.TypeScale.body, lineHeight = 24.sp),
        bodyMedium = bodyMedium.copy(fontSize = BlanktickTokens.TypeScale.footnote, lineHeight = 20.sp),
        labelSmall = labelSmall.copy(
            fontSize = BlanktickTokens.TypeScale.caption,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.4.sp
        )
    )
}

@Composable
fun BlanktickTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colors = if (darkTheme) DarkColors else LightColors

    // Material3 scheme is supplied so stock components inherit sensible values,
    // but Blanktick's own surfaces read from LocalBlanktickColors, which is the token
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

    CompositionLocalProvider(LocalBlanktickColors provides colors) {
        MaterialTheme(colorScheme = scheme, typography = BlanktickTypography, content = content)
    }
}

/** Monospaced, tabular style for anything the user might add up. */
val LedgerNumberStyle: TextStyle
    @Composable get() = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold)
