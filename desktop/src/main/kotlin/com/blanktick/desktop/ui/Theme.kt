package com.blanktick.desktop.ui

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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.platform.asComposeFontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.LineHeightStyle
import androidx.compose.ui.unit.sp
import com.blanktick.core.model.Severity

/*
 * Mirrors app/src/main/java/com/blanktick/app/ui/Theme.kt.
 *
 * Kept as a copy rather than extracted into a shared module because :core must
 * stay free of any UI dependency -- it is the module the Swift mirror is
 * checked against, and adding Compose to it would make that comparison
 * meaningless. The two files differ only in their package declaration; if one
 * changes, change both. `DesktopThemeParityTest` fails if they drift.
 */

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
    val notChecked: Color,
    /** Focus ring. MUST be an outline; hover MUST be a fill. See [BlanktickTheme]. */
    val focus: Color,
    /** The score gauge's unfilled track. Not `hairline`: that is 1.26:1. */
    val trackMuted: Color,
    val isDark: Boolean
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
    notChecked = BlanktickTokens.Severity.notChecked,
    focus = BlanktickTokens.Light.focus,
    trackMuted = BlanktickTokens.Light.trackMuted,
    isDark = false
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
    kelpTint = BlanktickTokens.Dark.kelpTint,
    critical = BlanktickTokens.Severity.criticalOnDark,
    high = BlanktickTokens.Severity.highOnDark,
    medium = BlanktickTokens.Severity.mediumOnDark,
    low = BlanktickTokens.Severity.lowOnDark,
    info = BlanktickTokens.Severity.infoOnDark,
    pass = BlanktickTokens.Severity.passOnDark,
    notChecked = BlanktickTokens.Severity.notCheckedOnDark,
    focus = BlanktickTokens.Dark.focus,
    trackMuted = BlanktickTokens.Dark.trackMuted,
    isDark = true
)

val LocalBlanktickColors = staticCompositionLocalOf { LightColors }

/**
 * Type scale from `design/tokens.json`, on the platform face.
 *
 * Sizes are `sp`, never `dp`, so the whole app scales with the user's font-size
 * setting. Finding body text sits at [BlanktickTokens.TypeScale.body] and is never
 * reduced to fit more on screen (DD-09).
 */
/**
 * The display face, resolved against fonts that are actually installed.
 *
 * ## What was proposed, and why it is not what shipped
 *
 * The design panel recommended binding `Segoe UI Variable Display` — Windows'
 * large-optical-size cut — on the reasoning that an 82sp numeral was being drawn
 * in a face cut for 12sp. That reasoning is sound and the panel flagged it as
 * inferred from a screenshot rather than verified.
 *
 * It does not survive verification. `GraphicsEnvironment` on this machine lists
 * `Segoe UI Variable` but **not** `Segoe UI Variable Display` or
 * `…Text`: Windows exposes the optical sizes as named instances inside one
 * variable family, and AWT surfaces only the family. Asking for a family that
 * does not exist gets silently substituted, so hard-coding the name would have
 * produced a *different* font from the one intended, with nothing reporting it.
 *
 * So the list is probed at runtime and the first installed entry wins. If none
 * is present the platform default is used, which is the honest outcome rather
 * than a silent substitution.
 */
private val DisplayFace: FontFamily = resolveFamily(
    "Segoe UI Variable", "SF Pro Display", "Inter", "Segoe UI"
)

/** The ledger column. Falls back to Compose's generic monospace. */
private val MonoFace: FontFamily = resolveFamily("Cascadia Mono", "Consolas", "JetBrains Mono")

// asComposeFontFamily is the only name-based system-font lookup Compose
// Multiplatform desktop exposes, and it is @ExperimentalTextApi. The runCatching
// is the contingency if that changes: an unavailable API degrades to the
// platform default rather than failing to start.
@OptIn(androidx.compose.ui.text.ExperimentalTextApi::class)
@Suppress("SwallowedException")
private fun resolveFamily(vararg preferred: String): FontFamily = runCatching {
    val installed = java.awt.GraphicsEnvironment
        .getLocalGraphicsEnvironment()
        .availableFontFamilyNames
        .toHashSet()

    val name = preferred.firstOrNull { candidate ->
        installed.any { it.equals(candidate, ignoreCase = true) }
    } ?: return@runCatching FontFamily.Default

    java.awt.Font(name, java.awt.Font.PLAIN, 12).asComposeFontFamily()
}.getOrDefault(FontFamily.Default)

private val BlanktickTypography = Typography().run {
    val lineHeightStyle = LineHeightStyle(
        alignment = LineHeightStyle.Alignment.Center,
        trim = LineHeightStyle.Trim.None
    )
    copy(
        // Tabular figures matter here: without them the numeral shifts inside
        // the gauge between scans, because "86" and "91" have different widths
        // in proportional digits.
        displayLarge = displayLarge.copy(
            fontFamily = DisplayFace,
            fontSize = BlanktickTokens.TypeScale.scoreDesktop,
            lineHeight = BlanktickTokens.TypeScale.scoreDesktop,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = (-0.03).sp,
            fontFeatureSettings = "tnum, lnum",
            lineHeightStyle = lineHeightStyle
        ),
        headlineMedium = headlineMedium.copy(
            fontFamily = DisplayFace,
            fontSize = BlanktickTokens.TypeScale.title1,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = (-0.02).sp
        ),
        titleLarge = titleLarge.copy(
            fontFamily = DisplayFace,
            fontSize = BlanktickTokens.TypeScale.title3,
            fontWeight = FontWeight.SemiBold,
            letterSpacing = (-0.01).sp
        ),
        titleMedium = titleMedium.copy(
            fontSize = BlanktickTokens.TypeScale.callout,
            fontWeight = FontWeight.SemiBold
        ),
        bodyLarge = bodyLarge.copy(fontSize = BlanktickTokens.TypeScale.body, lineHeight = 24.sp),
        // DD-09 refuses shrinking finding detail to fit more findings, so
        // bodyMedium is NOT the finding body -- FindingCard uses bodyLarge.
        // This stays at footnote for genuine secondary chrome only.
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

/**
 * Monospaced, tabular style for anything the user might add up.
 *
 * This comment used to sit above `bodyMedium.copy(fontWeight = Bold)` — not
 * monospaced, not tabular, and set two steps below body size. DD-06's entire
 * premise is that a user can add the deduction column and get `100 - score`;
 * proportional digits do not align into a column, so the arithmetic the product
 * invites you to check was harder to check than it needed to be.
 */
val LedgerNumberStyle: TextStyle
    @Composable get() = MaterialTheme.typography.bodyLarge.copy(
        fontFamily = MonoFace,
        fontFeatureSettings = "tnum, lnum",
        fontWeight = FontWeight.Medium,
        letterSpacing = 0.sp
    )
