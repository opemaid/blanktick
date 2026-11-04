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
import androidx.compose.ui.text.platform.Font
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
 * meaningless. The colour model is shared and comes from the same generated
 * tokens; the type differs, because this file binds the bundled brand faces
 * (desktop resources) and the Android one uses the system face. If the colour
 * model changes in one, change both. (No `DesktopThemeParityTest` exists in
 * the tree as of 2026-10-23, despite what this comment used to say.)
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
 * The brand faces, bundled: Hanken Grotesk and IBM Plex Mono, the same two
 * families blanktick.org self-hosts, so the app and the site read as one thing.
 *
 * ## Why bundled, and why this replaced the installed-font probe
 *
 * The previous code probed `GraphicsEnvironment` for Segoe UI Variable / SF Pro
 * / Inter and fell back to the platform default. That was honest, but it meant
 * the app's type changed with the machine and never matched the brand. These
 * are OFL fonts shipped as resources under `fonts/` (licences alongside).
 * Resources are not code, so the offline build gate is unaffected, and nothing
 * is fetched: a font that ships inside the download cannot phone home.
 *
 * Hanken Grotesk is variable upstream; the weights used here are static
 * instances cut from it with fontTools (`instancer`, wght 400/500/600/700/800),
 * because named-weight lookup is the one path Compose desktop resolves
 * reliably for a resource font.
 */
private val BrandFace: FontFamily = runCatching {
    FontFamily(
        Font("fonts/HankenGrotesk-Regular.ttf", FontWeight.Normal),
        Font("fonts/HankenGrotesk-Medium.ttf", FontWeight.Medium),
        Font("fonts/HankenGrotesk-SemiBold.ttf", FontWeight.SemiBold),
        Font("fonts/HankenGrotesk-Bold.ttf", FontWeight.Bold),
        Font("fonts/HankenGrotesk-ExtraBold.ttf", FontWeight.ExtraBold)
    )
}.getOrDefault(FontFamily.Default)

/** The display face is the brand face; the site uses one sans for both. */
private val DisplayFace: FontFamily = BrandFace

/** The ledger column, and every mono label. Same face as the site's. */
private val MonoFace: FontFamily = runCatching {
    FontFamily(
        Font("fonts/IBMPlexMono-Regular.ttf", FontWeight.Normal),
        Font("fonts/IBMPlexMono-SemiBold.ttf", FontWeight.Medium),
        Font("fonts/IBMPlexMono-SemiBold.ttf", FontWeight.SemiBold)
    )
}.getOrDefault(FontFamily.Monospace)

private fun TextStyle.branded() = copy(fontFamily = BrandFace)

private val BlanktickTypography = Typography().let { base ->
    // Every style on the brand face first, so stock Material components (menus,
    // switches, snackbars) do not fall back to the platform font mid-screen.
    Typography(
        displayLarge = base.displayLarge.branded(), displayMedium = base.displayMedium.branded(),
        displaySmall = base.displaySmall.branded(), headlineLarge = base.headlineLarge.branded(),
        headlineMedium = base.headlineMedium.branded(), headlineSmall = base.headlineSmall.branded(),
        titleLarge = base.titleLarge.branded(), titleMedium = base.titleMedium.branded(),
        titleSmall = base.titleSmall.branded(), bodyLarge = base.bodyLarge.branded(),
        bodyMedium = base.bodyMedium.branded(), bodySmall = base.bodySmall.branded(),
        labelLarge = base.labelLarge.branded(), labelMedium = base.labelMedium.branded(),
        labelSmall = base.labelSmall.branded()
    )
}.run {
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
        // The site's micro-labels ("SCAN RECEIPT", "CHECKS RAN") are mono caps.
        labelSmall = labelSmall.copy(
            fontFamily = MonoFace,
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
