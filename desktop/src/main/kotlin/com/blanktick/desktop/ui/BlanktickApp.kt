package com.blanktick.desktop.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.LocalScrollbarStyle
import androidx.compose.foundation.ScrollbarStyle
import androidx.compose.foundation.background
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.blanktick.core.RuleReport
import com.blanktick.core.ThreatSummary
import com.blanktick.core.ScanReport
import com.blanktick.desktop.AppState
import com.blanktick.desktop.Screen
import com.blanktick.desktop.ScanUiState

/**
 * The window.
 *
 * A persistent left rail rather than a phone's bottom bar: the tools (link,
 * password, photos) are not sub-pages of the scan, they are peers, and on a
 * wide screen there is no reason to hide them behind a menu.
 */
@Composable
fun BlanktickApp(state: AppState) {
    val c = LocalBlanktickColors.current
    val screen by state.screen.collectAsState()

    // A clearly visible scrollbar, app-wide. Compose Desktop's default is ~12%
    // black — invisible on this light paper, which read as "the tab does not
    // scroll" even though it did. This makes every scrollbar obvious and gives
    // the reader something to grab.
    val scrollbar = ScrollbarStyle(
        minimalHeight = 28.dp,
        thickness = 10.dp,
        shape = RoundedCornerShape(BlanktickTokens.Radius.sm),
        hoverDurationMillis = 250,
        unhoverColor = c.inkFaint.copy(alpha = 0.45f),
        hoverColor = c.inkMuted.copy(alpha = 0.85f)
    )

    CompositionLocalProvider(LocalScrollbarStyle provides scrollbar) {
    Surface(Modifier.fillMaxSize(), color = c.paper) {
        Row(Modifier.fillMaxSize()) {
            NavRail(current = screen, onSelect = state::show)
            Box(Modifier.weight(1f).fillMaxHeight()) {
                when (screen) {
                    Screen.SCAN -> ScanScreen(state)
                    Screen.POLICY -> PolicyScreen(state)
                    Screen.THREATS -> ThreatsHost(state)
                    Screen.LINK -> LinkScreen(state)
                    Screen.PASSWORDS -> PasswordScreen(state)
                    Screen.PHOTOS -> PhotoScreen(state)
                    Screen.SOFTWARE -> SoftwareScreen(state)
                    Screen.USB -> UsbScreen(state)
                    Screen.ASSISTANT -> AssistantScreen(state)
                    Screen.LIVE -> LiveProtectionScreen(state)
                    Screen.SETTINGS -> SettingsScreen(state)
                    Screen.ABOUT -> AboutScreen(state)
                }
            }
        }
    }
    }
}

@Composable
private fun NavRail(current: Screen, onSelect: (Screen) -> Unit) {
    val c = LocalBlanktickColors.current

    // Scrolls: at "Larger" text on a ~900px window the last entries (About)
    // were pushed below the window edge with no way to reach them. Found by
    // visual test.
    Column(
        Modifier
            .width(240.dp)
            .fillMaxHeight()
            .background(c.surfaceSunk)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            BrandMark(Modifier.size(32.dp))
            Text("Blanktick", style = MaterialTheme.typography.titleLarge, color = c.ink)
        }
        Text(
            "Offline. Nothing leaves this computer.",
            style = MaterialTheme.typography.labelSmall,
            color = c.inkFaint
        )
        Spacer(Modifier.size(24.dp))

        Screen.entries.forEach { destination ->
            val selected = destination == current
            val shape = RoundedCornerShape(BlanktickTokens.Radius.md)
            val (source, hovered) = rememberHoverState()

            Surface(
                color = when {
                    selected -> c.kelpTint
                    hovered -> c.surface
                    else -> Color.Transparent
                },
                shape = shape,
                modifier = Modifier
                    .fillMaxWidth()
                    .hoverable(source)
                    .interactive(shape) { onSelect(destination) }
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // The selected fill alone was white on surfaceSunk = 1.15:1,
                    // well under the 3:1 that 1.4.11 asks of a UI component
                    // boundary. The bar carries it at 8.49:1; weight and ink
                    // colour are the third and fourth channels.
                    Box(
                        Modifier
                            .width(3.dp)
                            .height(20.dp)
                            .background(if (selected) c.kelp else Color.Transparent)
                    )
                    Text(
                        destination.title,
                        style = MaterialTheme.typography.bodyLarge,
                        color = if (selected) c.ink else c.inkMuted,
                        fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
                    )
                }
            }
        }
    }
}

/**
 * The Blanktick mark — the bundled brand logo (`blanktick-icon-512.png`), a
 * metallic shield carrying the verified checkmark. Loaded from an offline
 * resource that ships inside the app, so it still needs no network.
 */
@Composable
private fun BrandMark(modifier: Modifier = Modifier) {
    Image(
        painter = painterResource("blanktick-icon-512.png"),
        contentDescription = null,
        modifier = modifier.clearAndSetSemantics { },
    )
}

// ------------------------------------------------------------------- scan

@Composable
private fun ScanScreen(state: AppState) {
    val scan by state.scan.collectAsState()

    when (val s = scan) {
        is ScanUiState.FirstRun -> FirstRun(state)
        is ScanUiState.Scanning -> Centered(s.step, "Everything is happening on this computer.")
        is ScanUiState.Unsupported -> Unsupported(s.osName)
        is ScanUiState.Failed -> Failed(s.message) { state.runScan() }
        is ScanUiState.Complete -> PostureDashboard(s, onScan = { state.runScan() }, onOpenPolicy = state::openPolicy)
    }
}

/**
 * Threats is a *view* of the last scan, never a second collection.
 *
 * It deliberately cannot run a scan of its own. Two screens that each gather
 * their own facts is how a product ends up showing a user two different truths
 * about the same machine in the same minute.
 */
@Composable
private fun ThreatsHost(state: AppState) {
    val scan by state.scan.collectAsState()

    when (val s = scan) {
        is ScanUiState.Complete -> ThreatsScreen(
            ThreatSummary.from(s.report, incomplete = s.collectionCaveats.isNotEmpty()),
            onOpenPolicy = state::openPolicy
        )
        is ScanUiState.Scanning -> Centered(s.step, "Everything is happening on this computer.")
        else -> Centered(
            "No scan yet.",
            "Run a scan on \"This computer\" and the threat picture appears here."
        )
    }
}

@Composable
private fun FirstRun(state: AppState) {
    val c = LocalBlanktickColors.current
    ScrollableColumn(spacing = 20.dp) {
        Text(
            "Blanktick checks this computer.\nNothing else.",
            style = MaterialTheme.typography.headlineMedium,
            color = c.ink
        )
        Text(
            "It works entirely offline. There is no account, no upload and no server. " +
                "The app contains no networking code at all, and the build fails if any is " +
                "ever added.",
            style = MaterialTheme.typography.bodyLarge,
            color = c.inkMuted
        )
        Promise("Your passwords are checked against a list built into the app. Nothing is sent, not even a hash.")
        Promise("Findings never leave this computer.")
        Promise("No analytics, no crash reporting, no third-party services.")
        Promise("Blanktick never changes a setting. It tells you what to change and you decide.")

        state.os?.let {
            Text(
                "Detected: ${it.displayName}",
                style = MaterialTheme.typography.labelSmall,
                color = c.inkFaint
            )
        }

        Spacer(Modifier.weight(1f))
        PrimaryButton("Run the first scan") { state.runScan() }
    }
}

@Composable
private fun Promise(text: String) {
    val c = LocalBlanktickColors.current
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("✓", color = c.pass, fontWeight = FontWeight.Bold)
        Text(text, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted)
    }
}

@Composable
private fun Centered(title: String, subtitle: String) {
    val c = LocalBlanktickColors.current
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(40.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(title, style = MaterialTheme.typography.titleLarge, color = c.ink)
        Spacer(Modifier.size(12.dp))
        Text(
            subtitle,
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkFaint,
            textAlign = TextAlign.Center
        )
    }
}

/**
 * An operating system this build does not know how to inspect.
 *
 * It would be trivial to fall through to the Linux collector and show a mostly
 * empty report. That would be a confident-looking screen produced by an app
 * that has no idea what it is looking at, which is precisely the failure the
 * whole architecture exists to prevent.
 */
@Composable
private fun Unsupported(osName: String) {
    val c = LocalBlanktickColors.current
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(40.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Blanktick does not know this system", style = MaterialTheme.typography.titleLarge, color = c.ink)
        Spacer(Modifier.size(12.dp))
        Text(
            "This build inspects Windows. It reports itself as \"$osName\", which is not Windows. " +
                "macOS and Linux are not supported in this release.\n\nRather than run checks written " +
                "for a different system and show you a score built from guesses, Blanktick stops here. " +
                "The link checker and the password checker still work — they do not depend on the " +
                "operating system.",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun Failed(message: String, onRetry: () -> Unit) {
    val c = LocalBlanktickColors.current
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(40.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("The scan did not finish", style = MaterialTheme.typography.titleLarge, color = c.ink)
        Spacer(Modifier.size(8.dp))
        Text(
            "No score is shown, because a partly-finished scan would be misleading.\n\n$message",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.size(24.dp))
        PrimaryButton("Try again", onClick = onRetry)
    }
}

@Composable
internal fun gradeColor(score: Int): Color {
    val c = LocalBlanktickColors.current
    return when {
        score >= 75 -> c.pass
        score >= 50 -> c.medium
        score >= 25 -> c.high
        else -> c.critical
    }
}
