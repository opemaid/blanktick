package com.blanktick.desktop.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.blanktick.desktop.AppState
import com.blanktick.desktop.Settings
import com.blanktick.desktop.history.ScanHistory
import androidx.compose.runtime.remember

/**
 * Settings — and a statement of exactly what gets written down.
 *
 * The app wrote nothing to disk until this screen existed. Rather than mention
 * that in a privacy policy, the screen prints the file's path and its entire
 * contents, so the claim is checkable in the place it is made.
 */
@Composable
fun SettingsScreen(state: AppState) {
    val c = LocalBlanktickColors.current
    val settings by state.settings.collectAsState()
    val error by state.settingsError.collectAsState()

    ScrollableColumn(spacing = BlanktickTokens.Space.s4) {
        Text("Settings", style = MaterialTheme.typography.headlineMedium, color = c.ink)

        error?.let { Notice(it) }

        // ---- motion -------------------------------------------------------
        SectionHeader("Motion")
        Card {
            Choice(
                label = "Reduce motion",
                detail = "Animations become instant. Blanktick cannot read your system's " +
                    "reduce-motion setting — Compose Desktop exposes no API for it, verified " +
                    "against the toolkit and against Windows itself — so this switch is the " +
                    "only way to honour that preference here.",
                options = listOf("Off", "On"),
                selectedIndex = if (settings.reduceMotion) 1 else 0
            ) { state.update { s -> s.copy(reduceMotion = it == 1) } }
        }

        // ---- appearance ---------------------------------------------------
        SectionHeader("Appearance")
        Card {
            Choice(
                label = "Theme",
                detail = "Dark is a first-class theme, not an inversion: the severity colours " +
                    "and surface tones are different values chosen for a near-black background.",
                options = listOf("System", "Light", "Dark"),
                selectedIndex = Settings.ThemeChoice.entries.indexOf(settings.theme)
            ) { i -> state.update { s -> s.copy(theme = Settings.ThemeChoice.entries[i]) } }

            Spacer(Modifier.height(BlanktickTokens.Space.s3))

            Choice(
                label = "Text size",
                detail = "Compose Desktop does not follow the Windows text-size slider, so it " +
                    "is set here instead.",
                options = listOf("Normal", "Large", "Larger"),
                selectedIndex = when {
                    settings.textScale >= 1.3f -> 2
                    settings.textScale >= 1.15f -> 1
                    else -> 0
                }
            ) { i ->
                state.update { s -> s.copy(textScale = listOf(1.0f, 1.15f, 1.3f)[i]) }
            }
        }

        // ---- history ------------------------------------------------------
        // The switch the settings file always had and this screen never showed:
        // history could be on while the text below said "no history".
        val historyVersion by state.historyVersion.collectAsState()
        val historyFile = ScanHistory.file()
        val scan by state.scan.collectAsState()
        val historyScans = remember(historyVersion, settings.keepHistory, scan) {
            if (historyFile.exists()) historyFile.useLines { l -> l.count { it.isNotBlank() } } else 0
        }
        SectionHeader("Scan history")
        Card {
            Choice(
                label = "Keep a history of scans",
                detail = "Off by default. When on, each finished scan adds one line to a separate " +
                    "file so an assistant connected over MCP can answer \"what changed since last " +
                    "time\". It keeps rule results only — which checks failed, their severity and " +
                    "points — never the details, addresses, account names or paths behind them. " +
                    "Turning it off stops recording; it does not delete what is already kept.",
                options = listOf("Off", "On"),
                selectedIndex = if (settings.keepHistory) 1 else 0
            ) { state.update { s -> s.copy(keepHistory = it == 1) } }
            Hairline()
            SelectionContainer {
                Text(historyFile.absolutePath, style = LedgerNumberStyle, color = c.ink)
            }
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    when (historyScans) {
                        0 -> "Nothing recorded."
                        1 -> "1 scan recorded."
                        else -> "$historyScans scans recorded."
                    },
                    style = MaterialTheme.typography.bodyLarge,
                    color = c.inkMuted
                )
                SecondaryButton("Delete history", enabled = historyScans > 0) { state.deleteHistory() }
            }
        }

        // ---- the file -----------------------------------------------------
        SectionHeader("What Blanktick writes down")
        Card {
            Text(
                "Blanktick writes at most two files. This one holds the preferences above and " +
                    "nothing else — no scan results, no scores, no findings, nothing identifying " +
                    "this computer. The other is the scan history above — " +
                    (if (settings.keepHistory) "history is on, so each scan is added to it. "
                    else "history is off, so nothing is added; a file left from before stays until you delete it. ") +
                    "Delete either at any time; the app starts again with defaults.",
                style = MaterialTheme.typography.bodyLarge,
                color = c.inkMuted
            )
            Hairline()
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s2)) {
                    Text(
                        Settings.file().absolutePath,
                        style = LedgerNumberStyle,
                        color = c.ink
                    )
                    Surface(
                        color = c.surfaceSunk,
                        shape = RoundedCornerShape(BlanktickTokens.Radius.md),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            settings.serialise().trim(),
                            style = LedgerNumberStyle,
                            color = c.inkMuted,
                            modifier = Modifier.padding(14.dp)
                        )
                    }
                }
            }
        }

        Text(
            "\"Nothing leaves this computer\" was never the same claim as \"nothing is " +
                "written\". The difference is above, rather than argued.",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkFaint,
            modifier = Modifier.widthIn(max = 640.dp)
        )
    }
}

/**
 * A labelled segmented choice.
 *
 * Segments rather than a switch: a switch encodes state in position alone, and
 * three of these have more than two states anyway.
 */
@Composable
private fun Choice(
    label: String,
    detail: String,
    options: List<String>,
    selectedIndex: Int,
    onSelect: (Int) -> Unit
) {
    val c = LocalBlanktickColors.current
    Column(verticalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s2)) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                label,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.SemiBold,
                color = c.ink
            )
            Row(horizontalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s1)) {
                options.forEachIndexed { i, option ->
                    val selected = i == selectedIndex
                    val shape = RoundedCornerShape(BlanktickTokens.Radius.sm)
                    Surface(
                        color = if (selected) c.ink else c.surfaceSunk,
                        shape = shape,
                        modifier = Modifier.interactive(shape) { onSelect(i) }
                    ) {
                        Text(
                            option,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                            color = if (selected) c.paper else c.inkMuted,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 9.dp)
                        )
                    }
                }
            }
        }
        Text(
            detail,
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted,
            modifier = Modifier.widthIn(max = 620.dp)
        )
    }
}
