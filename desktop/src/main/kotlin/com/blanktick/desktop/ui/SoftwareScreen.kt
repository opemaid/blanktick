package com.blanktick.desktop.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
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
import com.blanktick.core.intel.EolCatalog
import com.blanktick.desktop.AppState
import com.blanktick.desktop.ScanUiState

/**
 * What is installed on this computer.
 *
 * ## What this screen is, and is not
 *
 * It is the OS's own uninstall registry, read and sorted. It is **not** an
 * antivirus scan: nothing is hashed, no file is opened, no reputation service is
 * consulted, and none could be — the app has no network.
 *
 * Two rules run against this list (`DSK-SW-001`, `DSK-SW-002`) and their
 * findings appear on the dashboard with everything else. This screen exists for
 * the question the dashboard cannot answer: *what is actually on here?*
 */
@Composable
fun SoftwareScreen(state: AppState) {
    val c = LocalBlanktickColors.current
    val programs by state.programs.collectAsState()

    ScrollableColumn(spacing = BlanktickTokens.Space.s4) {
        Text("Installed software", style = MaterialTheme.typography.headlineMedium, color = c.ink)

        if (programs == null) {
            val scan by state.scan.collectAsState()
            if (scan is ScanUiState.Scanning) {
                Notice(
                    "Scanning this computer… the software list appears when the scan finishes " +
                        "(about 100 seconds). You can watch progress on \"This computer\"."
                )
            } else {
                Notice(
                    "Run a scan and this fills in. The list comes from the same place Windows " +
                        "Settings reads, so it costs nothing extra — but it is a product of the " +
                        "scan rather than a separate walk of your disk."
                )
                PrimaryButton("Run a scan", enabled = scan !is ScanUiState.Scanning) { state.runScan() }
            }
            return@ScrollableColumn
        }

        val list = programs.orEmpty()
        val eol = list.filter { EolCatalog.match(it.name, it.version) != null }
        val unattributed = list.filter { it.userWritableLocation && it.publisher.isNullOrBlank() }
        val userWritable = list.filter { it.userWritableLocation }

        // The dashboard: the four numbers the sections below break down, read at a
        // glance. A tile carries a severity tone only when its count is a real
        // attention item; a zero stays neutral rather than green, because this
        // screen is "a list, not a verdict" (see the notice below) and a wall of
        // green ticks would be exactly the verdict it refuses to give.
        // Each tile narrows the full list below to the programs behind its number.
        // "User-writable" had no list of its own at all — only its no-publisher
        // subset was itemised — so its count was the one number here you could
        // not trace to rows.
        var shown by remember { mutableStateOf(0) }
        SoftwareDashboard(
            total = list.size,
            pastSupport = eol.size,
            noPublisher = unattributed.size,
            userWritable = userWritable.size,
            selected = shown,
            onSelect = { shown = if (shown == it) 0 else it }
        )

        Text(
            "${list.size} programs. ${userWritable.size} are installed somewhere you can write " +
                "without administrator permission, which is normal for package managers and " +
                "several well-known apps. ${unattributed.size} of those name no publisher.",
            style = MaterialTheme.typography.bodyLarge,
            color = c.inkMuted,
            modifier = Modifier.widthIn(max = 720.dp)
        )

        Notice(
            "This is a list, not a verdict. Blanktick does not hash files, does not consult a " +
                "reputation service, and cannot tell you whether a program is malicious — that " +
                "needs a server. It checks two things it can answer offline: whether something " +
                "is past its vendor's security support, and whether something installed itself " +
                "somewhere it needed no permission to reach, without saying who made it."
        )

        if (eol.isNotEmpty()) {
            SectionHeader("Past security support", eol.size.toString())
            Card {
                eol.forEach { p ->
                    val entry = EolCatalog.match(p.name, p.version)
                    ProgramRow(p.name, p.version, entry?.let { "unsupported since ${it.endedYear}" }, c.high)
                }
            }
        }

        if (unattributed.isNotEmpty()) {
            SectionHeader("No publisher, user-writable location", unattributed.size.toString())
            Card {
                unattributed.forEach { ProgramRow(it.name, it.version, it.installLocation, c.medium) }
            }
        }

        val (title, rows) = when (shown) {
            1 -> "Past security support" to eol
            2 -> "No publisher named" to unattributed
            3 -> "Installed where you can write without permission" to userWritable
            else -> "Everything installed" to list
        }
        SectionHeader(title, rows.size.toString())
        if (shown != 0) {
            SecondaryButton("Show everything installed") { shown = 0 }
        }
        Card {
            SelectionContainer {
                Column {
                    rows.sortedBy { it.name.lowercase() }.forEach { p ->
                        ProgramRow(
                            p.name,
                            p.version,
                            p.publisher ?: "no publisher named",
                            if (p.publisher.isNullOrBlank()) c.notChecked else c.inkMuted
                        )
                    }
                }
            }
        }
    }
}

/**
 * The four headline counts as a row of tiles.
 *
 * Deliberately not a score. Each tile is a count the sections below itemise, so a
 * number can always be traced to the rows that make it up — the same "the
 * arithmetic is inspectable" contract the posture dashboard's ledger keeps. Tone
 * follows [severityLabel]'s rule that colour is the third channel after the
 * number and the label, and appears only where the count is something to look at.
 */
@Composable
private fun SoftwareDashboard(
    total: Int,
    pastSupport: Int,
    noPublisher: Int,
    userWritable: Int,
    selected: Int,
    onSelect: (Int) -> Unit
) {
    val c = LocalBlanktickColors.current
    Row(
        Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s3)
    ) {
        StatTile(Modifier.weight(1f), total, "Installed", c.ink, selected == 0) { onSelect(0) }
        StatTile(
            Modifier.weight(1f), pastSupport, "Past security support",
            if (pastSupport > 0) c.high else c.inkMuted, selected == 1
        ) { onSelect(1) }
        StatTile(
            Modifier.weight(1f), noPublisher, "No publisher",
            if (noPublisher > 0) c.medium else c.inkMuted, selected == 2
        ) { onSelect(2) }
        StatTile(Modifier.weight(1f), userWritable, "User-writable", c.inkMuted, selected == 3) { onSelect(3) }
    }
}

@Composable
private fun StatTile(
    modifier: Modifier,
    value: Int,
    label: String,
    tone: androidx.compose.ui.graphics.Color,
    selected: Boolean,
    onClick: () -> Unit
) {
    val c = LocalBlanktickColors.current
    val shape = RoundedCornerShape(BlanktickTokens.Radius.lg)
    val (source, hovered) = rememberHoverState()
    Surface(
        color = if (selected || hovered) c.kelpTint else c.surface,
        shape = shape,
        border = if (selected) BorderStroke(1.dp, c.kelp) else null,
        modifier = modifier
            .fillMaxHeight()
            .hoverable(source)
            .interactive(shape, onClick = onClick)
            .blanktickElevation(BlanktickTokens.Elevation.rest, shape)
    ) {
        Column(
            Modifier.padding(horizontal = 18.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s1)
        ) {
            Text(
                value.toString(),
                style = MaterialTheme.typography.headlineMedium,
                color = tone,
                maxLines = 1
            )
            Text(
                label,
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkMuted
            )
        }
    }
}

@Composable
private fun ProgramRow(name: String, version: String?, trailing: String?, tone: androidx.compose.ui.graphics.Color) {
    val c = LocalBlanktickColors.current
    Row(
        Modifier.fillMaxWidth().heightIn(min = BlanktickTokens.MinPointerTarget),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            name,
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.SemiBold,
            color = c.ink,
            modifier = Modifier.weight(1f)
        )
        version?.let {
            Text(it, style = LedgerNumberStyle, color = c.inkMuted)
            Spacer(Modifier.width(BlanktickTokens.Space.s3))
        }
        trailing?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodyMedium,
                color = tone,
                modifier = Modifier.widthIn(max = 320.dp)
            )
        }
    }
}
