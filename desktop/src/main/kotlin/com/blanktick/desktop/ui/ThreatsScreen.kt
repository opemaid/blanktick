package com.blanktick.desktop.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.VerticalScrollbar
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollbarAdapter
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.blanktick.core.LevelSummary
import com.blanktick.core.ThreatSummary
import com.blanktick.desktop.PolicyFilter
import androidx.compose.foundation.hoverable
import com.blanktick.core.model.Severity

/**
 * Threat posture across every monitored level.
 *
 * ## The design problem this screen exists to solve
 *
 * The dashboard answers "what is wrong with this computer". It cannot easily
 * answer "what is this computer being watched for", because a finding is loud
 * and an absence is silent. On a product whose whole claim is coverage honesty,
 * the silent half is the half that matters, so here every level is a row whether
 * or not it found anything, and the not-checkable segment is drawn with the same
 * weight as the rest.
 *
 * ## Why the not-checkable segment is hatched, not just coloured
 *
 * Measured, not assumed: `Severity.pass` (#0F4D3F) against `Severity.notChecked`
 * (#666D6B) is a contrast ratio of **1.84:1** in light mode and 1.78:1 in dark.
 * Both clear 3:1 against the *surface*, so each is legible on its own — but they
 * are nearly indistinguishable from **each other**, which is exactly the
 * confusion this product exists to prevent. Hue cannot carry that distinction,
 * so it is carried by texture (45° hatch), by position (always last), and by an
 * explicit count in the row label. Three channels, none of them colour alone.
 *
 * See `severityGlyph` for the same principle applied to severity.
 */
@Composable
fun ThreatsScreen(summary: ThreatSummary, onOpenPolicy: (PolicyFilter) -> Unit) {
    val c = LocalBlanktickColors.current
    val listState = rememberLazyListState()

    Box(Modifier.fillMaxSize()) {
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize().padding(BlanktickTokens.Space.s6),
        verticalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s5)
    ) {
        item { ThreatHeader(summary) }
        item { CensusPanel(summary, onOpenPolicy) }

        item {
            Panel("Monitored levels") {
                summary.levels.chunked(3).forEach { row ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        row.forEach { level ->
                            LevelTile(Modifier.weight(1f), level, !summary.incomplete) {
                                onOpenPolicy(PolicyFilter(category = level.category))
                            }
                        }
                        repeat(3 - row.size) { Spacer(Modifier.weight(1f)) }
                    }
                }
            }
        }

        item {
            Panel("Everything found") {
                if (summary.allFindings.isEmpty()) {
                    Notice(
                        "Nothing was found on the levels that answered. That is not the " +
                            "same as nothing being wrong — see the not-checkable counts above."
                    )
                } else {
                    summary.allFindings.forEach { sf ->
                        FindingCard(sf) { onOpenPolicy(PolicyFilter(ruleId = sf.finding.ruleId)) }
                    }
                }
            }
        }
    }

        VerticalScrollbar(
            adapter = rememberScrollbarAdapter(listState),
            modifier = Modifier.align(Alignment.CenterEnd).fillMaxHeight()
        )
    }
}

/**
 * The severity census.
 *
 * Deliberately not a score. The dashboard owns the score; repeating it here
 * would create two numbers that can disagree after a partial scan.
 */
@Composable
private fun ThreatHeader(summary: ThreatSummary) {
    val c = LocalBlanktickColors.current
    Column(verticalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s3)) {
        Text(
            "Threats",
            style = MaterialTheme.typography.headlineMedium,
            color = c.ink
        )
        Text(
            if (summary.incomplete) {
                "Across all monitored levels. Totals are withheld because the scan did not finish."
            } else {
                "${summary.totalFound} of ${summary.totalRules} checks found something. " +
                    "${summary.totalClear} came back clear. " +
                    "${summary.totalNotCheckable} could not be checked."
            },
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted
        )

    }
}

@Composable
private fun CensusPanel(summary: ThreatSummary, onOpenPolicy: (PolicyFilter) -> Unit) {
    val c = LocalBlanktickColors.current
    if (summary.incomplete) {
        Panel("Severity census") {
            Notice(
                "Totals are withheld — the scan did not finish. The findings are still listed " +
                    "below; a partial scan is a partial view, not a clean bill of health."
            )
        }
        return
    }
    Panel("Severity census") {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(3.dp)) {
            for (sev in listOf(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)) {
                SeverityTile(Modifier.weight(1f), sev, summary.countOf(sev)) {
                    onOpenPolicy(PolicyFilter(PolicyFilter.View.FAILED, severity = sev))
                }
            }
        }
        Text(
            "Zero counts are shown too — “0 critical” is reassurance a missing row cannot give.",
            style = MaterialTheme.typography.labelMedium,
            color = c.inkFaint
        )
    }
}

@Composable
private fun SeverityTile(modifier: Modifier, severity: Severity, count: Int, onClick: () -> Unit) {
    val c = LocalBlanktickColors.current
    val tone = if (count == 0) c.inkFaint else c.forSeverity(severity)
    val shape = RoundedCornerShape(BlanktickTokens.Radius.md)
    val (source, hovered) = rememberHoverState()
    // A zero opens nothing: there are no rules behind it to show.
    val enabled = count > 0
    Surface(
        modifier.hoverable(source, enabled).interactive(shape, enabled, onClick),
        color = if (hovered && enabled) c.kelpTint else c.surfaceSunk,
        shape = shape
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(severityLabel(severity), style = MaterialTheme.typography.labelMedium, color = c.inkMuted)
            Text(
                "$count",
                style = LedgerNumberStyle.copy(fontSize = 34.sp, fontWeight = FontWeight.SemiBold),
                color = tone
            )
        }
    }
}

@Composable
private fun SeverityCount(severity: Severity, count: Int) {
    val c = LocalBlanktickColors.current
    val tone = c.forSeverity(severity)
    // A zero recedes to muted ink: it is true, it is worth showing, and it must
    // not read as loudly as a real count of the same severity.
    val emphasis = if (count == 0) c.inkFaint else tone

    Row(
        horizontalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s2),
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.semantics {
            contentDescription = "$count ${severityLabel(severity)}"
        }
    ) {
        Text(
            severityGlyph(severity),
            color = emphasis,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.clearAndSetSemantics { }
        )
        Text(
            "$count",
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Bold,
            color = emphasis,
            modifier = Modifier.clearAndSetSemantics { }
        )
        Text(
            severityLabel(severity),
            style = MaterialTheme.typography.bodySmall,
            color = c.inkMuted,
            modifier = Modifier.clearAndSetSemantics { }
        )
    }
}

/**
 * One monitored level: name, coverage bar, reconciled counts.
 *
 * A level that answered nothing gets a sentence instead of a bar. An empty bar
 * and a bar full of passes look similar at a glance and mean opposite things.
 */
@Composable
private fun LevelRow(level: LevelSummary, showCounts: Boolean) {
    val c = LocalBlanktickColors.current

    Card {
        Column(verticalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s3)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    level.category.displayName,
                    style = MaterialTheme.typography.titleMedium,
                    color = c.ink
                )
                level.worst?.let { worst ->
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s2),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            severityGlyph(worst),
                            color = c.forSeverity(worst),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.clearAndSetSemantics { }
                        )
                        Text(
                            "worst: ${severityLabel(worst)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = c.forSeverity(worst),
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            if (level.total == 0) {
                Text(
                    "No checks exist for this level yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = c.inkFaint
                )
            } else if (level.answered == 0) {
                Text(
                    "Not monitored on this device — none of its ${level.total} checks could run.",
                    style = MaterialTheme.typography.bodySmall,
                    color = c.notChecked,
                    fontWeight = FontWeight.Bold
                )
                CoverageBar(level)
            } else {
                CoverageBar(level)
            }

            if (showCounts && level.total > 0) {
                Text(
                    buildString {
                        append("${level.found} found")
                        append("  ·  ${level.clear} clear")
                        append("  ·  ${level.notCheckable} not checkable")
                        if (level.wrongPlatform > 0) {
                            append(" (${level.wrongPlatform} written for another device")
                            if (level.unobservable > 0) {
                                append(", ${level.unobservable} unanswered")
                            }
                            append(")")
                        } else if (level.unobservable > 0) {
                            append(" (${level.unobservable} unanswered)")
                        }
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = c.inkMuted
                )
            }
        }
    }
}

/**
 * One monitored level as a compact tile in the grid: name, worst badge, the
 * coverage bar, and reconciled counts.
 */
@Composable
private fun LevelTile(modifier: Modifier, level: LevelSummary, showCounts: Boolean, onClick: () -> Unit) {
    val c = LocalBlanktickColors.current
    val shape = RoundedCornerShape(BlanktickTokens.Radius.md)
    val (source, hovered) = rememberHoverState()
    Surface(
        modifier.hoverable(source).interactive(shape, onClick = onClick),
        color = if (hovered) c.kelpTint else c.surfaceSunk,
        shape = shape
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    level.category.displayName,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = c.ink,
                    maxLines = 1
                )
                level.worst?.let {
                    Text(
                        severityGlyph(it),
                        color = c.forSeverity(it),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.clearAndSetSemantics { }
                    )
                }
            }
            if (level.total > 0) CoverageBar(level)
            Text(
                when {
                    level.total == 0 -> "no checks for this level"
                    showCounts -> "${level.found} found · ${level.clear} clear · ${level.notCheckable} not checkable"
                    else -> "${level.total} checks"
                },
                style = MaterialTheme.typography.labelSmall,
                color = c.inkMuted
            )
        }
    }
}

/**
 * Stacked coverage bar: found → clear → not-checkable, always in that order.
 *
 * Fixed order matters more than it looks. If segments reordered by size the bar
 * would be a different shape per row and the eye could no longer compare rows,
 * which is the only thing a six-row stack is for.
 *
 * A 2px surface-coloured gap separates segments so adjacent fills never touch —
 * without it a clear/not-checkable boundary at 1.84:1 is invisible.
 */
@Composable
private fun CoverageBar(level: LevelSummary) {
    val c = LocalBlanktickColors.current
    val total = level.total.coerceAtLeast(1)

    val segments = listOf(
        Triple(level.found, c.forSeverity(level.worst ?: Severity.LOW), false),
        Triple(level.clear, c.pass, false),
        Triple(level.notCheckable, c.notChecked, true)
    ).filter { it.first > 0 }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            // NOT fillMaxSize: inside a LazyColumn item that resolves to 0dp and
            // the bar silently disappears. This exact bug ate the severity rail
            // on the dashboard once already.
            .height(BAR_HEIGHT)
            .clip(RoundedCornerShape(BlanktickTokens.Radius.sm))
            .background(c.surfaceSunk)
            .semantics {
                contentDescription =
                    "${level.category.displayName}: ${level.found} found, " +
                        "${level.clear} clear, ${level.notCheckable} not checkable, " +
                        "of ${level.total} checks"
            },
        horizontalArrangement = Arrangement.spacedBy(SEGMENT_GAP)
    ) {
        for ((count, colour, hatched) in segments) {
            Box(
                modifier = Modifier
                    .weight(count.toFloat() / total)
                    .height(BAR_HEIGHT)
                    .background(if (hatched) colour.copy(alpha = HATCH_BASE_ALPHA) else colour)
                    .then(if (hatched) Modifier.drawBehind { hatch(colour) } else Modifier)
            )
        }
    }
}

/**
 * 45° hatch, drawn over the not-checkable segment.
 *
 * The texture is the accessible channel that hue cannot provide here (see the
 * 1.84:1 measurement in the file header). It is also the honest one: a hatched
 * block reads as "incomplete" to someone who never reads the legend.
 */
private fun DrawScope.hatch(colour: Color) {
    val step = HATCH_STEP_PX
    var x = -size.height
    while (x < size.width + size.height) {
        drawLine(
            color = colour,
            start = Offset(x, size.height),
            end = Offset(x + size.height, 0f),
            strokeWidth = HATCH_STROKE_PX
        )
        x += step
    }
}

/** 10dp: thick enough to read the hatch, thin enough not to become a chart. */
private val BAR_HEIGHT = 10.dp

/** The dataviz spacer — 2px of surface so adjacent fills never share an edge. */
private val SEGMENT_GAP = 2.dp

private const val HATCH_BASE_ALPHA = 0.28f
private const val HATCH_STEP_PX = 7f
private const val HATCH_STROKE_PX = 2f
