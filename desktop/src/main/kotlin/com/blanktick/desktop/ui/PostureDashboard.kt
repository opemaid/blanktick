package com.blanktick.desktop.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.hoverable
import androidx.compose.ui.graphics.Color
import com.blanktick.desktop.PolicyFilter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.blanktick.core.RuleReport
import com.blanktick.core.ScanReport
import com.blanktick.core.model.Category
import com.blanktick.core.model.ScanResult
import com.blanktick.desktop.ScanUiState

/**
 * The results view for "This computer" — a panel dashboard in the shape of a
 * security-posture console (a scan pipeline, a score, deductions by area,
 * findings, and what was checked), but carrying only what this one offline
 * machine actually produced. There is no fleet, no case queue, no industry
 * comparison, because there is no data for them and inventing it is the one
 * thing this product refuses.
 */
@Composable
fun PostureDashboard(
    state: ScanUiState.Complete,
    onScan: () -> Unit,
    onOpenPolicy: (PolicyFilter) -> Unit
) {
    val c = LocalBlanktickColors.current
    val r = state.report.result
    val wrong = state.report.skippedWrongPlatform.size
    val unobs = state.report.skippedUnobservable.size
    val incomplete = state.collectionCaveats.isNotEmpty()

    ScrollableColumn(padding = 28.dp, spacing = 18.dp) {

        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text("Security posture", style = MaterialTheme.typography.headlineMedium, color = c.ink)
                Text(
                    "This computer · offline scan · nothing left this machine",
                    style = MaterialTheme.typography.labelMedium, color = c.inkFaint
                )
            }
            PrimaryButton("Scan again", onClick = onScan)
        }

        // The reasons, not just the verdict. The score panel says "no score"; this
        // says why, above everything it qualifies — the older dashboard did, and
        // this one had dropped it, leaving "the scan did not finish" unexplained.
        if (incomplete) {
            Notice("This scan is incomplete. " + state.collectionCaveats.joinToString(" "))
        }
        state.collectionNotes.forEach { Notice(it) }

        // ---- pipeline ----------------------------------------------------
        Panel("Scan pipeline") {
            // Equal heights: when one sub-line wraps (larger text), the tiles
            // otherwise end at different depths.
            Row(
                Modifier.fillMaxWidth().height(IntrinsicSize.Min),
                horizontalArrangement = Arrangement.spacedBy(3.dp)
            ) {
                PipelineTile(Modifier.weight(1f), "Rules", "${r.checksRun + r.checksSkipped}", "shipped checks") {
                    onOpenPolicy(PolicyFilter(PolicyFilter.View.ALL))
                }
                PipelineTile(Modifier.weight(1f), "Checks ran", "${r.checksRun}", "on this machine") {
                    onOpenPolicy(PolicyFilter(PolicyFilter.View.RAN))
                }
                PipelineTile(Modifier.weight(1f), "Not checkable", "${r.checksSkipped}",
                    "$wrong wrong device · $unobs wouldn’t answer") {
                    onOpenPolicy(PolicyFilter(PolicyFilter.View.NOT_CHECKABLE))
                }
                PipelineTile(Modifier.weight(1f), "Findings", "${r.actionableFindings.size}", "need attention") {
                    onOpenPolicy(PolicyFilter(PolicyFilter.View.FAILED))
                }
            }
            Text(
                "A funnel of this scan, not a fleet. “Not checkable” is carried to the end, never folded into “clear”. " +
                    "Click any tile to see the rules behind it.",
                style = MaterialTheme.typography.labelMedium, color = c.inkFaint
            )
        }

        // ---- score | deductions ------------------------------------------
        // IntrinsicSize.Min + fillMaxHeight makes the two panels the same height,
        // so their bottoms align instead of leaving one panel with ragged dead
        // space beside a taller neighbour.
        Row(
            Modifier.fillMaxWidth().height(IntrinsicSize.Min),
            horizontalArrangement = Arrangement.spacedBy(18.dp)
        ) {
            Panel(
                "Score",
                Modifier.weight(1f).fillMaxHeight(),
                onClick = { onOpenPolicy(PolicyFilter.ALL) }
            ) {
                if (incomplete) {
                    Notice(
                        "No score this time. The scan did not finish, and a number built from a " +
                            "partial reading would describe how little was checked, not this computer."
                    )
                } else {
                    ScoreGauge(r.score, r.grade.label, state.previousScore, gradeColor(r.score))
                    Text(
                        "A score is 100 − ${100 - r.score} deductions, so it only means something " +
                            "next to coverage: ${r.checksSkipped} checks could not run.",
                        style = MaterialTheme.typography.bodyMedium, color = c.inkMuted,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
            Panel("Deductions by area", Modifier.weight(1f).fillMaxHeight()) {
                DeductionBars(r) { cat -> onOpenPolicy(PolicyFilter(PolicyFilter.View.FAILED, category = cat)) }
            }
        }

        // ---- what was checked (full width, short grid) -------------------
        // A short row-grid, not a tall column paired beside the findings — that
        // pairing stretched this panel into a mostly-empty box.
        Panel("What was checked") {
            WhatWasChecked(state.report) { cat -> onOpenPolicy(PolicyFilter(PolicyFilter.View.ALL, category = cat)) }
        }

        // ---- findings (full width — the tall, variable-length content) ----
        Panel("Needs attention") {
            val findings = r.actionableFindings.sortedByDescending { it.deduction }
            if (findings.isEmpty()) {
                Notice("Nothing to fix among the ${r.checksRun} checks that ran. That is not the same as safe.")
            } else {
                findings.forEach { sf ->
                    FindingCard(sf) { onOpenPolicy(PolicyFilter(ruleId = sf.finding.ruleId)) }
                }
            }
        }
    }
}

// --------------------------------------------------------------- pieces

@Composable
internal fun Panel(
    title: String,
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    val c = LocalBlanktickColors.current
    val shape = RoundedCornerShape(BlanktickTokens.Radius.lg)
    val (source, hovered) = rememberHoverState()
    Surface(
        modifier
            .fillMaxWidth()
            .then(
                if (onClick != null) Modifier.hoverable(source).interactive(shape, onClick = onClick)
                else Modifier
            ),
        color = c.surface,
        shape = shape,
        border = BorderStroke(1.dp, if (onClick != null && hovered) c.kelp else c.surfaceSunk)
    ) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text(
                title.uppercase(),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = c.inkFaint
            )
            content()
        }
    }
}

@Composable
private fun PipelineTile(modifier: Modifier, label: String, value: String, sub: String, onClick: () -> Unit) {
    val c = LocalBlanktickColors.current
    val shape = RoundedCornerShape(BlanktickTokens.Radius.md)
    val (source, hovered) = rememberHoverState()
    Surface(
        modifier.fillMaxHeight().hoverable(source).interactive(shape, onClick = onClick),
        color = if (hovered) c.kelpTint else c.surfaceSunk,
        shape = shape
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = c.inkMuted)
            Text(value, style = LedgerNumberStyle.copy(fontSize = 34.sp, fontWeight = FontWeight.SemiBold), color = c.ink)
            Text(sub, style = MaterialTheme.typography.labelSmall, color = c.inkFaint)
        }
    }
}

@Composable
private fun DeductionBars(result: ScanResult, onCategory: (Category) -> Unit) {
    val c = LocalBlanktickColors.current
    val cats = result.categories.filter { it.deduction > 0 }.sortedByDescending { it.deduction }
    if (cats.isEmpty()) {
        Text("No deductions — nothing that ran cost points.", style = MaterialTheme.typography.bodyMedium, color = c.inkMuted)
        return
    }
    val max = cats.maxOf { it.deduction }.coerceAtLeast(1)
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        cats.forEach { cat ->
            val shape = RoundedCornerShape(BlanktickTokens.Radius.sm)
            val (source, hovered) = rememberHoverState()
            Column(
                Modifier
                    .hoverable(source)
                    .interactive(shape) { onCategory(cat.category) }
                    .background(if (hovered) c.surfaceSunk else Color.Transparent, shape)
                    .padding(4.dp),
                verticalArrangement = Arrangement.spacedBy(5.dp)
            ) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(cat.category.displayName, style = MaterialTheme.typography.bodyLarge, color = c.ink)
                    Text("−${cat.deduction}", style = LedgerNumberStyle, color = c.inkMuted)
                }
                Box(
                    Modifier.fillMaxWidth().height(12.dp)
                        .background(c.surfaceSunk, RoundedCornerShape(6.dp))
                ) {
                    Box(
                        Modifier.fillMaxWidth(cat.deduction / max.toFloat()).height(12.dp)
                            .background(c.medium, RoundedCornerShape(6.dp))
                    )
                }
            }
        }
        Text(
            "Only areas with a deduction appear. Each category is capped, so one bad area cannot sink the score.",
            style = MaterialTheme.typography.labelMedium, color = c.inkFaint
        )
    }
}

@Composable
private fun WhatWasChecked(report: ScanReport, onCategory: (Category) -> Unit) {
    val byCat = report.rules.groupBy { it.category }
    // A 3-across grid so, full width, it stays short and wide instead of a
    // narrow column with dead space to its right.
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Category.entries.chunked(3).forEach { rowCats ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(18.dp)) {
                rowCats.forEach { cat ->
                    val rules = byCat[cat].orEmpty()
                    val ran = rules.count { it.outcome != RuleReport.Outcome.NOT_APPLICABLE }
                    val shape = RoundedCornerShape(BlanktickTokens.Radius.sm)
                    val (source, hovered) = rememberHoverState()
                    Box(
                        Modifier
                            .weight(1f)
                            .hoverable(source)
                            .interactive(shape) { onCategory(cat) }
                            .background(if (hovered) LocalBlanktickColors.current.surfaceSunk else Color.Transparent, shape)
                            .padding(4.dp)
                    ) {
                        StatusRow(
                            ran = ran > 0,
                            label = cat.displayName,
                            sub = if (ran > 0) "$ran check(s) ran" else "not observable on this device"
                        )
                    }
                }
                repeat(3 - rowCats.size) { Spacer(Modifier.weight(1f)) }
            }
        }
    }
}

@Composable
private fun StatusRow(ran: Boolean, label: String, sub: String) {
    val c = LocalBlanktickColors.current
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Surface(
            Modifier.size(26.dp),
            color = if (ran) c.kelpTint else c.surfaceSunk,
            shape = RoundedCornerShape(13.dp),
            border = BorderStroke(1.dp, if (ran) c.pass else c.inkFaint)
        ) {
            Text(
                if (ran) "✓" else "–",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = if (ran) c.pass else c.inkFaint,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
        Column {
            Text(label, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold, color = c.ink)
            Text(sub, style = MaterialTheme.typography.labelSmall, color = c.inkFaint)
        }
    }
}
