package com.blanktick.desktop.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.blanktick.core.RuleReport
import com.blanktick.core.model.Category
import com.blanktick.core.model.ScoredFinding
import com.blanktick.desktop.AppState
import com.blanktick.desktop.PolicyFilter
import com.blanktick.desktop.ScanUiState
import com.blanktick.desktop.Screen

/**
 * The policy: every rule Blanktick ships, and what each one concluded here.
 *
 * This is where every dashboard component leads. The dashboard is a summary of
 * counts; a count you cannot open is a number you have to take on trust, so each
 * tile, bar and card lands here narrowed to the rules behind it.
 *
 * Like Threats, it is a view of the last scan and never a second collection.
 */
@Composable
fun PolicyScreen(state: AppState) {
    val scan by state.scan.collectAsState()
    val filter by state.policyFilter.collectAsState()

    when (val s = scan) {
        is ScanUiState.Complete -> PolicyView(s, filter, state::setPolicyFilter) { state.show(Screen.SCAN) }
        else -> PolicyEmpty { state.show(Screen.SCAN) }
    }
}

@Composable
private fun PolicyEmpty(onBack: () -> Unit) {
    val c = LocalBlanktickColors.current
    ScrollableColumn(spacing = 16.dp) {
        Text("Policy", style = MaterialTheme.typography.headlineMedium, color = c.ink)
        Notice("No scan yet. Run a scan on \"This computer\" and every rule's result appears here.")
        SecondaryButton("Go to This computer", onClick = onBack)
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PolicyView(
    state: ScanUiState.Complete,
    filter: PolicyFilter,
    onFilter: (PolicyFilter) -> Unit,
    onBack: () -> Unit
) {
    val c = LocalBlanktickColors.current
    val report = state.report
    val findingsByRule = report.result.findings.groupBy { it.finding.ruleId }

    val shown = report.rules.filter { rule ->
        matches(rule, filter.view) &&
            (filter.category == null || rule.category == filter.category) &&
            (filter.ruleId == null || rule.ruleId == filter.ruleId) &&
            (filter.severity == null || findingsByRule[rule.ruleId].orEmpty().any {
                it.finding.severity == filter.severity && it.finding.severity.isActionable
            })
    }

    ScrollableColumn(padding = 28.dp, spacing = 18.dp) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text("Policy", style = MaterialTheme.typography.headlineMedium, color = c.ink)
                Text(
                    "Every rule Blanktick checks, and what it found on this computer",
                    style = MaterialTheme.typography.labelMedium, color = c.inkFaint
                )
            }
            SecondaryButton("Back to dashboard", onClick = onBack)
        }

        // ---- filters -------------------------------------------------------
        Panel("Show") {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                PolicyFilter.View.entries.forEach { v ->
                    FilterChip(
                        label = "${v.label} · ${report.rules.count { matches(it, v) }}",
                        selected = filter.view == v && !filter.isNarrowed,
                        onClick = { onFilter(filter.copy(view = v, ruleId = null, severity = null)) }
                    )
                }
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    label = "Every area",
                    selected = filter.category == null && !filter.isNarrowed,
                    onClick = { onFilter(filter.copy(category = null, ruleId = null, severity = null)) }
                )
                Category.entries.forEach { cat ->
                    FilterChip(
                        label = cat.displayName,
                        selected = filter.category == cat && !filter.isNarrowed,
                        onClick = { onFilter(filter.copy(category = cat, ruleId = null, severity = null)) }
                    )
                }
            }
            if (filter.isNarrowed) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        if (filter.ruleId != null) "Showing one rule you selected."
                        else "Showing rules with a ${filter.severity!!.name.lowercase()} finding.",
                        style = MaterialTheme.typography.bodyMedium, color = c.inkMuted
                    )
                    Spacer(Modifier.width(12.dp))
                    FilterChip("Show all rules", selected = false, onClick = { onFilter(PolicyFilter.ALL) })
                }
            }
        }

        // ---- rules, grouped by area -----------------------------------------
        if (shown.isEmpty()) {
            Notice("No rules match this filter.")
        }
        shown.groupBy { it.category }.toSortedMap(compareBy { it.ordinal }).forEach { (cat, rules) ->
            Panel("${cat.displayName} · ${rules.size}") {
                rules.forEachIndexed { i, rule ->
                    if (i > 0) Hairline()
                    RuleEntry(rule, findingsByRule[rule.ruleId].orEmpty(), highlighted = rule.ruleId == filter.ruleId)
                }
            }
        }
    }
}

private fun matches(rule: RuleReport, view: PolicyFilter.View): Boolean = when (view) {
    PolicyFilter.View.ALL -> true
    PolicyFilter.View.RAN -> rule.outcome != RuleReport.Outcome.NOT_APPLICABLE
    PolicyFilter.View.PASSED -> rule.outcome == RuleReport.Outcome.PASSED
    PolicyFilter.View.FAILED -> rule.outcome == RuleReport.Outcome.FAILED
    PolicyFilter.View.NOT_CHECKABLE -> rule.outcome == RuleReport.Outcome.NOT_APPLICABLE
}

@Composable
private fun RuleEntry(rule: RuleReport, findings: List<ScoredFinding>, highlighted: Boolean) {
    val c = LocalBlanktickColors.current
    val hasInfo = findings.any { !it.finding.severity.isActionable }
    val (label, tone) = when {
        // A rule whose only findings are informational passed and cost nothing,
        // but has something worth knowing — say both.
        rule.outcome == RuleReport.Outcome.PASSED && hasInfo -> "PASSED · WORTH KNOWING" to c.pass
        rule.outcome == RuleReport.Outcome.PASSED -> "PASSED" to c.pass
        rule.outcome == RuleReport.Outcome.FAILED -> "NEEDS ATTENTION" to c.high
        rule.skippedAsWrongPlatform -> "NOT APPLICABLE · written for a phone" to c.inkFaint
        else -> "NOT CHECKABLE · this computer wouldn't answer" to c.inkFaint
    }

    Surface(
        color = if (highlighted) c.kelpTint else Color.Transparent,
        shape = RoundedCornerShape(BlanktickTokens.Radius.md),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(horizontal = 8.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    rule.description,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = c.ink,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(12.dp))
                Text(label, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = tone)
            }
            Text(rule.ruleId, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace, color = c.inkFaint)
            // Informational findings are shown too — this page is the only place
            // they appear. They cost no points (the card shows no deduction) and
            // the label above says the rule passed, so they read as context,
            // not as something to fix.
            findings.forEach { FindingCard(it) }
        }
    }
}

@Composable
private fun FilterChip(label: String, selected: Boolean, onClick: () -> Unit) {
    val c = LocalBlanktickColors.current
    val shape = RoundedCornerShape(BlanktickTokens.Radius.sm)
    val (source, hovered) = rememberHoverState()
    Surface(
        color = when {
            selected -> c.kelpTint
            hovered -> c.surfaceSunk
            else -> c.surface
        },
        shape = shape,
        border = BorderStroke(1.dp, if (selected) c.kelp else c.surfaceSunk),
        modifier = Modifier.hoverable(source).interactive(shape, onClick = onClick)
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
            color = if (selected) c.ink else c.inkMuted,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp)
        )
    }
}
