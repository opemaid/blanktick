package com.blanktick.app.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.blanktick.app.ScanUiState
import com.blanktick.core.RuleReport
import com.blanktick.core.ScanReport
import com.blanktick.core.model.ScoredFinding
import com.blanktick.core.model.Severity

@Composable
fun HomeScreen(
    state: ScanUiState,
    onScan: () -> Unit,
    padding: PaddingValues,
    modifier: Modifier = Modifier
) {
    val c = LocalBlanktickColors.current

    Surface(modifier = modifier.fillMaxSize().padding(padding), color = c.paper) {
        when (state) {
            is ScanUiState.FirstRun -> FirstRun(onScan)
            is ScanUiState.Scanning -> Scanning(state.step)
            is ScanUiState.Failed -> Failed(state.message, onScan)
            is ScanUiState.Complete -> Results(state, onScan)
        }
    }
}

// ---------------------------------------------------------------- first run

@Composable
private fun FirstRun(onScan: () -> Unit) {
    val c = LocalBlanktickColors.current
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        Spacer(Modifier.width(0.dp))
        Text(
            "Blanktick checks this phone.\nNothing else.",
            style = MaterialTheme.typography.headlineMedium,
            color = c.ink
        )
        Text(
            "It works entirely offline. There is no account, no upload and no server — " +
                "because the app has no permission to reach the internet at all.",
            style = MaterialTheme.typography.bodyLarge,
            color = c.inkMuted
        )
        Promise("Your passwords are checked against a list built into the app. Nothing is sent, not even a hash.")
        Promise("Findings never leave this device.")
        Promise("No analytics, no crash-reporting SDK, no third-party code.")

        Spacer(Modifier.weight(1f))
        PrimaryButton("Run the first scan", onScan)
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

// ----------------------------------------------------------------- scanning

@Composable
private fun Scanning(step: String) {
    val c = LocalBlanktickColors.current
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(step, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted)
        Spacer(Modifier.size(12.dp))
        Text(
            "Everything is happening on this device.\nNothing is being sent anywhere.",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkFaint,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun Failed(message: String, onRetry: () -> Unit) {
    val c = LocalBlanktickColors.current
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("The scan did not finish", style = MaterialTheme.typography.titleLarge, color = c.ink)
        Spacer(Modifier.size(8.dp))
        // Shown rather than hidden: a partial scan must never be presented as a
        // clean result, so the user is told the run was incomplete.
        Text(
            "No score is shown, because a partly-finished scan would be misleading.\n\n$message",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.size(24.dp))
        PrimaryButton("Try again", onRetry)
    }
}

// ------------------------------------------------------------------ results

@Composable
private fun Results(state: ScanUiState.Complete, onScan: () -> Unit) {
    val c = LocalBlanktickColors.current
    val report = state.report
    val result = report.result
    val actionable = result.actionableFindings
    val notCheckable = report.notApplicable

    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp, 16.dp, 16.dp, 32.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Blanktick", style = MaterialTheme.typography.titleMedium, color = c.ink)
                Text(
                    "Offline · no network permission",
                    style = MaterialTheme.typography.labelSmall,
                    color = c.inkFaint
                )
            }
        }

        item {
            ScoreDial(
                score = result.score,
                previous = state.previousScore,
                grade = result.grade.label,
                color = gradeColor(result.score)
            )
        }

        if (state.intelSynthetic) {
            item {
                Notice(
                    "This build ships placeholder threat data, not the real corpus. Password and " +
                        "link results derived from it mean nothing yet, and are labelled as such " +
                        "rather than presented as findings."
                )
            }
        } else if (!state.intelComplete) {
            item {
                Notice(
                    "Threat data is not bundled in this build, so the password and " +
                        "blocklist checks were skipped. They are reported as not " +
                        "checkable rather than as passing."
                )
            }
        }

        if (actionable.isNotEmpty()) {
            item { SectionHeader("Needs attention", "${actionable.size} of ${result.checksRun} checks") }
            items(actionable, key = { it.finding.key }) { FindingCard(it) }
        } else {
            item {
                Notice(
                    "Nothing to fix among the ${result.checksRun} checks that ran. That does not " +
                        "mean this phone is safe — it means these particular problems are not " +
                        "present."
                )
            }
        }

        if (result.checksPassed > 0) {
            item { SectionHeader("Passed", "${result.checksPassed} checks") }
            item {
                PassedList(report.rules.filter { it.outcome == RuleReport.Outcome.PASSED })
            }
        }

        if (notCheckable.isNotEmpty()) {
            item { SectionHeader("What Blanktick can't check here", "${notCheckable.size} checks") }
            item { NotCheckableNotice() }
            item { NotCheckableList(notCheckable) }
        }

        item { Ledger(report) }

        item {
            state.intelDate?.let {
                Text(
                    "Threat data built on $it. It ships inside the app and refreshes when the " +
                        "app updates.",
                    style = MaterialTheme.typography.labelSmall,
                    color = c.inkFaint
                )
            }
        }

        item { PrimaryButton("Scan again", onScan) }
    }
}

// -------------------------------------------------------------- components

@Composable
private fun ScoreDial(score: Int, previous: Int?, grade: String, color: Color) {
    val c = LocalBlanktickColors.current

    // Interpolates from the PREVIOUS score, never from zero (DD-05): the
    // movement itself communicates the delta rather than decorating the total.
    val animated by animateFloatAsState(
        targetValue = score / 100f,
        animationSpec = tween(durationMillis = BlanktickTokens.Motion.SLOW_MS),
        label = "score"
    )
    val strokePx = with(LocalDensity.current) { 6.dp.toPx() }

    Column(
        Modifier.fillMaxWidth().padding(vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Box(
            Modifier.size(200.dp).clearAndSetSemantics {
                contentDescription = "Security score $score out of 100, $grade"
            },
            contentAlignment = Alignment.Center
        ) {
            androidx.compose.foundation.Canvas(Modifier.fillMaxSize()) {
                val inset = strokePx / 2
                val arcSize = Size(size.width - strokePx, size.height - strokePx)
                drawArc(
                    color = c.hairline, startAngle = -90f, sweepAngle = 360f, useCenter = false,
                    topLeft = Offset(inset, inset), size = arcSize,
                    style = Stroke(width = strokePx, cap = StrokeCap.Round)
                )
                drawArc(
                    color = color, startAngle = -90f, sweepAngle = 360f * animated, useCenter = false,
                    topLeft = Offset(inset, inset), size = arcSize,
                    style = Stroke(width = strokePx, cap = StrokeCap.Round)
                )
            }
            Text("$score", style = MaterialTheme.typography.displayLarge, color = c.ink)
        }
        Text(grade, style = MaterialTheme.typography.titleMedium, color = color)
        previous?.let {
            val delta = score - it
            Text(
                when {
                    delta == 0 -> "No change since last scan"
                    // No triangles: "▲" is exactly what severityGlyph(HIGH)
                    // returns, so the same mark meant "danger" on a finding card
                    // and "improvement" here.
                    delta > 0 -> "Up $delta since last scan"
                    else -> "Down ${-delta} since last scan"
                },
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkMuted
            )
        }
    }
}

@Composable
private fun FindingCard(scored: ScoredFinding) {
    val c = LocalBlanktickColors.current
    val f = scored.finding
    val severityColor = c.forSeverity(f.severity)

    Surface(
        color = c.surface,
        shape = RoundedCornerShape(BlanktickTokens.Radius.lg),
        modifier = Modifier.fillMaxWidth()
    ) {
        // IntrinsicSize.Min bounds the height so the rail can actually fill it.
        // With only heightIn(min=) the incoming maxHeight is still Infinity and
        // Compose's fill modifiers no-op, so the rail measured 3dp x 0dp and
        // never appeared -- confirmed by sampling the rendered screenshot.
        Row(Modifier.height(IntrinsicSize.Min).heightIn(min = BlanktickTokens.MinTouchTarget)) {
            // The coloured rail is decorative only. Every piece of information
            // it carries is also in the label and glyph below (DD-03).
            Box(
                Modifier
                    .width(4.dp)
                    .fillMaxHeight()
                    .background(severityColor)
            )
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        "${severityGlyph(f.severity)} ${severityLabel(f.severity)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = severityColor
                    )
                    if (scored.deduction > 0) {
                        Text(
                            "−${scored.deduction}",
                            style = LedgerNumberStyle,
                            color = c.inkMuted
                        )
                    }
                }
                Text(
                    f.title,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = c.ink
                )
                // bodyLarge, not bodyMedium: DD-09 names shrinking finding detail
                // to fit more findings as the temptation to refuse, and this was
                // rendering at 13.3sp against a 16sp base.
                Text(f.detail, style = MaterialTheme.typography.bodyLarge, color = c.inkMuted)
                Text(
                    f.remediation,
                    style = MaterialTheme.typography.bodyLarge,
                    color = c.kelp,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

@Composable
private fun NotCheckableNotice() {
    Notice(
        "These checks are not possible on this device — usually because the operating " +
            "system does not allow one app to inspect another. They are listed so you can " +
            "tell the difference between “checked and fine” and “never looked”."
    )
}

@Composable
private fun NotCheckableList(rules: List<RuleReport>) {
    val c = LocalBlanktickColors.current
    Column {
        rules.forEachIndexed { i, rule ->
            if (i > 0) HorizontalDivider(color = c.hairline)
            Row(
                Modifier.fillMaxWidth().heightIn(min = 44.dp).padding(vertical = 10.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    rule.description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.inkMuted,
                    modifier = Modifier.weight(1f)
                )
                Text("—", style = MaterialTheme.typography.bodyMedium, color = c.notChecked)
            }
        }
    }
}

@Composable
private fun PassedList(rules: List<RuleReport>) {
    val c = LocalBlanktickColors.current
    Surface(color = c.surface, shape = RoundedCornerShape(BlanktickTokens.Radius.lg)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("✓ PASSED", style = MaterialTheme.typography.labelSmall, color = c.pass)
            Text(
                rules.joinToString(" · ") { it.description },
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkMuted
            )
        }
    }
}

/**
 * The arithmetic, exposed (DD-06).
 *
 * The engine guarantees these integers sum to `100 - score`, so a user who adds
 * up the column gets the right answer. That is the point of the screen.
 */
@Composable
private fun Ledger(report: ScanReport) {
    val c = LocalBlanktickColors.current
    val result = report.result
    if (result.actionableFindings.isEmpty()) return

    Surface(color = c.surface, shape = RoundedCornerShape(BlanktickTokens.Radius.lg)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("HOW THE SCORE WAS CALCULATED", style = MaterialTheme.typography.labelSmall, color = c.inkFaint)

            result.categories.forEach { category ->
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            category.category.displayName,
                            style = MaterialTheme.typography.bodyMedium,
                            color = c.ink
                        )
                        category.cappedAt?.let {
                            Text(
                                "capped at $it so one bad area cannot dominate",
                                style = MaterialTheme.typography.labelSmall,
                                color = c.medium
                            )
                        }
                    }
                    Text("−${category.deduction}", style = LedgerNumberStyle, color = c.ink)
                }
            }

            HorizontalDivider(color = c.ink)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Score", style = MaterialTheme.typography.bodyLarge, color = c.ink, fontWeight = FontWeight.Bold)
                Text("${result.score}", style = LedgerNumberStyle, color = c.ink)
            }

            Surface(color = c.kelpTint, shape = RoundedCornerShape(BlanktickTokens.Radius.md)) {
                Text(
                    "These add up. Check us. 100 − ${100 - result.score} = ${result.score}, and " +
                        "every point traces to one finding above.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.pass,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }
    }
}

@Composable
private fun SectionHeader(title: String, count: String) {
    val c = LocalBlanktickColors.current
    Row(
        Modifier.fillMaxWidth().padding(top = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Bottom
    ) {
        Text(title, style = MaterialTheme.typography.bodyLarge, color = c.ink, fontWeight = FontWeight.SemiBold)
        Text(count, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted)
    }
}

@Composable
private fun Notice(text: String) {
    val c = LocalBlanktickColors.current
    Surface(color = c.surface, shape = RoundedCornerShape(BlanktickTokens.Radius.lg)) {
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted,
            modifier = Modifier.padding(16.dp)
        )
    }
}

@Composable
private fun PrimaryButton(label: String, onClick: () -> Unit) {
    val c = LocalBlanktickColors.current
    Button(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
        shape = RoundedCornerShape(BlanktickTokens.Radius.pill),
        colors = ButtonDefaults.buttonColors(containerColor = c.ink, contentColor = c.paper)
    ) {
        Text(label, style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun gradeColor(score: Int): Color {
    val c = LocalBlanktickColors.current
    return when {
        score >= 90 -> c.pass
        score >= 75 -> c.pass
        score >= 50 -> c.medium
        score >= 25 -> c.high
        else -> c.critical
    }
}
