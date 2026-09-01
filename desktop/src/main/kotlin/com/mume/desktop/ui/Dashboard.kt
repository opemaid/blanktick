package com.mume.desktop.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.v2.ScrollbarAdapter
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.VerticalScrollbar
import androidx.compose.foundation.rememberScrollbarAdapter
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.mume.core.RuleReport
import com.mume.core.ScanReport
import com.mume.desktop.ScanUiState

/**
 * The results dashboard.
 *
 * ## Why three regions rather than one column
 *
 * The previous version was a single scrolling column: dial, notice, findings,
 * a passed blob, a 28-row not-checkable list, ledger, button. Two consequences,
 * both measured rather than asserted:
 *
 * - At 1920 wide the finding detail ran to roughly 180 characters per line,
 *   about 2.5x a readable measure. Extra width has to buy more *regions*, not
 *   wider text.
 * - The ledger — the arithmetic DD-06 exists to make inspectable — sat after
 *   about 2,700dp of scroll, as did the primary action. Arithmetic you have to
 *   go looking for is not inspectable in any useful sense.
 *
 * So: a measure-capped findings column that is the primary read, a coverage
 * column holding everything the scan did not act on, and a **sidebar that does
 * not scroll**, carrying the score, the coverage census, the full ledger and
 * "Scan again". The ledger is now always on screen.
 */
@Composable
fun ResultsDashboard(state: ScanUiState.Complete, onScan: () -> Unit) {
    val report = state.report

    BoxWithConstraints(Modifier.fillMaxSize()) {
        // Two breakpoints, not five. Below 900 the sidebar has nowhere to go;
        // above 1320 there is room to lift coverage out of the scroll entirely.
        val width = maxWidth
        val threeColumn = width >= 1320.dp
        val twoColumn = !threeColumn && width >= 900.dp

        // Surplus width goes to the OUTER margin, never between the columns.
        // Letting the findings region absorb it with weight(1f) put ~210dp of
        // dead space between the last word of a finding and the ledger, which is
        // the same empty-middle problem the single-column layout had, moved.
        val contentMax = when {
            threeColumn -> 1520.dp
            twoColumn -> 1100.dp
            else -> MEASURE + 28.dp
        }

        Row(
            Modifier
                .fillMaxSize()
                .padding(horizontal = 32.dp, vertical = 24.dp)
                .widthIn(max = contentMax)
        ) {
            // ---- primary: findings -----------------------------------------
            Box(Modifier.weight(1f).fillMaxHeight()) {
                FindingsColumn(
                    state = state,
                    // Coverage joins the scroll only when it has no column of
                    // its own, so it is never simply dropped.
                    includeCoverage = !threeColumn
                )
            }

            if (threeColumn) {
                Spacer(Modifier.width(40.dp))
                Box(Modifier.width(400.dp).fillMaxHeight()) { CoverageColumn(report, ownScroll = true) }
            }

            if (threeColumn || twoColumn) {
                Spacer(Modifier.width(40.dp))
                StatusSidebar(state, onScan, Modifier.width(if (threeColumn) 320.dp else 300.dp))
            }
        }
    }
}

// --------------------------------------------------------------- findings

@Composable
private fun FindingsColumn(state: ScanUiState.Complete, includeCoverage: Boolean) {
    val c = LocalMumeColors.current
    val report = state.report
    val result = report.result
    val actionable = result.actionableFindings
    val listState = rememberLazyListState()

    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            // 28dp right padding reserves the scrollbar gutter so the bar never
            // sits on top of text.
            contentPadding = PaddingValues(end = 28.dp, bottom = 48.dp),
            verticalArrangement = Arrangement.spacedBy(MumeTokens.Space.s2)
        ) {
            item {
                Column(Modifier.widthIn(max = MEASURE)) {
                    Text(
                        "This computer",
                        style = MaterialTheme.typography.headlineMedium,
                        color = c.ink
                    )
                    Spacer(Modifier.height(MumeTokens.Space.s2))
                    ScanSummaryLine(state)
                }
            }

            // Placed above the findings, not below them, and above the score.
            // A caveat about how much of the machine was actually looked at
            // changes how every number under it should be read, so it cannot sit
            // where a reader arrives at it last.
            if (state.collectionCaveats.isNotEmpty()) {
                item {
                    Spacer(Modifier.height(MumeTokens.Space.s5))
                    Box(Modifier.widthIn(max = MEASURE)) {
                        Notice(
                            "This scan is incomplete. " +
                                state.collectionCaveats.joinToString(" ")
                        )
                    }
                }
            }

            if (state.intelSynthetic) {
                item {
                    Spacer(Modifier.height(MumeTokens.Space.s5))
                    Box(Modifier.widthIn(max = MEASURE)) {
                        Notice(
                            "This build ships placeholder threat data, not the real corpus. " +
                                "Password and link results from it mean nothing yet, and are " +
                                "labelled as such rather than presented as findings."
                        )
                    }
                }
            }

            item { Spacer(Modifier.height(MumeTokens.Space.s7)) }

            if (actionable.isNotEmpty()) {
                item {
                    Box(Modifier.widthIn(max = MEASURE)) {
                        SectionHeader("Needs attention", actionable.size.toString())
                    }
                    Spacer(Modifier.height(MumeTokens.Space.s3))
                }
                items(actionable, key = { it.finding.key }) {
                    Box(Modifier.widthIn(max = MEASURE)) { FindingCard(it) }
                }
            } else {
                item {
                    Box(Modifier.widthIn(max = MEASURE)) {
                        Notice(
                            "Nothing to fix among the ${result.checksRun} checks that ran. That " +
                                "does not mean this computer is safe — it means these particular " +
                                "problems are not present."
                        )
                    }
                }
            }

            if (includeCoverage) {
                item {
                    Spacer(Modifier.height(MumeTokens.Space.s7))
                    Box(Modifier.widthIn(max = MEASURE)) { CoverageColumn(report, ownScroll = false) }
                }
            }
        }

        VerticalScrollbar(
            adapter = rememberScrollbarAdapter(listState),
            modifier = Modifier.align(Alignment.CenterEnd).fillMaxHeight()
        )
    }
}

/** One sentence stating what the scan actually covered. */
@Composable
private fun ScanSummaryLine(state: ScanUiState.Complete) {
    val c = LocalMumeColors.current
    val r = state.report.result
    val total = r.checksRun + r.checksSkipped
    Text(
        "$total checks exist. ${r.checksRun} ran on this computer — ${r.checksPassed} passed, " +
            "${r.actionableFindings.size} need attention. ${r.checksSkipped} could not run.",
        style = MaterialTheme.typography.bodyLarge,
        color = c.inkMuted,
        modifier = Modifier
            .widthIn(max = MEASURE)
            // The count of what did NOT run is in the announced sentence, or the
            // null contract is dropped from the audio channel exactly as it was
            // dropped from the visual one.
            .semantics { liveRegion = LiveRegionMode.Polite }
    )
}

// --------------------------------------------------------------- coverage

/**
 * Everything the scan did not act on.
 *
 * The two skip reasons are separated because they are not the same fact. A rule
 * written for a phone will never run here whatever the user does; a rule that
 * applies here and returned nothing means this machine declined to answer, which
 * can change. Presenting 28 checks as one undifferentiated "could not run" was
 * the honest floor, not the honest answer.
 */
/**
 * @param ownScroll true when this has a column of its own. When it is instead
 *   embedded in the findings `LazyColumn` it must NOT scroll: a scrollable
 *   inside a lazy item is measured with an infinite maximum height and Compose
 *   throws. (Found by running it — the same unbounded-constraint family as the
 *   severity rail that measured 0dp tall.)
 */
@Composable
private fun CoverageColumn(report: ScanReport, ownScroll: Boolean) {
    val c = LocalMumeColors.current
    val wrongPlatform = report.skippedWrongPlatform
    val unobservable = report.skippedUnobservable
    val passed = report.rules.filter { it.outcome == RuleReport.Outcome.PASSED }
    val scroll = rememberScrollState()

    Column(
        if (ownScroll) {
            Modifier.fillMaxSize().verticalScroll(scroll)
        } else {
            Modifier.fillMaxWidth()
        },
        verticalArrangement = Arrangement.spacedBy(MumeTokens.Space.s3)
    ) {
        SectionHeader("Coverage")

        if (passed.isNotEmpty()) {
            Disclosure(
                title = "Passed",
                count = passed.size,
                tone = c.pass,
                initiallyOpen = false,
                summary = "Checked, and nothing wrong."
            ) { RuleRows(passed, c.pass, "PASSED") }
        }

        if (unobservable.isNotEmpty()) {
            Disclosure(
                title = "This computer wouldn't answer",
                count = unobservable.size,
                tone = c.notChecked,
                // Always open: these are the machine-specific ones, and they can
                // change. They are also the half a user might act on.
                initiallyOpen = true,
                summary = "The check applies to a computer, but this one did not " +
                    "supply the information. Never counted as a pass."
            ) { RuleRows(unobservable, c.notChecked, "NOT CHECKABLE") }
        }

        if (wrongPlatform.isNotEmpty()) {
            Disclosure(
                title = "Written for a phone",
                count = wrongPlatform.size,
                tone = c.notChecked,
                // Collapsed: identical on every scan of every Windows machine.
                // The count stays visible on the header so this is a fold, not a
                // hide -- the number is the part that must never disappear.
                initiallyOpen = false,
                summary = "Root detection, USB debugging, the Android app auditor. " +
                    "These will never run on a computer."
            ) { RuleRows(wrongPlatform, c.notChecked, "NOT APPLICABLE") }
        }
    }
}

@Composable
private fun Disclosure(
    title: String,
    count: Int,
    tone: Color,
    initiallyOpen: Boolean,
    summary: String,
    content: @Composable () -> Unit
) {
    val c = LocalMumeColors.current
    var open by remember { mutableStateOf(initiallyOpen) }
    val shape = RoundedCornerShape(MumeTokens.Radius.lg)

    Surface(color = c.surface, shape = shape, modifier = Modifier.fillMaxWidth().mumeElevation(MumeTokens.Elevation.rest, shape)) {
        Column(Modifier.padding(horizontal = 20.dp, vertical = 16.dp)) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .interactive(RoundedCornerShape(MumeTokens.Radius.sm)) { open = !open }
                    .padding(vertical = MumeTokens.Space.s1),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    title,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = c.ink
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(count.toString(), style = LedgerNumberStyle, color = tone)
                    Spacer(Modifier.width(MumeTokens.Space.s2))
                    Text(if (open) "−" else "+", style = LedgerNumberStyle, color = c.inkMuted)
                }
            }
            Text(summary, style = MaterialTheme.typography.bodyLarge, color = c.inkMuted)
            if (open) {
                Spacer(Modifier.height(MumeTokens.Space.s3))
                content()
            }
        }
    }
}

@Composable
private fun RuleRows(rules: List<RuleReport>, tone: Color, state: String) {
    val c = LocalMumeColors.current
    SelectionContainer {
        Column {
            rules.forEachIndexed { i, rule ->
                if (i > 0) Hairline()
                Row(
                    Modifier
                        .fillMaxWidth()
                        .height(MumeTokens.MinPointerTarget)
                        // The state is text, not an em dash. A screen reader
                        // previously heard the rule description and nothing
                        // distinguishing it from a passed check.
                        .semantics { contentDescription = "${rule.description}: $state" },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        rule.description,
                        style = MaterialTheme.typography.bodyLarge,
                        color = c.inkMuted,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(Modifier.width(MumeTokens.Space.s3))
                    Text(
                        if (state == "PASSED") "✓" else "—",
                        style = MaterialTheme.typography.bodyLarge,
                        color = tone
                    )
                }
            }
        }
    }
}

// ---------------------------------------------------------------- sidebar

@Composable
private fun StatusSidebar(
    state: ScanUiState.Complete,
    onScan: () -> Unit,
    modifier: Modifier = Modifier
) {
    val c = LocalMumeColors.current
    val result = state.report.result

    Column(
        modifier.fillMaxHeight(),
        verticalArrangement = Arrangement.spacedBy(MumeTokens.Space.s4)
    ) {
        ScoreGauge(
            score = result.score,
            grade = result.grade.label,
            previous = state.previousScore,
            color = gradeColor(result.score)
        )

        CoverageMeter(
            ran = result.checksRun,
            skipped = result.checksSkipped
        )

        Ledger(state.report)

        Spacer(Modifier.weight(1f))

        state.intelDate?.let {
            Text(
                "Threat data built $it · ${result.checksRun + result.checksSkipped} rules",
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkFaint
            )
        }
        PrimaryButton("Scan again", onClick = onScan)
    }
}

/**
 * The score.
 *
 * DD-05 says the numeral is primary and the arc secondary. The previous
 * treatment was a 200dp box with a 6dp closed 360-degree ring around an 82.6sp
 * numeral: the glyph occupied roughly half the dial's width, so the ring was an
 * equal partner rather than a backdrop — and a *closed* ring reads as a progress
 * donut nearing completion, which is the wrong metaphor entirely. A security
 * posture is not a task you finish.
 *
 * So: a 168dp box, a 2.5dp stroke, an open 270-degree gauge with the quadrant at
 * the bottom removed, and the numeral one rung up the same minor-third scale to
 * 99.1sp. The numeral now occupies about 71% of the dial rather than 50%, which
 * makes "numeral primary" a measurement instead of an assertion.
 */
@Composable
private fun ScoreGauge(score: Int, grade: String, previous: Int?, color: Color) {
    val c = LocalMumeColors.current

    val animated by animateFloatAsState(
        targetValue = score / 100f,
        // 320ms, not 700. 700 is a phone-hero duration; on a pointer device it
        // reads as lag. DD-10's spring, which was defined in tokens.json and
        // never generated, so every animation silently ran FastOutSlowIn.
        animationSpec = tween(320, easing = MumeTokens.Motion.SPRING),
        label = "score"
    )
    val strokePx = with(LocalDensity.current) { 2.5.dp.toPx() }

    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(MumeTokens.Space.s2)
    ) {
        Box(
            Modifier.size(168.dp).clearAndSetSemantics {
                contentDescription = "Security score $score out of 100, $grade"
            },
            contentAlignment = Alignment.Center
        ) {
            Canvas(Modifier.fillMaxSize()) {
                val inset = strokePx / 2
                val arcSize = Size(size.width - strokePx, size.height - strokePx)
                // 135 degrees to 45 degrees: an open gauge, not a closed ring.
                drawArc(
                    color = c.trackMuted, startAngle = 135f, sweepAngle = 270f, useCenter = false,
                    topLeft = Offset(inset, inset), size = arcSize,
                    style = Stroke(width = strokePx, cap = StrokeCap.Butt)
                )
                drawArc(
                    color = color, startAngle = 135f, sweepAngle = 270f * animated, useCenter = false,
                    topLeft = Offset(inset, inset), size = arcSize,
                    style = Stroke(width = strokePx, cap = StrokeCap.Round)
                )
            }
            Text("$score", style = MaterialTheme.typography.displayLarge, color = c.ink)
        }
        Text(grade, style = MaterialTheme.typography.titleLarge, color = color)
        previous?.let {
            val delta = score - it
            Text(
                // No triangles: the up-arrow was the same glyph severityGlyph()
                // returns for HIGH, so the same mark meant "danger" on a finding
                // card and "improvement" here, 200px apart.
                when {
                    delta == 0 -> "No change since last scan"
                    delta > 0 -> "Up $delta since last scan"
                    else -> "Down ${-delta} since last scan"
                },
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkMuted
            )
        }
    }
}

/**
 * The denominator, which the dashboard previously never stated.
 *
 * "2 of 17 checks" silently redefined what a check was between sections and
 * implied a 17-rule product. The number that matters is that 45 exist and 17
 * ran. Two segments only — a third for the handful that failed would be a few
 * percent of the bar, undrawable and unlabelable, and pass-versus-fail is the
 * score's job.
 */
@Composable
private fun CoverageMeter(ran: Int, skipped: Int) {
    val c = LocalMumeColors.current
    val total = (ran + skipped).coerceAtLeast(1)

    Column(verticalArrangement = Arrangement.spacedBy(MumeTokens.Space.s2)) {
        Row(Modifier.fillMaxWidth().height(10.dp)) {
            Box(
                Modifier
                    .weight(ran.toFloat().coerceAtLeast(0.01f))
                    .fillMaxHeight()
                    .background(c.pass, RoundedCornerShape(5.dp))
            )
            Spacer(Modifier.width(2.dp))
            Box(
                Modifier
                    .weight(skipped.toFloat().coerceAtLeast(0.01f))
                    .fillMaxHeight()
                    .background(c.notChecked, RoundedCornerShape(5.dp))
            )
        }
        Text(
            "$ran of $total checks ran here",
            style = MaterialTheme.typography.bodyLarge,
            color = c.ink
        )
        Text(
            "$skipped could not run",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted
        )
    }
}

/**
 * The arithmetic, exposed (DD-06).
 *
 * One row **per finding**, not per category. The previous version iterated
 * `result.categories`, so a machine whose two findings were both NETWORK
 * rendered a single row reading "Network −14" while the cards above said −9 and
 * −5. The user could not follow it, which is the one thing this panel exists to
 * let them do. It also returned early when there were no findings — deleting the
 * arithmetic exactly when someone is most entitled to check nothing was hidden.
 */
@Composable
private fun Ledger(report: ScanReport) {
    val c = LocalMumeColors.current
    val result = report.result
    val scored = result.actionableFindings

    Card {
        Text(
            "HOW THE SCORE WAS CALCULATED",
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Bold,
            color = c.inkMuted
        )

        if (scored.isEmpty()) {
            Text(
                "Nothing was deducted. 100 − 0 = ${result.score}.",
                style = MaterialTheme.typography.bodyLarge,
                color = c.ink
            )
            return@Card
        }

        scored.forEach { s ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    s.finding.title,
                    style = MaterialTheme.typography.bodyLarge,
                    color = c.ink,
                    maxLines = 2,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(MumeTokens.Space.s3))
                Text("−${s.deduction}", style = LedgerNumberStyle, color = c.ink)
            }
        }

        result.categories.filter { it.cappedAt != null }.forEach { cat ->
            Text(
                "${cat.category.displayName} capped at ${cat.cappedAt} so one bad area " +
                    "cannot dominate",
                style = MaterialTheme.typography.bodyMedium,
                color = c.medium
            )
        }

        Hairline()
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(
                "Score",
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Bold,
                color = c.ink
            )
            Text("${result.score}", style = LedgerNumberStyle, color = c.ink)
        }

        Surface(color = c.kelpTint, shape = RoundedCornerShape(MumeTokens.Radius.md)) {
            Text(
                "These add up. 100 − ${100 - result.score} = ${result.score}, and every point " +
                    "traces to one finding.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.pass,
                modifier = Modifier.padding(14.dp)
            )
        }
    }
}

/**
 * Reading measure for the findings column.
 *
 * 680dp at 16sp is roughly 85 characters. Comfortable measure is 45-75, so this
 * is the ceiling rather than the target — but the alternative on a 1920 window
 * was 180 characters, and the surplus width is spent on the coverage and status
 * columns instead of on longer lines.
 */
private val MEASURE = 680.dp
