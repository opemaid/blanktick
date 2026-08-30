package com.mume.desktop.ui

import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.interaction.collectIsHoveredAsState
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.clickable
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.PointerIcon
import androidx.compose.ui.input.pointer.pointerHoverIcon
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.mume.core.model.ScoredFinding
import com.mume.core.model.Severity

/**
 * Shared surfaces.
 *
 * Visually identical to the Android app by construction — both read the same
 * generated [MumeTokens] — but built for a pointer and a wide window rather than
 * a thumb and a narrow one.
 */

// ------------------------------------------------------------------ elevation

/**
 * DD-13's "very soft diffused ambient shadow", applied.
 *
 * `Modifier.shadow` with an explicit ambient/spot pair rather than
 * `Surface(shadowElevation =)`, which draws a tight grey Material shadow — the
 * harsh drop shadow DD-13 rejects by name.
 *
 * On dark this is a no-op: a shadow is invisible on `#0C0E0D` at any alpha, so
 * dark separates planes with a hairline border and a lit top edge instead. That
 * is the practical meaning of "a first-class theme, not an inversion".
 */
@Composable
fun Modifier.mumeElevation(
    spec: MumeTokens.ShadowSpec,
    shape: RoundedCornerShape
): Modifier {
    val c = LocalMumeColors.current
    return if (c.isDark) {
        this.border(1.dp, c.hairline, shape)
    } else {
        this.shadow(
            elevation = spec.dp,
            shape = shape,
            clip = false,
            ambientColor = spec.ambient,
            spotColor = spec.spot
        )
    }
}

// ---------------------------------------------------------------- interaction

/**
 * Pointer affordances, and the reason they are hand-rolled.
 *
 * Compose's default `LocalIndication` is `DefaultDebugIndication`, which draws
 * **the same** black 10% rectangle for hover and for focus — so a keyboard user
 * cannot locate focus while a mouse is on screen, and on dark the wash is
 * invisible against `surfaceSunk`. It also draws outside `Surface`'s clip layer,
 * putting a hard-cornered grey rectangle under a rounded pill.
 *
 * So indication is switched off and replaced with two channels that cannot be
 * confused: **hover is a fill, focus is an outline.**
 */
@Composable
fun Modifier.interactive(
    shape: RoundedCornerShape,
    enabled: Boolean = true,
    onClick: () -> Unit
): Modifier {
    val c = LocalMumeColors.current
    val source = remember { MutableInteractionSource() }
    val focused by source.collectIsFocusedAsState()

    return this
        .clickable(
            interactionSource = source,
            indication = null,
            enabled = enabled,
            onClick = onClick
        )
        .then(if (focused) Modifier.border(2.dp, c.focus, shape) else Modifier)
        .pointerHoverIcon(if (enabled) PointerIcon.Hand else PointerIcon.Default)
}

/** Tracks hover without consuming clicks, for surfaces that tint on hover. */
@Composable
fun rememberHoverState(): Pair<MutableInteractionSource, Boolean> {
    val source = remember { MutableInteractionSource() }
    val hovered by source.collectIsHoveredAsState()
    return source to hovered
}

// ----------------------------------------------------------------- primitives

@Composable
fun SectionHeader(title: String, trailing: String? = null) {
    val c = LocalMumeColors.current
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Bottom
    ) {
        Text(
            title,
            // titleLarge, not bodyLarge: a section header and a finding title were
            // both 16sp one weight apart, which is not a hierarchy.
            style = MaterialTheme.typography.titleLarge,
            color = c.ink,
            modifier = Modifier.semantics { heading() }
        )
        trailing?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium, color = c.inkFaint)
        }
    }
}

/**
 * Meta-commentary about the scan — never a finding.
 *
 * Deliberately *not* card-shaped. It previously used the same surface, radius
 * and width as a `FindingCard`, so the "this build ships placeholder data"
 * caveat wore the costume of a finding and was the largest slab on the screen.
 * Flat, hairline-bordered, one radius step down.
 */
@Composable
fun Notice(text: String) {
    val c = LocalMumeColors.current
    val shape = RoundedCornerShape(MumeTokens.Radius.md)
    Box(
        Modifier
            .fillMaxWidth()
            .border(1.dp, c.hairline, shape)
    ) {
        Text(
            text,
            style = MaterialTheme.typography.bodyLarge,
            color = c.inkMuted,
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 16.dp)
        )
    }
}

@Composable
fun Card(
    elevation: MumeTokens.ShadowSpec = MumeTokens.Elevation.rest,
    content: @Composable () -> Unit
) {
    val c = LocalMumeColors.current
    val shape = RoundedCornerShape(MumeTokens.Radius.lg)
    Surface(
        color = c.surface,
        shape = shape,
        modifier = Modifier.fillMaxWidth().mumeElevation(elevation, shape)
    ) {
        Column(
            Modifier.padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(MumeTokens.Space.s2)
        ) {
            content()
        }
    }
}

/**
 * The double bezel (DD-13).
 *
 * A `surfaceSunk` tray at `Radius.shell` holding a `paper` core at
 * `Radius.core`, separated by exactly `Radius.shellPad`. The three tokens were
 * generated for this and used nowhere: `core == shell - shellPad` is asserted in
 * `check_tokens.py`, which is what keeps the curves parallel rather than merely
 * claiming they are.
 */
@Composable
fun Bezel(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    val c = LocalMumeColors.current
    Box(
        modifier
            .background(c.surfaceSunk, RoundedCornerShape(MumeTokens.Radius.shell))
            .padding(MumeTokens.Radius.shellPad)
    ) {
        Box(
            Modifier
                .background(c.paper, RoundedCornerShape(MumeTokens.Radius.core))
                .then(
                    if (c.isDark) {
                        Modifier.border(
                            1.dp,
                            MumeTokens.Elevation.innerTopDark,
                            RoundedCornerShape(MumeTokens.Radius.core)
                        )
                    } else {
                        Modifier
                    }
                )
        ) { content() }
    }
}

// -------------------------------------------------------------------- buttons

@Composable
fun PrimaryButton(label: String, enabled: Boolean = true, onClick: () -> Unit) {
    val c = LocalMumeColors.current
    val shape = RoundedCornerShape(MumeTokens.Radius.pill)
    val (source, hovered) = rememberHoverState()
    val pressed by source.collectIsPressedAsState()

    Surface(
        color = if (hovered && enabled) c.kelp else c.ink,
        contentColor = c.paper,
        shape = shape,
        modifier = Modifier
            .hoverable(source, enabled)
            .heightIn(min = 48.dp)
            .interactive(shape, enabled, onClick)
    ) {
        Box(
            Modifier.padding(horizontal = 28.dp, vertical = 14.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                label,
                style = MaterialTheme.typography.titleMedium,
                color = if (pressed) c.paper.copy(alpha = 0.85f) else c.paper
            )
        }
    }
}

@Composable
fun SecondaryButton(label: String, enabled: Boolean = true, onClick: () -> Unit) {
    val c = LocalMumeColors.current
    val shape = RoundedCornerShape(MumeTokens.Radius.pill)
    val (source, hovered) = rememberHoverState()

    Surface(
        color = if (hovered && enabled) c.surfaceSunk else Color.Transparent,
        shape = shape,
        border = androidx.compose.foundation.BorderStroke(1.dp, c.hairline),
        modifier = Modifier
            .hoverable(source, enabled)
            .heightIn(min = 48.dp)
            .interactive(shape, enabled, onClick)
    ) {
        Box(
            Modifier.padding(horizontal = 24.dp, vertical = 14.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                label,
                style = MaterialTheme.typography.bodyLarge,
                color = if (enabled) c.ink else c.inkFaint
            )
        }
    }
}

// --------------------------------------------------------------- finding card

/**
 * One finding.
 *
 * The coloured rail is decorative only: everything it carries is also in the
 * glyph and the label beside it (DD-03), so the card is complete in greyscale
 * and to a screen reader.
 *
 * ## Two bugs this rewrite fixes
 *
 * 1. **The rail did not render at all.** It was `Modifier.width(3.dp)
 *    .fillMaxSize()` inside a `Row` inside a `LazyColumn`, where the incoming
 *    `maxHeight` is `Constraints.Infinity` — Compose's fill modifiers no-op on
 *    an unbounded axis, so it measured 3dp x 0dp. Confirmed by sampling the
 *    rendered screenshot: not one pixel of severity colour on the card edge.
 *    `height(IntrinsicSize.Min)` on the Row bounds the axis and makes
 *    `fillMaxHeight` meaningful.
 * 2. **Detail and remediation rendered at 13.3sp.** DD-09 says finding body text
 *    never goes below base size, and names shrinking it to fit more findings as
 *    the temptation to refuse. They are `bodyLarge` (16sp) now.
 */
@Composable
fun FindingCard(scored: ScoredFinding) {
    val c = LocalMumeColors.current
    val f = scored.finding
    val severityColor = c.forSeverity(f.severity)
    val shape = RoundedCornerShape(MumeTokens.Radius.lg)

    val (source, hovered) = rememberHoverState()
    val lift by animateDpAsState(
        targetValue = if (hovered) 2.dp else 0.dp,
        animationSpec = tween(MumeTokens.Motion.FAST_MS, easing = MumeTokens.Motion.SPRING),
        label = "lift"
    )

    Surface(
        color = c.surface,
        shape = shape,
        modifier = Modifier
            .fillMaxWidth()
            .hoverable(source)
            .mumeElevation(
                if (hovered) MumeTokens.Elevation.raised else MumeTokens.Elevation.rest,
                shape
            )
            .padding(bottom = lift)
    ) {
        // IntrinsicSize.Min bounds the height so the rail can fill it.
        Row(Modifier.height(IntrinsicSize.Min)) {
            Box(
                Modifier
                    .width(4.dp)
                    .fillMaxHeight()
                    .background(
                        severityColor,
                        RoundedCornerShape(topStart = MumeTokens.Radius.lg, bottomStart = MumeTokens.Radius.lg)
                    )
            )
            SelectionContainer {
                Column(
                    Modifier.padding(horizontal = 20.dp, vertical = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(MumeTokens.Space.s2)
                ) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        SeverityChip(f.severity)
                        if (scored.deduction > 0) {
                            Text("−${scored.deduction}", style = LedgerNumberStyle, color = c.inkMuted)
                        }
                    }
                    Text(
                        f.title,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.SemiBold,
                        color = c.ink
                    )
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
}

/**
 * Severity as glyph + label + colour, in that order of importance (DD-03).
 *
 * The glyph is a separate `Text` with semantics cleared, so a screen reader
 * announces "MEDIUM" rather than "black square, MEDIUM". It was previously
 * concatenated into the label string, which put punctuation noise into the
 * audio channel and rendered the whole chip at 11.1sp — the smallest type in a
 * product whose severity model puts the label first.
 */
@Composable
private fun SeverityChip(severity: Severity) {
    val c = LocalMumeColors.current
    val tone = c.forSeverity(severity)
    Row(
        horizontalArrangement = Arrangement.spacedBy(MumeTokens.Space.s2),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            severityGlyph(severity),
            color = tone,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.clearAndSetSemantics { }
        )
        Text(
            severityLabel(severity),
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Bold,
            color = tone
        )
    }
}

// ------------------------------------------------------------------- ledger

@Composable
fun KeyValueRow(label: String, value: String, valueColor: Color? = null, mono: Boolean = false) {
    val c = LocalMumeColors.current
    Row(
        Modifier.fillMaxWidth().heightIn(min = MumeTokens.MinPointerTarget),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyLarge,
            color = c.inkMuted,
            modifier = Modifier.weight(1f)
        )
        Spacer(Modifier.size(MumeTokens.Space.s3))
        Text(
            value,
            style = if (mono) LedgerNumberStyle else MaterialTheme.typography.bodyLarge,
            color = valueColor ?: c.ink
        )
    }
}

@Composable
fun Hairline() {
    HorizontalDivider(color = LocalMumeColors.current.hairline)
}
