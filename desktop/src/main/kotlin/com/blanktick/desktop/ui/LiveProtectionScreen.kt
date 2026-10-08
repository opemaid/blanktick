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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.blanktick.core.model.Severity
import com.blanktick.desktop.AppState
import com.blanktick.desktop.LiveDetection
import com.blanktick.sensor.EnforcementOutcome
import com.blanktick.sensor.Response

/**
 * Live protection: the Pro sensor, surfaced in the app.
 *
 * Deliberately honest in three ways the rest of Blanktick already is. It leads
 * with what it is *not* (a full antivirus; an enforcer) before what it is. It
 * treats an empty detection list as the sensor working, never as a clean bill of
 * health. And it shows each detection as a line to investigate — the response it
 * *would* take — rather than claiming it stopped anything.
 */
@Composable
fun LiveProtectionScreen(state: AppState) {
    val c = LocalBlanktickColors.current
    val live = state.live

    val running by live.running.collectAsState()
    val elevated by live.elevated.collectAsState()
    val providerName by live.providerName.collectAsState()
    val counts by live.counts.collectAsState()
    val detections by live.detections.collectAsState()
    val enforce by live.enforce.collectAsState()

    ScrollableColumn(spacing = 20.dp) {
        SectionHeader("Live protection", trailing = "Pro · preview")

        Notice(
            "This watches the computer as it runs and flags attack behaviour: a document spawning a " +
                "shell, an AI assistant being driven to act, credential theft, ransomware, a process " +
                "beaconing out, data smuggled over DNS. It runs a local sensor and opens no network. " +
                "It is a behavioural detector, not a full antivirus — and right now it detects and warns. " +
                "It does not yet stop a process for you."
        )

        Card {
            Column(Modifier.padding(4.dp)) {
                Text(
                    if (running) "Watching this computer" else "Not running",
                    style = MaterialTheme.typography.titleMedium,
                    color = c.ink
                )
                Spacer(Modifier.size(8.dp))
                if (running) {
                    Text("Source: $providerName", style = MaterialTheme.typography.bodySmall, color = c.inkMuted)
                    Text(
                        elevationLine(elevated),
                        style = MaterialTheme.typography.bodySmall,
                        color = c.inkMuted
                    )
                } else {
                    Text(
                        "Start it to watch process, network and DNS activity for attack behaviour. " +
                            "It stops when you leave the app.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = c.inkMuted
                    )
                }
                Spacer(Modifier.size(16.dp))
                if (running) {
                    SecondaryButton("Stop") { live.stop() }
                } else {
                    PrimaryButton("Start live protection") { live.start() }
                }
            }
        }

        if (running) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                CountCard("Processes", counts.processes, Modifier.weight(1f))
                CountCard("Connections", counts.connections, Modifier.weight(1f))
                CountCard("DNS names", counts.dns, Modifier.weight(1f))
            }

            EnforceToggle(enforce, live::setEnforce)
        }

        SectionHeader("Detections", trailing = if (detections.isEmpty()) null else detections.size.toString())

        if (detections.isEmpty()) {
            Notice(
                if (running)
                    "Nothing flagged yet. On a healthy machine this stays empty — that is the sensor " +
                        "working, not sitting idle. Silence here is not a clean bill of health; it means " +
                        "nothing matching an attack was seen while it was watching."
                else
                    "No detections. Start live protection to begin watching."
            )
        } else {
            detections.forEach { DetectionCard(it) }
        }
    }
}

@Composable
private fun EnforceToggle(enforce: Boolean, onChange: (Boolean) -> Unit) {
    val c = LocalBlanktickColors.current
    Card {
        Column(Modifier.padding(4.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Stop flagged processes", style = MaterialTheme.typography.titleSmall, color = c.ink)
                    Text(
                        "Off by default. When on, a high-severity detection stops the process instead " +
                            "of only warning.",
                        style = MaterialTheme.typography.bodySmall,
                        color = c.inkMuted
                    )
                }
                Spacer(Modifier.size(12.dp))
                Switch(checked = enforce, onCheckedChange = onChange)
            }
            if (enforce) {
                Spacer(Modifier.size(10.dp))
                Text(
                    "Enforcement is on. These detections are heuristic, so this can stop a legitimate " +
                        "program. Blanktick never touches system processes or itself, and it terminates " +
                        "rather than freezes — a true forensic suspend is not implemented yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = c.high,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

@Composable
private fun CountCard(label: String, value: Int, modifier: Modifier = Modifier) {
    val c = LocalBlanktickColors.current
    Box(modifier) {
        Card {
            Column(Modifier.padding(4.dp)) {
                Text(value.toString(), style = MaterialTheme.typography.headlineSmall, color = c.ink)
                Text(label, style = MaterialTheme.typography.labelMedium, color = c.inkFaint)
            }
        }
    }
}

@Composable
private fun DetectionCard(ld: LiveDetection) {
    val c = LocalBlanktickColors.current
    val d = ld.detection
    val finding = d.finding
    val accent = severityColor(finding.severity)

    Card {
        Row(Modifier.fillMaxWidth()) {
            // Colour is the third channel: the rule id, title and severity word
            // carry the finding on their own; the bar only reinforces it.
            Box(
                Modifier
                    .width(4.dp)
                    .height(64.dp)
                    .background(accent, RoundedCornerShape(BlanktickTokens.Radius.sm))
            )
            Spacer(Modifier.size(14.dp))
            Column(Modifier.weight(1f)) {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(finding.ruleId, style = MaterialTheme.typography.labelSmall, color = c.inkFaint)
                    Text(
                        severityWord(finding.severity),
                        style = MaterialTheme.typography.labelSmall,
                        color = accent,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Spacer(Modifier.size(4.dp))
                Text(
                    finding.title,
                    style = MaterialTheme.typography.bodyLarge,
                    color = c.ink,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.size(6.dp))
                Text(finding.detail, style = MaterialTheme.typography.bodySmall, color = c.inkMuted)
                Spacer(Modifier.size(8.dp))
                val enforcement = ld.enforcement
                if (enforcement != null && enforcement.outcome == EnforcementOutcome.STOPPED) {
                    Text(
                        "Stopped: " + enforcement.detail,
                        style = MaterialTheme.typography.labelMedium,
                        color = c.pass,
                        fontWeight = FontWeight.SemiBold
                    )
                } else {
                    Text(
                        recommended(d.response),
                        style = MaterialTheme.typography.labelMedium,
                        color = c.inkMuted,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        }
    }
}

private fun elevationLine(elevated: Boolean?): String = when (elevated) {
    true -> "Running with administrator rights: full, machine-wide visibility."
    false -> "Without administrator rights: your session only. Run the app as admin for full coverage."
    null -> "Checking privileges…"
}

@Composable
private fun severityColor(sev: Severity): Color {
    val c = LocalBlanktickColors.current
    return when (sev) {
        Severity.CRITICAL -> c.critical
        Severity.HIGH -> c.high
        Severity.MEDIUM -> c.medium
        Severity.LOW, Severity.INFO -> c.inkMuted
    }
}

private fun severityWord(sev: Severity): String =
    sev.name.lowercase().replaceFirstChar { it.uppercase() }

private fun recommended(r: Response): String = when (r) {
    Response.KILL -> "Recommended: stop this process"
    Response.SUSPEND -> "Recommended: suspend it and investigate"
    Response.ALERT -> "Recommended: investigate"
    Response.OBSERVE -> "Recommended: note it"
}
