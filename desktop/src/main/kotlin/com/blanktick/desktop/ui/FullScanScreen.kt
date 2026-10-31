package com.blanktick.desktop.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.blanktick.desktop.AppState
import com.blanktick.desktop.FullScanUiState
import com.blanktick.desktop.collect.FullPcScan.Drive
import com.blanktick.desktop.collect.FullPcScan.DriveKind
import com.blanktick.desktop.collect.FullPcScan.DriveOutcome
import kotlinx.coroutines.delay

/**
 * Every file on every local drive.
 *
 * ## What "whole PC" means here, said on the screen
 *
 * Every fixed and removable drive, from its root, read by Microsoft Defender's
 * engine. "This computer" covers the rest — settings, startup entries,
 * drivers, accounts — so the two together are the whole machine. Network
 * shares are left out and the screen says so; a drive that could not be read
 * is listed as not scanned, never as clean.
 *
 * Nothing found is moved or deleted. The list is the result; what to do about
 * it is the user's decision, in Windows Security.
 */
@Composable
fun FullScanScreen(state: AppState) {
    val c = LocalBlanktickColors.current
    val s by state.fullScan.state.collectAsState()

    ScrollableColumn(spacing = BlanktickTokens.Space.s4) {
        Text("Scan your whole PC", style = MaterialTheme.typography.headlineMedium, color = c.ink)

        Notice(
            "Every file on every drive in this computer, including plugged-in USB drives, read by " +
                "Microsoft Defender's engine — the one already on your PC and kept up to date by " +
                "Windows. Blanktick still makes no network connection. Nothing found is moved or " +
                "deleted: you get the list and decide. Settings, startup programs and drivers are " +
                "covered by \"This computer\"; together the two are the whole machine."
        )

        when (val st = s) {
            FullScanUiState.Idle -> {
                Text(
                    "A whole-PC scan reads every file, so it takes a while — often 30 minutes to a " +
                        "few hours on a full drive. You can keep using the computer and the rest of " +
                        "Blanktick while it runs.",
                    style = MaterialTheme.typography.bodyLarge,
                    color = c.inkMuted,
                    modifier = Modifier.widthIn(max = 720.dp)
                )
                PrimaryButton("Scan whole PC") { state.fullScan.start() }
            }

            FullScanUiState.Preparing -> Text(
                "Finding your drives…",
                style = MaterialTheme.typography.bodyLarge,
                color = c.inkMuted
            )

            is FullScanUiState.Unavailable -> {
                Card {
                    Text(st.reason, style = MaterialTheme.typography.bodyLarge, color = c.notChecked)
                }
                SecondaryButton("Try again") { state.fullScan.start() }
            }

            is FullScanUiState.Running -> {
                var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
                LaunchedEffect(st.startedAtMillis) {
                    while (true) {
                        now = System.currentTimeMillis()
                        delay(1_000)
                    }
                }
                SectionHeader(
                    "Scanning drive ${st.current + 1} of ${st.drives.size}",
                    elapsed(now - st.startedAtMillis)
                )
                Card {
                    st.drives.forEachIndexed { i, drive ->
                        val done = st.finished.getOrNull(i)?.second
                        DriveRow(
                            drive,
                            when {
                                done != null -> outcomeLabel(done)
                                i == st.current -> "scanning…"
                                else -> "waiting"
                            },
                            when {
                                done != null -> outcomeTone(done)
                                i == st.current -> c.ink
                                else -> c.inkFaint
                            }
                        )
                    }
                }
                SecondaryButton("Stop") { state.fullScan.cancel() }
            }

            is FullScanUiState.Done -> {
                SectionHeader(
                    when {
                        st.cancelled -> "Stopped"
                        st.threats > 0 -> "Threats found on ${st.threats} " + if (st.threats == 1) "drive" else "drives"
                        st.allClean -> "Every drive scanned — nothing found"
                        else -> "Finished, with drives not scanned"
                    },
                    elapsed(st.elapsedMillis)
                )
                Card {
                    st.results.forEach { (drive, outcome) ->
                        DriveRow(drive, outcomeLabel(outcome), outcomeTone(outcome))
                        when (outcome) {
                            is DriveOutcome.Threats -> ThreatList(outcome)
                            is DriveOutcome.NotScanned -> Text(
                                outcome.reason,
                                style = MaterialTheme.typography.bodyMedium,
                                color = c.inkMuted,
                                modifier = Modifier.padding(bottom = BlanktickTokens.Space.s2)
                            )
                            DriveOutcome.Clean -> Unit
                        }
                    }
                }
                if (st.threats > 0) {
                    Notice(
                        "Nothing has been removed. To deal with a threat, open Windows Security → " +
                            "Virus & threat protection and run a scan there; Defender will offer " +
                            "to quarantine or remove what it finds."
                    )
                }
                if (st.notScanned > 0 && !st.cancelled) {
                    Text(
                        "A drive listed as not scanned was not checked at all. It is not counted " +
                            "as clean.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = c.notChecked
                    )
                }
                PrimaryButton("Scan again") { state.fullScan.start() }
            }
        }
    }
}

@Composable
private fun DriveRow(drive: Drive, status: String, tone: androidx.compose.ui.graphics.Color) {
    val c = LocalBlanktickColors.current
    Row(
        Modifier.fillMaxWidth().heightIn(min = BlanktickTokens.MinPointerTarget),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(BlanktickTokens.Space.s3)
    ) {
        Text(
            drive.root.trimEnd('\\') + (drive.label?.let { "  $it" } ?: ""),
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.SemiBold,
            color = c.ink
        )
        Text(
            if (drive.kind == DriveKind.REMOVABLE) "removable" else "local disk",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkFaint,
            modifier = Modifier.weight(1f)
        )
        Text(status, style = MaterialTheme.typography.bodyMedium, color = tone)
    }
}

@Composable
private fun ThreatList(outcome: DriveOutcome.Threats) {
    val c = LocalBlanktickColors.current
    if (outcome.detections.isEmpty()) {
        Text(
            "Defender reported threats on this drive but its list could not be read (this " +
                "happens on a non-English Windows). Open Windows Security to see them.",
            style = MaterialTheme.typography.bodyMedium,
            color = c.high
        )
        return
    }
    SelectionContainer {
        Column(Modifier.padding(bottom = BlanktickTokens.Space.s2)) {
            outcome.detections.forEach { d ->
                Text(d.threat, style = MaterialTheme.typography.bodyLarge, color = c.critical, fontWeight = FontWeight.SemiBold)
                d.resources.forEach {
                    Text(it, style = MaterialTheme.typography.bodyMedium, color = c.ink, modifier = Modifier.padding(start = 16.dp))
                }
            }
        }
    }
}

@Composable
private fun outcomeTone(outcome: DriveOutcome) = LocalBlanktickColors.current.let { c ->
    when (outcome) {
        DriveOutcome.Clean -> c.pass
        is DriveOutcome.Threats -> c.critical
        is DriveOutcome.NotScanned -> c.notChecked
    }
}

private fun outcomeLabel(outcome: DriveOutcome) = when (outcome) {
    DriveOutcome.Clean -> "scanned, nothing found"
    is DriveOutcome.Threats ->
        if (outcome.detections.isEmpty()) "threats found"
        else "${outcome.detections.size} " + if (outcome.detections.size == 1) "threat" else "threats"
    is DriveOutcome.NotScanned -> "not scanned"
}

private fun elapsed(ms: Long): String {
    val total = (ms / 1000).coerceAtLeast(0)
    val h = total / 3600
    val m = (total % 3600) / 60
    val sec = total % 60
    return if (h > 0) "%d:%02d:%02d".format(h, m, sec) else "%d:%02d".format(m, sec)
}
