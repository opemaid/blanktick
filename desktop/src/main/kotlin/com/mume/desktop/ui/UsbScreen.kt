package com.mume.desktop.ui

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
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.mume.desktop.AppState
import com.mume.desktop.ScanUiState

/**
 * Removable media, and what this computer remembers about it.
 *
 * ## What this is not
 *
 * It is not a virus scan of your USB stick. Mume does not open files on the
 * drive, does not hash them, and could not check them against anything if it
 * did — that needs a server. Two things about removable media are answerable
 * offline, and those are the two it checks: whether Windows will let a drive
 * run a program the moment it is plugged in, and whether an attached drive is
 * encrypted.
 *
 * The device history below is deliberately not a finding and never costs a
 * point. It is here because a machine quietly keeping a list of every stick and
 * handset ever connected is the sort of thing people are surprised to learn,
 * and telling them what their own computer knows is the job.
 */
@Composable
fun UsbScreen(state: AppState) {
    val c = LocalMumeColors.current
    // Recomposes when the scan state changes; the facts themselves are held on
    // AppState so this screen shows exactly what the dashboard scored, never a
    // second independent read.
    val scan by state.scan.collectAsState()
    val facts = if (scan is ScanUiState.Complete) state.desktopFacts else null

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(40.dp),
        verticalArrangement = Arrangement.spacedBy(MumeTokens.Space.s4)
    ) {
        Text("USB & removable media", style = MaterialTheme.typography.headlineMedium, color = c.ink)

        if (facts == null) {
            Notice(
                "Run a scan and this fills in. Everything here comes from the same single " +
                    "pass as the rest of the report — plugging something in and re-scanning " +
                    "is the way to check a specific drive."
            )
            PrimaryButton("Run a scan") { state.runScan() }
            return@Column
        }

        Notice(
            "Mume does not scan the contents of a drive. It does not open your files, hash " +
                "them, or check them against anything — that would need a server, and this app " +
                "has no way to reach one. It answers the two questions about removable media " +
                "that can be answered offline."
        )

        // ---- attached now -------------------------------------------------
        val drives = facts.removableDrives
        SectionHeader("Attached now", drives?.size?.toString() ?: "unknown")
        Card {
            when {
                drives == null -> Text(
                    "The drive list could not be read, so nothing is claimed about it. " +
                        "Reported as not checkable rather than as \"none attached\".",
                    style = MaterialTheme.typography.bodyLarge,
                    color = c.notChecked
                )
                drives.isEmpty() -> Text(
                    "Nothing plugged in. The encryption check reports as not checkable rather " +
                        "than passing — there was nothing to look at, which is not the same as " +
                        "nothing being wrong.",
                    style = MaterialTheme.typography.bodyLarge,
                    color = c.inkMuted
                )
                else -> drives.forEach { drive ->
                    val tone = when (drive.encrypted) {
                        true -> c.pass
                        false -> c.medium
                        null -> c.notChecked
                    }
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = MumeTokens.MinPointerTarget),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            drive.letter + (drive.label?.let { "  $it" } ?: ""),
                            style = MaterialTheme.typography.bodyLarge,
                            fontWeight = FontWeight.SemiBold,
                            color = c.ink,
                            modifier = Modifier.weight(1f)
                        )
                        drive.sizeBytes?.let {
                            Text(
                                "%.0f GB".format(it / 1_073_741_824.0),
                                style = LedgerNumberStyle,
                                color = c.inkMuted
                            )
                            Spacer(Modifier.width(MumeTokens.Space.s3))
                        }
                        Text(
                            when (drive.encrypted) {
                                true -> "encrypted"
                                false -> "not encrypted"
                                null -> "encryption unknown"
                            },
                            style = MaterialTheme.typography.bodyMedium,
                            color = tone
                        )
                    }
                }
            }
        }

        // ---- autorun ------------------------------------------------------
        SectionHeader("Auto-run from a plugged-in drive")
        Card {
            Text(
                when (facts.autoRunBlockedForRemovable) {
                    true -> "Blocked. Windows will not run a program off a drive just because " +
                        "you plugged it in — that has been the default since 2011, and this " +
                        "machine still has it."
                    false -> "Allowed. The policy on this computer has been changed from the " +
                        "Windows default, so a drive can start a program the moment it is " +
                        "connected. That is how USB worms spread."
                    null -> "Could not be read, so nothing is claimed either way."
                },
                style = MaterialTheme.typography.bodyLarge,
                color = when (facts.autoRunBlockedForRemovable) {
                    true -> c.inkMuted
                    false -> c.high
                    null -> c.notChecked
                },
                modifier = Modifier.widthIn(max = 720.dp)
            )
        }

        // ---- history ------------------------------------------------------
        val remembered = facts.rememberedUsbDevices
        SectionHeader("What this computer remembers", remembered?.size?.toString() ?: "unknown")
        Card {
            Text(
                "Windows records every drive and phone connected to it, and keeps that record " +
                    "long after the device is gone. None of this is a problem to fix and none " +
                    "of it costs you a point — it is here because it is your computer's memory " +
                    "of you, and you should be able to see it.",
                style = MaterialTheme.typography.bodyLarge,
                color = c.inkMuted
            )
            if (!remembered.isNullOrEmpty()) {
                Hairline()
                SelectionContainer {
                    Column {
                        remembered.forEach {
                            Text(
                                it,
                                style = MaterialTheme.typography.bodyLarge,
                                color = c.ink,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(min = MumeTokens.MinPointerTarget)
                                    .padding(vertical = MumeTokens.Space.s1)
                            )
                        }
                    }
                }
            } else if (remembered != null) {
                Text(
                    "Nothing recorded.",
                    style = MaterialTheme.typography.bodyLarge,
                    color = c.inkMuted
                )
            }
        }
    }
}
