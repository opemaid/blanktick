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
import com.mume.core.intel.EolCatalog
import com.mume.desktop.AppState

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
    val c = LocalMumeColors.current
    val programs by state.programs.collectAsState()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(40.dp),
        verticalArrangement = Arrangement.spacedBy(MumeTokens.Space.s4)
    ) {
        Text("Installed software", style = MaterialTheme.typography.headlineMedium, color = c.ink)

        if (programs == null) {
            Notice(
                "Run a scan and this fills in. The list comes from the same place Windows " +
                    "Settings reads, so it costs nothing extra — but it is a product of the " +
                    "scan rather than a separate walk of your disk."
            )
            Spacer(Modifier.widthIn(max = 1.dp))
            PrimaryButton("Run a scan") { state.runScan() }
            return@Column
        }

        val list = programs.orEmpty()
        val eol = list.filter { EolCatalog.match(it.name, it.version) != null }
        val unattributed = list.filter { it.userWritableLocation && it.publisher.isNullOrBlank() }
        val userWritable = list.filter { it.userWritableLocation }

        Text(
            "${list.size} programs. ${userWritable.size} are installed somewhere you can write " +
                "without administrator permission, which is normal for package managers and " +
                "several well-known apps. ${unattributed.size} of those name no publisher.",
            style = MaterialTheme.typography.bodyLarge,
            color = c.inkMuted,
            modifier = Modifier.widthIn(max = 720.dp)
        )

        Notice(
            "This is a list, not a verdict. Mume does not hash files, does not consult a " +
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

        SectionHeader("Everything installed", list.size.toString())
        Card {
            SelectionContainer {
                Column {
                    list.sortedBy { it.name.lowercase() }.forEach { p ->
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

@Composable
private fun ProgramRow(name: String, version: String?, trailing: String?, tone: androidx.compose.ui.graphics.Color) {
    val c = LocalMumeColors.current
    Row(
        Modifier.fillMaxWidth().heightIn(min = MumeTokens.MinPointerTarget),
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
            Spacer(Modifier.width(MumeTokens.Space.s3))
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
