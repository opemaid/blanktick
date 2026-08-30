package com.mume.desktop.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.mume.core.model.LinkVerdict
import com.mume.desktop.AppState
import com.mume.desktop.NoNetwork
import java.io.File
import javax.swing.JFileChooser
import javax.swing.UIManager

// ------------------------------------------------------------------- link

/**
 * The link checker.
 *
 * Identical analysis to the Android build and to the marketing site — all three
 * call `UrlAnalyzer` — and identically incapable of following a link. A
 * shortener resolves to *unknown*, never to *safe*, because resolving it would
 * require fetching it.
 */
@Composable
fun LinkScreen(state: AppState) {
    val c = LocalMumeColors.current
    val analysis by state.link.collectAsState()
    var input by remember { mutableStateOf("") }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(40.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Check a link", style = MaterialTheme.typography.headlineMedium, color = c.ink)
        Text(
            "Paste a link before you open it. Mume reads the address itself — it never visits it, " +
                "and cannot: this app has no way to make a network request.",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted
        )

        OutlinedTextField(
            value = input,
            onValueChange = { input = it; state.checkLink(it) },
            label = { Text("Link") },
            placeholder = { Text("https://…") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = { state.checkLink(input) })
        )

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            PrimaryButton("Check", enabled = input.isNotBlank()) { state.checkLink(input) }
            SecondaryButton("Clear", enabled = input.isNotBlank()) {
                input = ""
                state.clearLink()
            }
        }

        analysis?.let { result ->
            val tone = when (result.verdict) {
                LinkVerdict.DANGEROUS -> c.critical
                LinkVerdict.SUSPICIOUS -> c.high
                LinkVerdict.UNKNOWN -> c.medium
                LinkVerdict.SAFE -> c.pass
            }

            Card {
                Text(verdictLabel(result.verdict), style = MaterialTheme.typography.labelSmall, color = tone)
                Text(
                    result.displayHost ?: result.host ?: "Could not read an address from that",
                    style = MaterialTheme.typography.titleLarge,
                    color = c.ink
                )
                result.registrableDomain?.let {
                    KeyValueRow("The site you would actually reach", it)
                }
                result.impersonatedBrand?.let {
                    KeyValueRow("Looks like it is imitating", it, valueColor = c.critical)
                }
                KeyValueRow("Risk score", "${result.riskScore} / 100", valueColor = tone)

                if (result.verdict == LinkVerdict.UNKNOWN) {
                    Text(
                        "Unknown is a real answer, not a failure. Following this link to see where " +
                            "it goes is the one thing Mume will not do.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = c.inkMuted
                    )
                }
            }

            if (result.signals.isNotEmpty()) {
                SectionHeader("What Mume noticed", "${result.signals.size}")
                Card {
                    result.signals.sortedByDescending { it.weight }.forEach { signal ->
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(
                                signal.explanation,
                                style = MaterialTheme.typography.bodyMedium,
                                color = c.ink,
                                modifier = Modifier.weight(1f)
                            )
                            Spacer(Modifier.size(12.dp))
                            Text("+${signal.weight}", style = LedgerNumberStyle, color = c.inkMuted)
                        }
                    }
                }
            }
        }
    }
}

private fun verdictLabel(verdict: LinkVerdict): String = when (verdict) {
    LinkVerdict.SAFE -> "NOTHING SUSPICIOUS FOUND"
    LinkVerdict.UNKNOWN -> "UNKNOWN"
    LinkVerdict.SUSPICIOUS -> "SUSPICIOUS"
    LinkVerdict.DANGEROUS -> "DANGEROUS"
}

// --------------------------------------------------------------- passwords

/**
 * The password checker.
 *
 * ## What it does not do
 *
 * It does not read your browser's saved passwords. It could — the vaults are on
 * this disk and decryptable by this user — and it deliberately does not, because
 * an application that can silently decrypt your password store is one you have
 * to take on trust, and the entire point of this product is not asking for
 * trust. You type in what you want checked.
 *
 * The password never leaves this function's stack frame: it is hashed against a
 * per-run random salt for the reuse comparison and then dropped. Nothing on
 * screen or in memory afterwards can reconstruct it.
 */
@Composable
fun PasswordScreen(state: AppState) {
    val c = LocalMumeColors.current
    val checks by state.passwords.collectAsState()
    var label by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }

    val corpusAvailable = state.intel.isComplete
    val synthetic = state.intel.manifest?.synthetic == true

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(40.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Check a password", style = MaterialTheme.typography.headlineMedium, color = c.ink)
        Text(
            "Checked against a list of breached passwords built into the app. Nothing is sent " +
                "anywhere — not the password, not a hash of it, not even the fact that you " +
                "checked.",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted
        )

        when {
            synthetic -> Notice(
                "This build ships placeholder data instead of the real breach corpus, so a " +
                    "result here means nothing. Reported rather than hidden."
            )
            !corpusAvailable -> Notice(
                "The breach list is not bundled in this build, so passwords cannot be checked. " +
                    "Mume will say “could not check”, never “not found”."
            )
        }

        OutlinedTextField(
            value = label,
            onValueChange = { label = it },
            label = { Text("What is it for? (optional, stays on this screen)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = {
                state.checkPassword(label, password)
                password = ""
                label = ""
            })
        )

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            PrimaryButton("Check it", enabled = password.isNotEmpty()) {
                state.checkPassword(label, password)
                password = ""
                label = ""
            }
            SecondaryButton("Forget these results", enabled = checks.isNotEmpty()) {
                state.clearPasswords()
            }
        }

        if (checks.isNotEmpty()) {
            SectionHeader("This session", "${checks.size} checked")
            checks.forEach { check ->
                val tone: Color = when (check.breached) {
                    true -> c.critical
                    false -> c.pass
                    null -> c.notChecked
                }
                Card {
                    Text(
                        when (check.breached) {
                            true -> "FOUND IN A BREACH"
                            false -> "NOT IN THE LIST"
                            null -> "COULD NOT CHECK"
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = tone
                    )
                    Text(check.label, style = MaterialTheme.typography.bodyLarge, color = c.ink)
                    when (check.breached) {
                        true -> Text(
                            "This exact password appears in public breach lists. Attackers try " +
                                "these first, on every site. Change it wherever you have used it.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = c.inkMuted
                        )
                        false -> Text(
                            "Not in the bundled list. That is not the same as safe — the list is " +
                                "large but finite, and a password can be weak without ever having " +
                                "been breached.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = c.inkMuted
                        )
                        null -> Text(
                            "The breach list was not available, so no check was performed.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = c.inkMuted
                        )
                    }
                    if (check.reusedInSession) {
                        Text(
                            "You already entered this same password on this screen.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = c.high,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    if (check.length < 12) {
                        Text(
                            "${check.length} characters. Length is what actually resists guessing; " +
                                "aim for at least twelve.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = c.medium
                        )
                    }
                }
            }

            Notice(
                "These results feed the next scan as “${checks.size} passwords checked”. They " +
                    "describe only what you typed here — Mume has not read your browser's saved " +
                    "passwords and will not."
            )
        }
    }
}

// ------------------------------------------------------------------ photos

/**
 * Counts photos carrying a GPS position.
 *
 * The scan reads the first part of each file, looks for a GPS tag, and counts.
 * It never extracts the coordinates — see `ExifGps` — so at no point does the
 * process hold a location, which is why the result can be shown, screenshotted
 * and shared without leaking the thing it is warning about.
 */
@Composable
fun PhotoScreen(state: AppState) {
    val c = LocalMumeColors.current
    val photos by state.photos.collectAsState()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(40.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Photo locations", style = MaterialTheme.typography.headlineMedium, color = c.ink)
        Text(
            "Most phones write the exact spot a photo was taken into the file. Sharing the file " +
                "shares the address. Mume counts how many of yours do this — it does not read " +
                "where, and cannot.",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted
        )

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            PrimaryButton("Choose a folder…", enabled = !photos.scanning) {
                pickFolder()?.let(state::scanPhotos)
            }
            SecondaryButton("Clear", enabled = photos.done && !photos.scanning) {
                state.clearPhotos()
            }
        }

        photos.folder?.let {
            Text(it, style = MaterialTheme.typography.labelSmall, color = c.inkFaint)
        }

        if (photos.scanning) {
            Card {
                Text("SCANNING", style = MaterialTheme.typography.labelSmall, color = c.inkFaint)
                Text(
                    "${photos.scanned} photos read, ${photos.withLocation} with a location so far",
                    style = MaterialTheme.typography.bodyLarge,
                    color = c.ink
                )
            }
        }

        if (photos.done) {
            val share = if (photos.scanned > 0) photos.withLocation * 100 / photos.scanned else 0
            Card {
                Text(
                    if (photos.withLocation == 0) "NO LOCATIONS FOUND" else "LOCATIONS FOUND",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (photos.withLocation == 0) c.pass else c.high
                )
                Text(
                    "${photos.withLocation} of ${photos.scanned} photos carry an exact location",
                    style = MaterialTheme.typography.titleLarge,
                    color = c.ink
                )
                if (photos.withLocation > 0) {
                    Text(
                        "$share% of the photos Mume could read. Sending one of these to someone " +
                            "sends the place it was taken, usually to within a few metres.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = c.inkMuted
                    )
                    Text(
                        "Turn off location for the camera on the device that takes them, and strip " +
                            "location when sharing.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = c.kelp,
                        fontWeight = FontWeight.SemiBold
                    )
                }

                // Files that could not be read are stated, never folded into
                // the clean count. A "0 of 500" that quietly skipped 400 HEICs
                // would be the most reassuring possible lie.
                if (photos.unsupported > 0 || photos.unreadable > 0) {
                    Hairline()
                    if (photos.unsupported > 0) {
                        KeyValueRow(
                            "Not a format Mume reads (HEIC, PNG, WebP)",
                            photos.unsupported.toString(),
                            valueColor = c.notChecked
                        )
                    }
                    if (photos.unreadable > 0) {
                        KeyValueRow(
                            "Could not be read",
                            photos.unreadable.toString(),
                            valueColor = c.notChecked
                        )
                    }
                    Text(
                        "These are not counted as clean. Mume only reads JPEG, so a library of " +
                            "iPhone HEIC files will mostly land here.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = c.inkMuted
                    )
                }
            }
        }
    }
}

/** Swing's directory chooser. Returns null when the user cancels. */
private fun pickFolder(): File? = try {
    runCatching { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()) }
    val chooser = JFileChooser().apply {
        fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
        dialogTitle = "Choose a folder of photos"
    }
    if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) chooser.selectedFile else null
} catch (_: Exception) {
    null
}

// ------------------------------------------------------------------- about

@Composable
fun AboutScreen(state: AppState) {
    val c = LocalMumeColors.current
    val manifest = state.intel.manifest

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(40.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("About Mume", style = MaterialTheme.typography.headlineMedium, color = c.ink)

        Card {
            Text("THE PROMISE", style = MaterialTheme.typography.labelSmall, color = c.inkFaint)
            Text(
                "Mume does not connect to anything. No account, no upload, no server, no " +
                    "analytics. Every check runs against data that ships inside the application.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.ink
            )
        }

        SectionHeader("How that is enforced here")

        Card {
            Text(
                "On a phone the operating system enforces it: the Android build does not hold the " +
                    "INTERNET permission, so the kernel refuses every socket. A desktop has no " +
                    "equivalent, so this build uses two weaker mechanisms and says so rather than " +
                    "implying the same guarantee.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkMuted
            )
            Hairline()
            KeyValueRow("Build fails if any Mume class references a network API", "enforced", c.pass)
            KeyValueRow("java.net.Socket blocked at runtime", blockLabel(0), tone(0))
            KeyValueRow("http/https URLs blocked at runtime", blockLabel(1), tone(1))
            KeyValueRow("java.nio.channels", "not interceptable", c.notChecked)
            KeyValueRow("Native code and child processes", "out of reach", c.notChecked)
        }

        Notice(
            "If you want a hard guarantee rather than a strong one, add an outbound firewall rule " +
                "for this application. That is enforced by your operating system, not by us, " +
                "which is the only kind of guarantee worth having."
        )

        SectionHeader("This build")
        Card {
            KeyValueRow("Operating system", state.os?.displayName ?: "not recognised")
            KeyValueRow("Threat data built on", manifest?.builtOn ?: "not bundled")
            KeyValueRow(
                "Passwords in the list",
                manifest?.passwordCount?.takeIf { it > 0 }?.toString() ?: "—"
            )
            KeyValueRow(
                "Domains in the list",
                manifest?.domainCount?.takeIf { it > 0 }?.toString() ?: "—"
            )
            if (manifest?.synthetic == true) {
                Text(
                    "This data is synthetic placeholder content, not a real corpus. Results " +
                        "derived from it are not meaningful and the app labels them as such.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.medium,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }

        SectionHeader("What Mume deliberately cannot do")
        Card {
            Text(
                "• Check whether your email address appears in a breach. That needs a service, " +
                    "and there is none.\n" +
                    "• Expand a shortened link. It is reported unknown, never safe.\n" +
                    "• Tell you about threats discovered after this build. The threat data " +
                    "refreshes when the app updates.\n" +
                    "• Read your browser's saved passwords. It could; it will not.\n" +
                    "• Change any setting on this computer. It tells you; you decide.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkMuted
            )
        }

        Text(
            "Passing every check does not mean you are safe. It means these particular problems " +
                "are not present.",
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkFaint
        )
    }
}

/** Reports whether a given runtime block actually installed. */
@Composable
private fun blockLabel(index: Int): String {
    val gaps = NoNetwork.gaps
    val subject = if (index == 0) "java.net.Socket" else "java.net.URL"
    return if (gaps.any { it.startsWith(subject) }) "could not install" else "active"
}

@Composable
private fun tone(index: Int): Color {
    val c = LocalMumeColors.current
    return if (blockLabel(index) == "active") c.pass else c.medium
}
