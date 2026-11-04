package com.blanktick.app.ui

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.blanktick.app.PasswordCheck
import com.blanktick.app.ScanViewModel
import com.blanktick.core.model.LinkVerdict

/**
 * The three local tools and the About screen.
 *
 * Each one is the phone-shaped twin of a desktop screen and calls the identical
 * core code, so the two builds cannot disagree about a verdict — only about
 * layout.
 */

// ------------------------------------------------------------------- link

@Composable
fun LinkScreen(viewModel: ScanViewModel, padding: PaddingValues) {
    val c = LocalBlanktickColors.current
    val analysis by viewModel.linkResult.collectAsStateWithLifecycle()
    var input by remember { mutableStateOf("") }

    LazyColumn(
        Modifier.fillMaxSize().padding(padding),
        contentPadding = PaddingValues(16.dp, 16.dp, 16.dp, 32.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text("Check a link", style = MaterialTheme.typography.headlineMedium, color = c.ink)
        }
        item {
            Text(
                "Paste a link before you open it, or share one to Blanktick from any app. Blanktick reads " +
                    "the address itself — it never visits it, and cannot: this app has no " +
                    "permission to reach the internet.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkMuted
            )
        }
        item {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it; viewModel.checkLink(it) },
                label = { Text("Link") },
                placeholder = { Text("https://…") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Done
                )
            )
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                BlanktickButton("Check", enabled = input.isNotBlank()) { viewModel.checkLink(input) }
                BlanktickOutlineButton("Clear", enabled = input.isNotBlank()) {
                    input = ""
                    viewModel.clearLink()
                }
            }
        }

        analysis?.let { result ->
            val tone = when (result.verdict) {
                LinkVerdict.DANGEROUS -> c.critical
                LinkVerdict.SUSPICIOUS -> c.high
                LinkVerdict.UNKNOWN -> c.medium
                LinkVerdict.SAFE -> c.pass
            }

            item {
                ToolCard {
                    Text(verdictLabel(result.verdict), style = MaterialTheme.typography.labelSmall, color = tone)
                    Text(
                        result.displayHost ?: result.host ?: "No address could be read from that",
                        style = MaterialTheme.typography.titleLarge,
                        color = c.ink
                    )
                    result.registrableDomain?.let { Row2("The site you would actually reach", it) }
                    result.impersonatedBrand?.let { Row2("Looks like it is imitating", it, c.critical) }
                    Row2("Risk score", "${result.riskScore} / 100", tone)

                    if (result.verdict == LinkVerdict.UNKNOWN) {
                        Text(
                            "Unknown is a real answer, not a failure. Following this link to see " +
                                "where it goes is the one thing Blanktick will not do.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = c.inkMuted
                        )
                    }
                }
            }

            if (result.signals.isNotEmpty()) {
                item { ToolSectionHeader("What Blanktick noticed", "${result.signals.size}") }
                items(result.signals.sortedByDescending { it.weight }, key = { it.id }) { signal ->
                    ToolCard {
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
 * It does not read your saved passwords. Android does not let one app read
 * another's autofill store, and Blanktick would not read it if it could: an app that
 * can silently enumerate your credentials is one you have to take on trust, and
 * the point of this product is not asking for trust. You type in what you want
 * checked.
 *
 * The password never leaves the view model's stack frame: it is hashed against a
 * per-run random salt for the reuse comparison and then dropped.
 */
@Composable
fun PasswordScreen(viewModel: ScanViewModel, padding: PaddingValues) {
    val c = LocalBlanktickColors.current
    val checks by viewModel.passwords.collectAsStateWithLifecycle()
    var label by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }

    val corpusAvailable = viewModel.intel.isComplete
    val synthetic = viewModel.intel.manifest?.synthetic == true

    LazyColumn(
        Modifier.fillMaxSize().padding(padding),
        contentPadding = PaddingValues(16.dp, 16.dp, 16.dp, 32.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { Text("Check a password", style = MaterialTheme.typography.headlineMedium, color = c.ink) }
        item {
            Text(
                "Checked against a list of breached passwords built into the app. Nothing is sent " +
                    "anywhere — not the password, not a hash of it, not even the fact that you " +
                    "checked.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkMuted
            )
        }

        if (synthetic) {
            item {
                ToolNotice(
                    "This build ships placeholder data instead of the real breach corpus, so a " +
                        "result here means nothing. Reported rather than hidden."
                )
            }
        } else if (!corpusAvailable) {
            item {
                ToolNotice(
                    "The breach list is not bundled in this build, so passwords cannot be " +
                        "checked. Blanktick will say “could not check”, never “not found”."
                )
            }
        }

        item {
            OutlinedTextField(
                value = label,
                onValueChange = { label = it },
                label = { Text("What is it for? (optional)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
        }
        item {
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Password") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done
                )
            )
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                BlanktickButton("Check it", enabled = password.isNotEmpty()) {
                    viewModel.checkPassword(label, password)
                    password = ""
                    label = ""
                }
                BlanktickOutlineButton("Forget results", enabled = checks.isNotEmpty()) {
                    viewModel.clearPasswords()
                }
            }
        }

        if (checks.isNotEmpty()) {
            item { ToolSectionHeader("This session", "${checks.size} checked") }
            items(checks) { check -> PasswordResultCard(check) }
            item {
                ToolNotice(
                    "These feed the next scan as “${checks.size} passwords checked”. They describe " +
                        "only what you typed here — Blanktick cannot read your saved passwords, and " +
                        "would not."
                )
            }
        }
    }
}

@Composable
private fun PasswordResultCard(check: PasswordCheck) {
    val c = LocalBlanktickColors.current
    val tone: Color = when (check.breached) {
        true -> c.critical
        false -> c.pass
        null -> c.notChecked
    }

    ToolCard {
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
        Text(
            when (check.breached) {
                true -> "This exact password appears in public breach lists. Attackers try these " +
                    "first, on every site. Change it wherever you have used it."
                false -> "Not in the bundled list. That is not the same as safe — the list is " +
                    "large but finite, and a password can be weak without ever having been " +
                    "breached."
                null -> "The breach list was not available, so no check was performed."
            },
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted
        )
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
                "${check.length} characters. Length is what actually resists guessing; aim for at " +
                    "least twelve.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.medium
            )
        }
    }
}

// ------------------------------------------------------------------ photos

/**
 * Counts photos carrying a GPS position.
 *
 * Reads the EXIF header of each image in the library and asks one question of
 * it. The coordinates are never read into a variable, so the count is the only
 * thing this feature can ever disclose — including to us, in a crash report we
 * do not collect.
 */
@Composable
fun PhotoScreen(viewModel: ScanViewModel, padding: PaddingValues) {
    val c = LocalBlanktickColors.current
    val photos by viewModel.photos.collectAsStateWithLifecycle()

    val permission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        Manifest.permission.READ_MEDIA_IMAGES
    } else {
        @Suppress("DEPRECATION") Manifest.permission.READ_EXTERNAL_STORAGE
    }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) viewModel.scanPhotos() else viewModel.photoPermissionDenied()
    }

    LazyColumn(
        Modifier.fillMaxSize().padding(padding),
        contentPadding = PaddingValues(16.dp, 16.dp, 16.dp, 32.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { Text("Photo locations", style = MaterialTheme.typography.headlineMedium, color = c.ink) }
        item {
            Text(
                "Most phones write the exact spot a photo was taken into the file. Sharing the " +
                    "file shares the address. Blanktick counts how many of yours do this — it does not " +
                    "read where, and cannot.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkMuted
            )
        }
        item {
            ToolNotice(
                "This needs permission to read your photos. It is used to read the header of each " +
                    "image and nothing else: no picture is opened, copied, or sent."
            )
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                BlanktickButton("Scan my photos", enabled = !photos.scanning) { launcher.launch(permission) }
                BlanktickOutlineButton("Clear", enabled = photos.done) { viewModel.clearPhotos() }
            }
        }

        if (photos.permissionDenied) {
            item {
                ToolNotice(
                    "Permission was declined, so no photos were looked at. The scan will report " +
                        "this check as not run — never as passed."
                )
            }
        }

        if (photos.scanning) {
            item {
                ToolCard {
                    Text("SCANNING", style = MaterialTheme.typography.labelSmall, color = c.inkFaint)
                    Text(
                        "${photos.scanned} read, ${photos.withLocation} with a location so far",
                        style = MaterialTheme.typography.bodyLarge,
                        color = c.ink
                    )
                }
            }
        }

        if (photos.done) {
            item {
                val share = if (photos.scanned > 0) photos.withLocation * 100 / photos.scanned else 0
                ToolCard {
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
                            "$share% of the photos Blanktick could read. Sending one of these to " +
                                "someone sends the place it was taken, usually to within a few " +
                                "metres.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = c.inkMuted
                        )
                        Text(
                            "Turn off location for your camera app, and strip location when sharing.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = c.kelp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    if (photos.unreadable > 0) {
                        HorizontalDivider(color = c.hairline)
                        Row2("Could not be read", photos.unreadable.toString(), c.notChecked)
                        Text(
                            "These are not counted as clean.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = c.inkMuted
                        )
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------- about

@Composable
fun AboutScreen(viewModel: ScanViewModel, padding: PaddingValues) {
    val c = LocalBlanktickColors.current
    val manifest = viewModel.intel.manifest

    LazyColumn(
        Modifier.fillMaxSize().padding(padding),
        contentPadding = PaddingValues(16.dp, 16.dp, 16.dp, 32.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { Text("About Blanktick", style = MaterialTheme.typography.headlineMedium, color = c.ink) }

        item {
            ToolCard {
                Text("THE PROMISE", style = MaterialTheme.typography.labelSmall, color = c.inkFaint)
                Text(
                    "Blanktick has no permission to reach the internet. Not restricted, not " +
                        "well-behaved — the permission is absent from the app, so Android itself " +
                        "refuses every connection this app could ever attempt.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.ink
                )
                Text(
                    "You can check that yourself, without trusting us:\n" +
                        "Settings → Apps → Blanktick → Permissions, and in a terminal:\n" +
                        "aapt dump permissions blanktick.apk",
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.inkMuted
                )
            }
        }

        item { ToolSectionHeader("This build") }
        item {
            ToolCard {
                Row2("Threat data built on", manifest?.builtOn ?: "not bundled")
                Row2(
                    "Passwords in the list",
                    manifest?.passwordCount?.takeIf { it > 0 }?.toString() ?: "—"
                )
                Row2("Domains in the list", manifest?.domainCount?.takeIf { it > 0 }?.toString() ?: "—")
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
        }

        item { ToolSectionHeader("What Blanktick deliberately cannot do") }
        item {
            ToolCard {
                Text(
                    "• Check whether your email address appears in a breach. That needs a " +
                        "service, and there is none.\n" +
                        "• Expand a shortened link. It is reported unknown, never safe.\n" +
                        "• Tell you about threats discovered after this build. The threat data " +
                        "refreshes when the app updates.\n" +
                        "• Block trackers or filter DNS. That needs network capability, which " +
                        "this app does not have.\n" +
                        "• Read your saved passwords. Android does not allow it, and we would not " +
                        "want it.\n" +
                        "• Change any setting on this phone. It tells you; you decide.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.inkMuted
                )
            }
        }

        item {
            Text(
                "Passing every check does not mean you are safe. It means these particular " +
                    "problems are not present.",
                style = MaterialTheme.typography.bodyMedium,
                color = c.inkFaint
            )
        }
    }
}

// -------------------------------------------------------------- components

@Composable
private fun ToolCard(content: @Composable () -> Unit) {
    val c = LocalBlanktickColors.current
    Surface(
        color = c.surface,
        shape = RoundedCornerShape(BlanktickTokens.Radius.lg),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            content()
        }
    }
}

@Composable
private fun ToolNotice(text: String) {
    val c = LocalBlanktickColors.current
    Surface(
        color = c.surfaceSunk,
        shape = RoundedCornerShape(BlanktickTokens.Radius.lg),
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkMuted,
            modifier = Modifier.padding(16.dp)
        )
    }
}

@Composable
private fun ToolSectionHeader(title: String, trailing: String? = null) {
    val c = LocalBlanktickColors.current
    Row(
        Modifier.fillMaxWidth().padding(top = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(title, style = MaterialTheme.typography.bodyLarge, color = c.ink, fontWeight = FontWeight.SemiBold)
        trailing?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted) }
    }
}

@Composable
private fun Row2(label: String, value: String, valueColor: Color? = null) {
    val c = LocalBlanktickColors.current
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = c.inkMuted, modifier = Modifier.weight(1f))
        Spacer(Modifier.size(12.dp))
        Text(value, style = MaterialTheme.typography.bodyMedium, color = valueColor ?: c.ink)
    }
}

@Composable
private fun BlanktickButton(label: String, enabled: Boolean = true, onClick: () -> Unit) {
    val c = LocalBlanktickColors.current
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.heightIn(min = BlanktickTokens.MinTouchTarget),
        shape = RoundedCornerShape(BlanktickTokens.Radius.sm),
        // blanktick.org CTA: brand kelp, paper text (9.34:1), both themes.
        colors = ButtonDefaults.buttonColors(
            containerColor = BlanktickTokens.Brand.kelp,
            contentColor = BlanktickTokens.Light.paper
        )
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun BlanktickOutlineButton(label: String, enabled: Boolean = true, onClick: () -> Unit) {
    val c = LocalBlanktickColors.current
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.heightIn(min = BlanktickTokens.MinTouchTarget),
        shape = RoundedCornerShape(BlanktickTokens.Radius.sm)
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, color = c.ink)
    }
}
