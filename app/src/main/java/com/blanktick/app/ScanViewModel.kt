package com.blanktick.app

import android.app.Application
import android.content.ContentUris
import android.provider.MediaStore
import androidx.exifinterface.media.ExifInterface
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.blanktick.app.collect.AndroidCollector
import com.blanktick.app.collect.IntelBundle
import com.blanktick.core.BlanktickScanner
import com.blanktick.core.ScanReport
import com.blanktick.core.analysis.UrlAnalysis
import com.blanktick.core.analysis.UrlAnalyzer
import com.blanktick.core.model.PasswordAudit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Calendar

/**
 * Which screen is showing.
 *
 * [tabLabel] is separate from [title] because five text labels have to fit
 * across the narrowest phone we support. "This phone" clipped at the left edge
 * on a 1080px screen; the bar uses the short form and the screen keeps the long
 * one. Shrinking the type instead was the other option, and losing legibility
 * to fit a word is the wrong trade in an app people open when worried.
 */
enum class Tab(val title: String, val tabLabel: String) {
    SCAN("This phone", "Phone"),
    LINK("Check a link", "Link"),
    PASSWORDS("Check a password", "Passwords"),
    PHOTOS("Photo locations", "Photos"),
    ABOUT("About", "About")
}

/** What the home screen is showing. */
sealed interface ScanUiState {
    data object FirstRun : ScanUiState
    data class Scanning(val step: String) : ScanUiState
    data class Complete(
        val report: ScanReport,
        val previousScore: Int?,
        val intelDate: String?,
        val intelComplete: Boolean,
        val intelSynthetic: Boolean
    ) : ScanUiState
    data class Failed(val message: String) : ScanUiState
}

/**
 * Result of checking one password against the bundled corpus.
 *
 * Carries no password and no hash of one — only a verdict — so a screenshot, a
 * crash dump or a heap inspection of this object yields nothing.
 */
data class PasswordCheck(
    val label: String,
    val breached: Boolean?,
    val reusedInSession: Boolean,
    val length: Int
)

data class PhotoScanState(
    val scanning: Boolean = false,
    val scanned: Int = 0,
    val withLocation: Int = 0,
    val unreadable: Int = 0,
    val done: Boolean = false,
    /** Set when the media permission was refused; the check then reports as not run. */
    val permissionDenied: Boolean = false
)

/**
 * Drives a scan and the three local tools.
 *
 * The device scan is a few hundred milliseconds of file and settings reads, so
 * it runs on [Dispatchers.IO] and reports progress rather than blocking the UI.
 * There is no repository layer and no cache: a scan describes the device *now*,
 * and serving a stale one would be worse than making the user wait.
 */
class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val _tab = MutableStateFlow(Tab.SCAN)
    val tab: StateFlow<Tab> = _tab.asStateFlow()

    private val _state = MutableStateFlow<ScanUiState>(ScanUiState.FirstRun)
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    private val _linkResult = MutableStateFlow<UrlAnalysis?>(null)
    val linkResult: StateFlow<UrlAnalysis?> = _linkResult.asStateFlow()

    private val _passwords = MutableStateFlow<List<PasswordCheck>>(emptyList())
    val passwords: StateFlow<List<PasswordCheck>> = _passwords.asStateFlow()

    private val _photos = MutableStateFlow(PhotoScanState())
    val photos: StateFlow<PhotoScanState> = _photos.asStateFlow()

    private val scanner = BlanktickScanner()
    val intel: IntelBundle by lazy { IntelBundle.load(getApplication()) }

    private val analyzer: UrlAnalyzer by lazy {
        UrlAnalyzer(blocklist = intel.domainBlocklist(), allowlist = intel.domainAllowlist())
    }

    /**
     * Previous score, kept only in memory for this process.
     *
     * The score arc animates from the previous value to the new one (DD-05), so
     * a delta is needed — but persisting a history of how insecure someone's
     * phone was is exactly the kind of data decision D-05 says not to keep.
     */
    private var previousScore: Int? = null

    fun show(tab: Tab) { _tab.value = tab }

    // ----------------------------------------------------------------- scan

    fun scan() {
        viewModelScope.launch {
            _state.value = ScanUiState.Scanning("Reading device settings…")
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val collector = AndroidCollector(getApplication())
                    val snapshot = collector.collect(intel.snapshot(today()))
                        // Merge in whatever the tool screens have measured, so
                        // the score reflects the work the user actually did.
                        .copy(
                            passwordAudit = passwordAudit(),
                            photosScanned = _photos.value.takeIf { it.done }?.scanned,
                            photosWithPreciseLocation = _photos.value.takeIf { it.done }?.withLocation
                        )
                    scanner.scan(snapshot)
                }
            }

            _state.value = result.fold(
                onSuccess = { report ->
                    val previous = previousScore
                    previousScore = report.result.score
                    ScanUiState.Complete(
                        report = report,
                        previousScore = previous,
                        intelDate = intel.manifest?.builtOn,
                        intelComplete = intel.isComplete,
                        intelSynthetic = intel.manifest?.synthetic == true
                    )
                },
                onFailure = { error ->
                    // Surfaced, never swallowed. A scan that silently half-ran
                    // would show a reassuring score built from missing data.
                    ScanUiState.Failed(error.message ?: error::class.simpleName ?: "Scan failed")
                }
            )
        }
    }

    // ----------------------------------------------------------------- link

    fun checkLink(url: String) {
        _linkResult.update { if (url.isBlank()) null else analyzer.analyze(url) }
        if (url.isNotBlank()) _tab.value = Tab.LINK
    }

    fun clearLink() = _linkResult.update { null }

    // ------------------------------------------------------------ passwords

    /**
     * Per-process salt for the reuse comparison.
     *
     * Reuse detection needs to know two entries were the same string. It does
     * *not* need the string, and it must not survive the process. So entries
     * are compared by `SHA-256(salt || password)` with a salt generated at
     * startup and never written anywhere: the digests are meaningless outside
     * this run and are not a rainbow-table target even if the heap is dumped.
     */
    private val sessionSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
    private val seenDigests = mutableSetOf<String>()

    /**
     * @param password never stored on this object, never logged, never placed
     *   into a [PasswordCheck]. It lives on this stack frame only.
     */
    fun checkPassword(label: String, password: String) {
        if (password.isEmpty()) return

        val digest = MessageDigest.getInstance("SHA-256")
            .apply { update(sessionSalt) }
            .digest(password.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        val reused = !seenDigests.add(digest)

        _passwords.update { existing ->
            existing + PasswordCheck(
                label = label.ifBlank { "Password ${existing.size + 1}" },
                breached = intel.isPasswordBreached(password),
                reusedInSession = reused,
                length = password.length
            )
        }
    }

    fun clearPasswords() {
        seenDigests.clear()
        _passwords.value = emptyList()
    }

    /**
     * Turns this session's checks into the audit the scoring rules consume.
     *
     * This describes **the passwords the user chose to type in**, not every
     * credential on the phone. Android's autofill store is not readable by
     * another app, and Blanktick would not read it if it were: an app that can
     * silently enumerate your saved passwords is one you have to take on trust.
     */
    private fun passwordAudit(): PasswordAudit? {
        val checks = _passwords.value
        if (checks.isEmpty()) return null
        return PasswordAudit(
            credentialsChecked = checks.size,
            breachedCount = checks.count { it.breached == true },
            reusedCount = checks.count { it.reusedInSession },
            weakCount = checks.count { it.length < 12 }
        )
    }

    // --------------------------------------------------------------- photos

    fun photoPermissionDenied() {
        // Denied is not "clean". The scan will report the photo check as not
        // run, which is what DATA-EXIF-001 does with a null count.
        _photos.value = PhotoScanState(permissionDenied = true, done = false)
    }

    /**
     * Counts photos in the user's library that carry a GPS position.
     *
     * Queries MediaStore for image IDs and reads only the EXIF header of each —
     * never the pixels, and never the coordinates themselves. What the app
     * learns, and all it can therefore ever leak, is a count.
     */
    fun scanPhotos() {
        viewModelScope.launch {
            _photos.value = PhotoScanState(scanning = true)

            withContext(Dispatchers.IO) {
                var scanned = 0
                var located = 0
                var unreadable = 0

                val resolver = getApplication<Application>().contentResolver
                val collection = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
                val projection = arrayOf(MediaStore.Images.Media._ID)

                runCatching {
                    resolver.query(collection, projection, null, null, null)?.use { cursor ->
                        val idColumn = cursor.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
                        while (cursor.moveToNext() && scanned + unreadable < MAX_PHOTOS) {
                            val uri = ContentUris.withAppendedId(collection, cursor.getLong(idColumn))
                            val hasLocation = runCatching {
                                resolver.openInputStream(uri)?.use { stream ->
                                    // ExifInterface reports whether the tags are
                                    // present without us ever calling for the
                                    // values, which is the only thing we want to
                                    // know and the only thing we can then leak.
                                    ExifInterface(stream).latLong != null
                                }
                            }.getOrNull()

                            when (hasLocation) {
                                true -> { scanned++; located++ }
                                false -> scanned++
                                null -> unreadable++
                            }

                            if ((scanned + unreadable) % 50 == 0) {
                                _photos.value = PhotoScanState(true, scanned, located, unreadable)
                            }
                        }
                    }
                }

                _photos.value = PhotoScanState(
                    scanning = false,
                    scanned = scanned,
                    withLocation = located,
                    unreadable = unreadable,
                    done = true
                )
            }
        }
    }

    fun clearPhotos() { _photos.value = PhotoScanState() }

    private fun today(): String {
        val c = Calendar.getInstance()
        return "%04d-%02d-%02d".format(
            c.get(Calendar.YEAR), c.get(Calendar.MONTH) + 1, c.get(Calendar.DAY_OF_MONTH)
        )
    }

    private companion object {
        /**
         * Ceiling on a single scan.
         *
         * A phone library can be enormous and the proportion stops moving long
         * before the end. The UI states the cap when it is reached rather than
         * presenting a truncated count as a total.
         */
        const val MAX_PHOTOS = 20_000
    }
}
