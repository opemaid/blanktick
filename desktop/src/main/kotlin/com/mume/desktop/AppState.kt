package com.mume.desktop

import com.mume.core.MumeScanner
import com.mume.core.ScanReport
import com.mume.core.analysis.ExifGps
import com.mume.core.analysis.UrlAnalysis
import com.mume.core.analysis.UrlAnalyzer
import com.mume.core.model.DesktopOs
import com.mume.core.model.PasswordAudit
import com.mume.desktop.collect.DesktopCollector
import com.mume.desktop.collect.DesktopIntel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.LocalDate

/** Which screen the window is showing. */
enum class Screen(val title: String) {
    SCAN("This computer"),
    LINK("Check a link"),
    PASSWORDS("Check a password"),
    PHOTOS("Photo locations"),
    SOFTWARE("Installed software"),
    USB("USB & drives"),
    SETTINGS("Settings"),
    ABOUT("About")
}

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
    /** The OS is not one this build knows how to inspect. */
    data class Unsupported(val osName: String) : ScanUiState
}

/**
 * Result of checking one password against the bundled corpus.
 *
 * Carries no password and no hash of one — only a verdict — so a screenshot,
 * a crash dump or a heap inspection of this object yields nothing.
 */
data class PasswordCheck(
    val label: String,
    val breached: Boolean?,
    val reusedInSession: Boolean,
    val length: Int
)

data class PhotoScanState(
    val folder: String? = null,
    val scanning: Boolean = false,
    val scanned: Int = 0,
    val withLocation: Int = 0,
    val unreadable: Int = 0,
    val unsupported: Int = 0,
    val done: Boolean = false
)

/**
 * The whole application's state.
 *
 * A single holder rather than one per screen, because the screens are not
 * independent: a photo scan and a password check both feed the *next* device
 * scan, exactly as they do on Android. Keeping that wiring in one place is what
 * stops the score and the screens disagreeing about what was measured.
 */
class AppState(private val scope: CoroutineScope) {

    private val scanner = MumeScanner()
    val intel: DesktopIntel by lazy { DesktopIntel.load() }

    private val analyzer: UrlAnalyzer by lazy {
        UrlAnalyzer(blocklist = intel.domainBlocklist(), allowlist = intel.domainAllowlist())
    }

    private val _screen = MutableStateFlow(Screen.SCAN)
    val screen: StateFlow<Screen> = _screen.asStateFlow()

    private val _scan = MutableStateFlow<ScanUiState>(ScanUiState.FirstRun)
    val scan: StateFlow<ScanUiState> = _scan.asStateFlow()

    private val _link = MutableStateFlow<UrlAnalysis?>(null)
    val link: StateFlow<UrlAnalysis?> = _link.asStateFlow()

    private val _passwords = MutableStateFlow<List<PasswordCheck>>(emptyList())
    val passwords: StateFlow<List<PasswordCheck>> = _passwords.asStateFlow()

    private val _photos = MutableStateFlow(PhotoScanState())
    val photos: StateFlow<PhotoScanState> = _photos.asStateFlow()

    private val _settings = MutableStateFlow(Settings.load())
    val settings: StateFlow<Settings> = _settings.asStateFlow()

    /**
     * The desktop block from the last scan.
     *
     * Held so the software and USB screens can show what the scan already read,
     * rather than each running its own collection pass. One scan, one set of
     * facts — a screen that re-queried independently could disagree with the
     * dashboard, and then neither would be trustworthy.
     */
    private val _desktopFacts = MutableStateFlow<com.mume.core.model.DesktopFacts?>(null)
    var desktopFacts: com.mume.core.model.DesktopFacts? = null
        private set

    /** Null until a scan has run: the inventory is a product of the scan, not a separate walk. */
    private val _programs = MutableStateFlow<List<com.mume.core.model.InstalledProgram>?>(null)
    val programs: StateFlow<List<com.mume.core.model.InstalledProgram>?> = _programs.asStateFlow()

    /** Set when a settings write fails, so the UI can say so rather than silently forget. */
    private val _settingsError = MutableStateFlow<String?>(null)
    val settingsError: StateFlow<String?> = _settingsError.asStateFlow()

    fun update(transform: (Settings) -> Settings) {
        val next = transform(_settings.value)
        _settings.value = next
        _settingsError.value = if (Settings.save(next)) null
        else "Could not write " + Settings.file().absolutePath + ". Changes apply now but will not survive a restart."
    }

    /**
     * Previous score, held in memory for this process only.
     *
     * The dial animates from the last value rather than from zero, so a delta is
     * needed. Writing a history of how insecure someone's computer was to disk
     * is exactly the data decision D-05 says not to keep.
     */
    private var previousScore: Int? = null

    val os: DesktopOs? = DesktopCollector.detectOs()

    fun show(screen: Screen) { _screen.value = screen }

    // ----------------------------------------------------------------- scan

    fun runScan() {
        scope.launch {
            val collector = DesktopCollector.forCurrentOs()
            if (collector == null) {
                _scan.value = ScanUiState.Unsupported(System.getProperty("os.name") ?: "unknown")
                return@launch
            }

            _scan.value = ScanUiState.Scanning("Reading system settings…")

            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val snapshot = collector
                        .collect(intel.snapshot(LocalDate.now().toString()))
                        // Merge in whatever the other screens have measured, so
                        // the score reflects the work the user actually did.
                        .copy(
                            passwordAudit = passwordAudit(),
                            photosScanned = _photos.value.takeIf { it.done }?.scanned,
                            photosWithPreciseLocation = _photos.value.takeIf { it.done }?.withLocation
                        )
                    _programs.value = snapshot.desktop?.installedPrograms
                    desktopFacts = snapshot.desktop
                    scanner.scan(snapshot)
                }
            }

            _scan.value = result.fold(
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
                    // Surfaced, never swallowed. A partly-finished scan shown as
                    // a score would be a reassuring number built from a failure.
                    ScanUiState.Failed(error.message ?: error::class.simpleName ?: "Scan failed")
                }
            )
        }
    }

    // ----------------------------------------------------------------- link

    fun checkLink(url: String) {
        _link.update { if (url.isBlank()) null else analyzer.analyze(url) }
    }

    fun clearLink() = _link.update { null }

    // ------------------------------------------------------------ passwords

    /**
     * Per-process salt for the reuse comparison.
     *
     * Reuse detection needs to know that two entries were the same string. It
     * does *not* need the string, and it must not survive the process. So
     * entries are compared by `SHA-256(salt || password)` with a salt generated
     * at startup and never written anywhere: the digests are meaningless outside
     * this run, and are not a rainbow-table target even if the heap is dumped.
     */
    private val sessionSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
    private val seenDigests = mutableSetOf<String>()

    /**
     * Checks one password against the bundled corpus.
     *
     * The password is a parameter and a local; it is never stored on this
     * object, never logged, and never placed in a [PasswordCheck].
     *
     * @return `breached = null` when the corpus is not bundled, which the UI
     *   must render as "could not check" and never as "not found".
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
     * Note what this is and is not: it describes **the passwords the user chose
     * to type in**, not every credential on the machine. Mume does not read
     * browser password stores — doing so would mean decrypting the user's vault,
     * which is a capability a security app should not have and a user cannot
     * verify the app is not abusing. The UI says exactly this next to the count.
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

    /**
     * Walks a folder counting photos that carry a GPS position.
     *
     * Reads at most the first [ExifGps.BYTES_TO_READ] of each file and never
     * extracts the coordinates. Progress is published as it goes because a
     * photo library can be tens of thousands of files and a frozen window with
     * no explanation is indistinguishable from a hang.
     */
    fun scanPhotos(folder: File) {
        scope.launch {
            _photos.value = PhotoScanState(folder = folder.absolutePath, scanning = true)

            withContext(Dispatchers.IO) {
                var scanned = 0
                var located = 0
                var unreadable = 0
                var unsupported = 0

                folder.walkTopDown()
                    .onEnter { !it.isHidden }
                    .filter { it.isFile && it.length() > 0 }
                    .filter { it.extension.lowercase() in PHOTO_EXTENSIONS }
                    .take(MAX_PHOTOS)
                    .forEach { file ->
                        when (inspect(file)) {
                            ExifGps.Verdict.HAS_LOCATION -> { scanned++; located++ }
                            ExifGps.Verdict.NO_LOCATION -> scanned++
                            ExifGps.Verdict.UNSUPPORTED -> unsupported++
                            ExifGps.Verdict.UNREADABLE -> unreadable++
                        }

                        if ((scanned + unreadable + unsupported) % 50 == 0) {
                            _photos.value = PhotoScanState(
                                folder.absolutePath, true, scanned, located, unreadable, unsupported
                            )
                        }
                    }

                _photos.value = PhotoScanState(
                    folder = folder.absolutePath,
                    scanning = false,
                    scanned = scanned,
                    withLocation = located,
                    unreadable = unreadable,
                    unsupported = unsupported,
                    done = true
                )
            }
        }
    }

    fun clearPhotos() { _photos.value = PhotoScanState() }

    private fun inspect(file: File): ExifGps.Verdict = try {
        val head = ByteArray(minOf(file.length(), ExifGps.BYTES_TO_READ.toLong()).toInt())
        file.inputStream().use { it.read(head) }
        ExifGps.inspect(head)
    } catch (_: Exception) {
        // Permission denied, file vanished mid-walk: unreadable, not clean.
        ExifGps.Verdict.UNREADABLE
    }

    private companion object {
        /** JPEG only — see [ExifGps]. Others are counted as unsupported. */
        val PHOTO_EXTENSIONS = setOf("jpg", "jpeg", "jpe", "heic", "heif", "png", "webp")

        /**
         * Ceiling on a single scan.
         *
         * A photo library can be enormous and the answer stops changing long
         * before the end. The UI states the cap when it is hit rather than
         * presenting a truncated count as a total.
         */
        const val MAX_PHOTOS = 20_000
    }
}
