package com.blanktick.core.model

/**
 * The platforms Blanktick ships on.
 *
 * Platform is carried on every snapshot because a large number of rules are
 * only observable on one of them (see ADR-002 / decision D-01). Rules declare
 * which platforms they apply to and are skipped elsewhere — they never emit a
 * hollow "passed" result on a platform that physically cannot check them.
 *
 * [DESKTOP] was added in phase 2. It is deliberately a sibling of the two
 * mobile platforms rather than a variant of them: a desktop observes a largely
 * disjoint set of facts (firewall, local administrators, autoruns, Secure
 * Boot) and cannot observe most of the mobile ones. Because [BaseRule] defaults
 * to the mobile pair, adding this constant could not silently enable an
 * existing rule on desktop — every rule that runs there had to opt in by name.
 */
enum class Platform { ANDROID, IOS, DESKTOP }

/**
 * Which desktop OS family a [Platform.DESKTOP] snapshot came from.
 *
 * Kept separate from [Platform] so that rules stay platform-gated rather than
 * OS-gated: a rule asks "can I observe this?" via the null contract, not "am I
 * on Windows?". The family is carried for wording — the same finding says
 * "BitLocker", "FileVault" or "LUKS" depending on this value — and never to
 * decide whether a check ran.
 */
enum class DesktopOs(val displayName: String) {
    WINDOWS("Windows"),
    MACOS("macOS"),
    LINUX("Linux")
}

/**
 * Severity of a finding.
 *
 * The ordinal ordering is load-bearing: findings are sorted by severity
 * descending for deterministic output, and [ScoringPolicy] maps each level to a
 * base deduction weight.
 */
enum class Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    val isActionable: Boolean get() = this != INFO
}

/**
 * Buckets that findings roll up into.
 *
 * Categories exist so that a pile-up in one area cannot alone destroy the score
 * (each has a cap in [ScoringPolicy]) and so the UI can group remediation.
 */
enum class Category(val displayName: String) {
    DEVICE_INTEGRITY("Device integrity"),
    OS_CURRENCY("System updates"),
    NETWORK("Network"),
    APP_HYGIENE("Apps"),
    DATA_EXPOSURE("Personal data"),
    ACCOUNT_SECURITY("Access & accounts")
}

/** Screen lock strength, ordered weakest to strongest. */
enum class ScreenLock {
    NONE,
    SWIPE,
    PATTERN,
    PIN_SHORT,      // <= 4 digits
    PIN_LONG,       // >= 5 digits
    PASSWORD,
    UNKNOWN
}

/** How confident we are in a link verdict. `UNKNOWN` is a real answer, not a failure. */
enum class LinkVerdict { SAFE, UNKNOWN, SUSPICIOUS, DANGEROUS }

/**
 * A single actionable problem found on the device.
 *
 * Every finding must carry a remediation. A finding the user cannot act on is
 * information, not a deduction — such things are emitted at [Severity.INFO] and
 * contribute zero to the score.
 *
 * @param ruleId stable identifier, e.g. `NET-CA-001`. Identical across Android
 *   and iOS implementations; the golden fixtures assert on these.
 * @param subjectId disambiguates multiple findings from the same rule (e.g. the
 *   package name of each offending app). Empty when the rule is a singleton.
 * @param weightMultiplier scales the severity's base weight; used by rules that
 *   have a natural intensity (e.g. how far past the patch window a device is).
 */
data class Finding(
    val ruleId: String,
    val category: Category,
    val severity: Severity,
    val title: String,
    val detail: String,
    val remediation: String,
    val subjectId: String = "",
    val weightMultiplier: Double = 1.0,
    val evidence: Map<String, String> = emptyMap()
) {
    init {
        require(ruleId.isNotBlank()) { "ruleId must not be blank" }
        require(weightMultiplier > 0.0) { "weightMultiplier must be positive, was $weightMultiplier" }
        require(severity == Severity.INFO || remediation.isNotBlank()) {
            "actionable finding $ruleId must carry a remediation"
        }
    }

    /** Stable key for deduplication and for the UI's diff between scans. */
    val key: String get() = if (subjectId.isEmpty()) ruleId else "$ruleId#$subjectId"
}

/**
 * A finding after scoring, carrying the exact number of points it cost.
 *
 * [deduction] is an integer so the UI can display "-14" and have the column of
 * numbers sum precisely to `100 - score`. See [com.blanktick.core.scoring.Apportionment].
 */
data class ScoredFinding(
    val finding: Finding,
    val deduction: Int,
    val rawDeduction: Double
)

/** Overall grade band. Thresholds live in [ScoringPolicy]. */
enum class Grade(val label: String) {
    STRONG("Strong"),
    GOOD("Good"),
    FAIR("Fair"),
    WEAK("Weak"),
    AT_RISK("At risk")
}

/** Per-category roll-up shown in the score breakdown. */
data class CategoryScore(
    val category: Category,
    val deduction: Int,
    val cappedAt: Int?,
    val findingCount: Int
)

/**
 * The complete result of a scan.
 *
 * @param checksRun rules that actually executed on this platform.
 * @param checksSkipped rules skipped because the platform cannot observe their
 *   inputs. Surfaced in the UI as "not applicable on iOS", never as "passed".
 */
data class ScanResult(
    val score: Int,
    val grade: Grade,
    val findings: List<ScoredFinding>,
    val categories: List<CategoryScore>,
    val checksRun: Int,
    val checksPassed: Int,
    val checksSkipped: Int,
    val platform: Platform,
    val intelBundleDate: String?,
    val intelStalenessDays: Int?,
    val scannedAt: Long
) {
    val actionableFindings: List<ScoredFinding>
        get() = findings.filter { it.finding.severity.isActionable }

    /** Invariant asserted by the test suite: displayed deductions must reconcile. */
    val deductionsReconcile: Boolean
        get() = 100 - findings.sumOf { it.deduction } == score
}
