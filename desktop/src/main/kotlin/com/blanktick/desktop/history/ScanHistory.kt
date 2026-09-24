package com.blanktick.desktop.history

import com.blanktick.core.ScanReport
import com.blanktick.core.json.Json
import com.blanktick.core.json.JsonValue
import com.blanktick.desktop.Settings
import java.io.File
import java.time.Instant

/**
 * A local, append-only record of past scans, so an MCP client (Claude, or any
 * other) can *ask* about this machine instead of re-running a ~100-second scan
 * every time. The client connects over stdio and searches this file; Blanktick
 * still opens no socket, and the bytecode gate still forbids one.
 *
 * ## This deliberately revises decision D-05
 *
 * D-05 said Blanktick keeps no history of how insecure a machine was, because a
 * file listing a machine's weaknesses is a map for whoever reads it next — and
 * "the app never touches the network" does **not** change that: a local file is
 * a local file, readable by any process running as the user. The product owner
 * has since asked for exactly this store, so it exists — but only under the two
 * constraints that keep it faithful to the reason D-05 existed:
 *
 *  1. **Off by default.** Nothing is recorded unless the user turns on
 *     [Settings.keepHistory]. The default posture is still "keep nothing".
 *
 *  2. **Summary, never snapshot.** Only rule *outcomes* are stored — id,
 *     severity, category, the generic on-screen title, points. The sensitive
 *     specifics (the actual DNS address, account names, open ports, and any
 *     full paths) live in `Finding.detail`, `Finding.evidence` and the raw
 *     `DeviceSnapshot`, and **none of those reach this file**. [historyOmits]
 *     is asserted by the test suite. What is kept answers "what is wrong, and
 *     what changed"; it is not enough to be a target map.
 *
 * `subjectId` is kept because it is the finding's identity across scans (the
 * key that lets "what changed" work). Where it names a program it reveals no
 * more than local malware already sees by reading that program's own path.
 *
 * ## Format
 *
 * JSON Lines: one object per scan, appended. Line-oriented so a person auditing
 * the privacy claim can read it in a text editor, and so a truncated write
 * costs one snapshot rather than the file — same reasoning as the intel
 * manifest (D-03). Parsed with the hand-rolled [Json]; no new dependency.
 */
object ScanHistory {

    /** Fields on a finding that must never be written here. Asserted by a test. */
    val historyOmits = listOf("detail", "remediation", "evidence")

    fun file(): File = File(Settings.file().parentFile, "history.jsonl")

    /**
     * Append a summarized snapshot — but only if the user has opted in.
     *
     * Silently does nothing when history is off, which is the default: a scan
     * that changes no file is the D-05 behaviour, and callers should be able to
     * record unconditionally without first checking a flag.
     */
    fun record(report: ScanReport, settings: Settings = Settings.load(), at: File = file()) {
        if (!settings.keepHistory) return
        at.parentFile?.mkdirs()
        at.appendText(Json.write(encode(report)) + "\n")
    }

    fun all(at: File = file()): List<Snapshot> {
        if (!at.isFile) return emptyList()
        return at.readLines()
            .filter { it.isNotBlank() }
            .mapNotNull { Json.parseOrNull(it)?.let(::decode) }
            .sortedBy { it.scannedAt }
    }

    fun latest(at: File = file()): Snapshot? = all(at).maxByOrNull { it.scannedAt }

    /**
     * Findings across history that match every non-null filter, newest first,
     * each paired with the scan it came from so the caller can date it.
     */
    fun search(
        snapshots: List<Snapshot>,
        severity: String? = null,
        ruleId: String? = null,
        category: String? = null,
        sinceEpochMillis: Long? = null
    ): List<Pair<Snapshot, SnapFinding>> =
        snapshots
            .sortedByDescending { it.scannedAt }
            .filter { sinceEpochMillis == null || it.scannedAt >= sinceEpochMillis }
            .flatMap { snap -> snap.findings.map { snap to it } }
            .filter { (_, f) ->
                (severity == null || f.severity.equals(severity, ignoreCase = true)) &&
                    (ruleId == null || f.ruleId.equals(ruleId, ignoreCase = true)) &&
                    (category == null || f.category.equals(category, ignoreCase = true))
            }

    /** What is different between the two most recent scans, keyed by finding. */
    fun changesBetween(previous: Snapshot?, latest: Snapshot?): Change {
        if (latest == null) return Change(emptyList(), emptyList(), emptyList())
        val now = latest.findings.associateBy { it.key }
        val then = (previous?.findings ?: emptyList()).associateBy { it.key }
        return Change(
            resolved = then.filterKeys { it !in now }.values.toList(),
            appeared = now.filterKeys { it !in then }.values.toList(),
            unchanged = now.filterKeys { it in then }.values.toList()
        )
    }

    // ------------------------------------------------------------- rendering
    // Text, not JSON: every MCP tool here returns a human-and-model-readable
    // block, exactly as `blanktick_scan` does, so no numeric-rendering protocol
    // trap (a whole number as `1.0`) can arise. `now` is a parameter so the
    // staleness line is testable.

    fun renderHistory(snapshots: List<Snapshot>, now: Long = System.currentTimeMillis()): String {
        if (snapshots.isEmpty()) return NO_HISTORY
        return buildString {
            appendLine("BLANKTICK SCAN HISTORY  (${snapshots.size} recorded)")
            appendLine("=".repeat(60))
            appendLine("This is a stored record, not a live reading. Each line is the state at")
            appendLine("the moment that scan ran; the machine may have changed since.")
            appendLine()
            snapshots.sortedByDescending { it.scannedAt }.forEach { s ->
                appendLine(
                    "${asOf(s.scannedAt, now)}  score ${s.score}/100 ${s.grade}  " +
                        "${s.findings.count { it.severity != "INFO" }} finding(s), " +
                        "${s.checksRun} run / ${s.checksSkipped} not checkable"
                )
            }
        }
    }

    fun renderSearch(
        matches: List<Pair<Snapshot, SnapFinding>>,
        now: Long = System.currentTimeMillis()
    ): String {
        if (matches.isEmpty()) return "No stored finding matches that. (This searches recorded scans, not the live machine.)"
        return buildString {
            appendLine("MATCHES IN STORED SCANS: ${matches.size}")
            appendLine("=".repeat(60))
            matches.forEach { (snap, f) ->
                appendLine("[${f.severity}] ${f.ruleId}${if (f.subjectId.isEmpty()) "" else " (${f.subjectId})"}  -${f.deduction}")
                appendLine("   ${f.title}")
                appendLine("   seen in scan ${asOf(snap.scannedAt, now)}")
            }
        }
    }

    fun renderChanges(previous: Snapshot?, latest: Snapshot?, now: Long = System.currentTimeMillis()): String {
        if (latest == null) return NO_HISTORY
        val c = changesBetween(previous, latest)
        return buildString {
            appendLine("CHANGE SINCE THE PREVIOUS SCAN")
            appendLine("=".repeat(60))
            if (previous == null) {
                appendLine("Only one scan is on record (${asOf(latest.scannedAt, now)}), so there is")
                appendLine("nothing to compare it against yet.")
                return@buildString
            }
            appendLine("from ${asOf(previous.scannedAt, now)}  (score ${previous.score})")
            appendLine("to   ${asOf(latest.scannedAt, now)}  (score ${latest.score})")
            appendLine()
            appendLine("RESOLVED (${c.resolved.size}) — present before, gone now:")
            if (c.resolved.isEmpty()) appendLine("   none")
            else c.resolved.forEach { appendLine("   [${it.severity}] ${it.ruleId}  ${it.title}") }
            appendLine()
            appendLine("NEW (${c.appeared.size}) — not present before:")
            if (c.appeared.isEmpty()) appendLine("   none")
            else c.appeared.forEach { appendLine("   [${it.severity}] ${it.ruleId}  ${it.title}") }
            appendLine()
            appendLine("A resolved finding means it was not found this time. It is not proof the")
            appendLine("underlying thing was fixed rather than simply not observed on this run.")
        }
    }

    private fun asOf(epochMillis: Long, now: Long): String {
        val ageMin = (now - epochMillis).coerceAtLeast(0) / 60_000
        val age = when {
            ageMin < 1 -> "just now"
            ageMin < 60 -> "$ageMin min ago"
            ageMin < 1_440 -> "${ageMin / 60} h ago"
            else -> "${ageMin / 1_440} d ago"
        }
        return "${Instant.ofEpochMilli(epochMillis)} ($age)"
    }

    private const val NO_HISTORY =
        "No scan history is recorded. It is off by default; turn it on with " +
            "keepHistory=true in settings.conf, then run a scan. Until then there is " +
            "nothing stored to search."

    // -------------------------------------------------------- serialisation

    private fun encode(report: ScanReport): JsonValue {
        val r = report.result
        val fields = mutableListOf(
            // Epoch as a string on purpose: the hand-rolled Json holds numbers as
            // Double, and a millisecond epoch neither fits an Int nor should round-trip
            // through floating point.
            "scannedAt" to Json.str(r.scannedAt.toString()),
            "platform" to Json.str(r.platform.name),
            "score" to Json.num(r.score),
            "grade" to Json.str(r.grade.name),
            "checksRun" to Json.num(r.checksRun),
            "checksPassed" to Json.num(r.checksPassed),
            "checksSkipped" to Json.num(r.checksSkipped),
            "findings" to Json.arr(
                r.findings.map { sf ->
                    // Outcomes only. detail / remediation / evidence are deliberately absent.
                    Json.obj(
                        "ruleId" to Json.str(sf.finding.ruleId),
                        "subjectId" to Json.str(sf.finding.subjectId),
                        "severity" to Json.str(sf.finding.severity.name),
                        "category" to Json.str(sf.finding.category.name),
                        "title" to Json.str(sf.finding.title),
                        "deduction" to Json.num(sf.deduction)
                    )
                }
            )
        )
        // Optional fields are omitted rather than written null: the hand-rolled
        // Json has no null builder, and absent reads back as null in decode().
        r.intelBundleDate?.let { fields.add("intelBundleDate" to Json.str(it)) }
        r.intelStalenessDays?.let { fields.add("intelStalenessDays" to Json.num(it)) }
        return Json.obj(*fields.toTypedArray())
    }

    private fun decode(j: JsonValue): Snapshot? {
        val scannedAt = j["scannedAt"]?.asString?.toLongOrNull() ?: return null
        return Snapshot(
            scannedAt = scannedAt,
            platform = j["platform"]?.asString ?: "UNKNOWN",
            score = j["score"]?.asInt ?: 0,
            grade = j["grade"]?.asString ?: "UNKNOWN",
            checksRun = j["checksRun"]?.asInt ?: 0,
            checksPassed = j["checksPassed"]?.asInt ?: 0,
            checksSkipped = j["checksSkipped"]?.asInt ?: 0,
            intelBundleDate = j["intelBundleDate"]?.asString,
            intelStalenessDays = j["intelStalenessDays"]?.asInt,
            findings = j["findings"]?.asArray?.mapNotNull { f ->
                val id = f["ruleId"]?.asString ?: return@mapNotNull null
                SnapFinding(
                    ruleId = id,
                    subjectId = f["subjectId"]?.asString ?: "",
                    severity = f["severity"]?.asString ?: "INFO",
                    category = f["category"]?.asString ?: "",
                    title = f["title"]?.asString ?: "",
                    deduction = f["deduction"]?.asInt ?: 0
                )
            } ?: emptyList()
        )
    }
}

/** One recorded scan, reduced to what is safe to keep. */
data class Snapshot(
    val scannedAt: Long,
    val platform: String,
    val score: Int,
    val grade: String,
    val checksRun: Int,
    val checksPassed: Int,
    val checksSkipped: Int,
    val intelBundleDate: String?,
    val intelStalenessDays: Int?,
    val findings: List<SnapFinding>
)

/** A finding as stored: outcome only, no raw specifics. */
data class SnapFinding(
    val ruleId: String,
    val subjectId: String,
    val severity: String,
    val category: String,
    val title: String,
    val deduction: Int
) {
    /** Identity across scans; matches core `Finding.key`. */
    val key: String get() = if (subjectId.isEmpty()) ruleId else "$ruleId#$subjectId"
}

/** The diff between two scans. */
data class Change(
    val resolved: List<SnapFinding>,
    val appeared: List<SnapFinding>,
    val unchanged: List<SnapFinding>
)
