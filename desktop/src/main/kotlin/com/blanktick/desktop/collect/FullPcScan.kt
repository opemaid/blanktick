package com.blanktick.desktop.collect

import java.util.concurrent.TimeUnit

/**
 * Every file on every local drive, read by the scanner already on this PC.
 *
 * ## Why this exists
 *
 * The ordinary scan asks Defender about a short list of files — what starts
 * with Windows and what is running from a user folder — because it has to
 * finish in about a hundred seconds. That is the right list for a check-up and
 * the wrong one for the sentence "Blanktick scans your whole PC". This is the
 * pass that makes the sentence true: each fixed and removable drive, from its
 * root, every folder and every file, handed to Microsoft Defender's engine.
 *
 * ## Why Defender and not our own engine
 *
 * An offline app cannot keep a signature database current, and the bundled
 * malware-hash list is not one. Defender's engine is already on the machine,
 * already updated by Windows, and runs as SYSTEM, so it can read files the
 * logged-in user cannot. Asking it is the honest way to look at every file;
 * pretending a hash list does the same would not be.
 *
 * ## It reports, it does not act
 *
 * `-DisableRemediation` on every call, the same as the quick scan: Defender
 * names what it found and leaves it where it is. Nothing is quarantined or
 * deleted by this pass. The user reads the list and decides.
 *
 * ## The exit code lies, again
 *
 * Measured on this machine: a clean folder exits 0; a detection exits 2; a
 * path that cannot be scanned ALSO exits 2, with `CmdTool: Failed with hr =
 * 0x…`. So 2 is read as "threats" only when no failure HRESULT is present —
 * otherwise the drive is reported as not scanned, never as clean and never as
 * infected.
 */
object FullPcScan {

    enum class DriveKind { FIXED, REMOVABLE }

    data class Drive(val root: String, val kind: DriveKind, val label: String? = null)

    data class Detection(val threat: String, val resources: List<String>)

    sealed interface DriveOutcome {
        data object Clean : DriveOutcome

        /**
         * Defender said it found something. [detections] may be empty when the
         * names could not be read from its output; the count still stands.
         */
        data class Threats(val detections: List<Detection>) : DriveOutcome

        /** Not looked at, or the scanner failed. Never folded into Clean. */
        data class NotScanned(val reason: String) : DriveOutcome
    }

    /** What the machine offers before anything is scanned. */
    data class Plan(val scannerPath: String?, val defenderEnabled: Boolean?, val drives: List<Drive>?) {
        val canScan: Boolean get() = scannerPath != null && defenderEnabled == true && !drives.isNullOrEmpty()
    }

    /** Defender's scanner, only from its admin-owned directory. */
    fun scannerPath(): String? =
        System.getenv("ProgramFiles")?.let { Shell.resolve("$it\\Windows Defender\\MpCmdRun.exe") }

    /**
     * Drive types 3 (local disk) and 2 (removable). Network shares and optical
     * drives are left out: a share is someone else's computer, and a disc
     * cannot carry anything that was not already on it when it was burned.
     */
    fun plan(): Plan {
        val kv = Shell.powershellKeyValues(
            """
            try { "defender.enabled=" + [bool](Get-MpComputerStatus -ErrorAction Stop).AntivirusEnabled } catch { }
            try {
              Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
                Where-Object { ${'$'}_.DriveType -eq 3 -or ${'$'}_.DriveType -eq 2 } |
                ForEach-Object { "drive=" + ${'$'}_.DeviceID + "`t" + ${'$'}_.DriveType + "`t" + ${'$'}_.VolumeName }
            } catch { }
            """.trimIndent(),
            timeoutSeconds = 60
        )
        return Plan(
            scannerPath = scannerPath(),
            defenderEnabled = Shell.parseBoolean(kv["defender.enabled"]?.firstOrNull()),
            drives = kv["drive"]?.mapNotNull(::parseDrive)
        )
    }

    internal fun parseDrive(line: String): Drive? {
        val parts = line.split('\t')
        val id = parts.getOrNull(0)?.trim()?.takeIf { Regex("^[A-Za-z]:$").matches(it) } ?: return null
        val kind = when (parts.getOrNull(1)?.trim()) {
            "3" -> DriveKind.FIXED
            "2" -> DriveKind.REMOVABLE
            else -> return null
        }
        return Drive("$id\\", kind, parts.getOrNull(2)?.trim()?.ifEmpty { null })
    }

    /** A running scan of one drive, so the caller can stop it. */
    class Handle internal constructor(private val process: Process) {
        fun cancel() {
            process.destroyForcibly()
        }
    }

    /**
     * Scans one drive and blocks until Defender is done or [onStart]'s handle
     * is cancelled. A whole system drive can take an hour or more; there is
     * deliberately no timeout, because a timed-out drive would be a drive the
     * slogan claims was scanned and was not.
     */
    fun scanDrive(scanner: String, drive: Drive, onStart: (Handle) -> Unit = {}): DriveOutcome {
        val process = try {
            ProcessBuilder(scanner, "-Scan", "-ScanType", "3", "-File", drive.root, "-DisableRemediation")
                .redirectErrorStream(true)
                .start()
        } catch (e: Exception) {
            return DriveOutcome.NotScanned("Defender's scanner could not be started (${e.message ?: "unknown error"}).")
        }
        process.outputStream.close()
        onStart(Handle(process))
        // Read on this thread: redirectErrorStream merges both pipes, so one
        // reader drains everything and a full pipe can never stall the scan.
        val output = runCatching { process.inputStream.bufferedReader().readText() }.getOrDefault("")
        process.waitFor(10, TimeUnit.SECONDS)
        if (process.isAlive) process.destroyForcibly()
        val code = runCatching { process.exitValue() }.getOrNull()
            ?: return DriveOutcome.NotScanned("The scan was stopped before it finished.")
        return interpret(code, output)
    }

    private val FAILURE_HR = Regex("""hr\s*=\s*0x[0-9a-fA-F]+""")

    /** Pure, so the verdict rules are tested without a scanner. */
    internal fun interpret(exitCode: Int, output: String): DriveOutcome = when {
        FAILURE_HR.containsMatchIn(output) ->
            DriveOutcome.NotScanned("Defender could not scan this drive (${FAILURE_HR.find(output)!!.value}).")
        exitCode == 0 -> DriveOutcome.Clean
        exitCode == 2 -> DriveOutcome.Threats(parseDetections(output))
        // Killed by cancel shows up here as 1 or a large negative on Windows.
        else -> DriveOutcome.NotScanned("The scan ended without a result (exit code $exitCode).")
    }

    /**
     * Reads Defender's threat list:
     *
     * ```
     * Threat                  : Virus:DOS/EICAR_Test_File
     * Resources               : 1 total
     *     file                : C:\eicar\eicar.com
     * ```
     *
     * The labels are English. On another display language nothing here
     * matches, the list comes back empty, and the screen says threats were
     * found without naming them — the count is from the exit code, which is
     * not translated.
     */
    internal fun parseDetections(output: String): List<Detection> {
        val found = mutableListOf<Detection>()
        var threat: String? = null
        val resources = mutableListOf<String>()
        fun flush() {
            threat?.let { found += Detection(it, resources.toList()) }
            threat = null
            resources.clear()
        }
        output.lineSequence().forEach { raw ->
            val line = raw.trimEnd()
            val t = Regex("""^\s*Threat\s*:\s*(.+)$""").find(line)
            if (t != null) {
                flush()
                threat = t.groupValues[1].trim()
                return@forEach
            }
            if (threat == null) return@forEach
            if (Regex("""^\s*Resources\s*:""").containsMatchIn(line)) return@forEach
            Regex("""^\s{2,}(\w+)\s*:\s*(.+)$""").find(line)?.let {
                resources += it.groupValues[2].trim()
            }
        }
        flush()
        return found
    }
}
