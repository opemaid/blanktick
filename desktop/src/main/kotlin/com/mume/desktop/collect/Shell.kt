package com.mume.desktop.collect

import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Runs a local command and returns what it printed.
 *
 * ## Why a security app is allowed to do this
 *
 * Every desktop fact Mume reports — the firewall state, the update history, the
 * list of local administrators — is held by the operating system and exposed
 * through a command-line tool. There is no unprivileged API for most of them.
 * So the collectors shell out, and this class is the single, auditable place
 * where that happens.
 *
 * ## The constraints that make it safe to have here
 *
 * 1. **No shell.** Commands are passed as an argument vector straight to
 *    [ProcessBuilder]. There is no `cmd /c`, no `sh -c`, and therefore nothing
 *    for a metacharacter in a machine name or a user name to escape into.
 * 2. **No user input reaches an argument.** Every command in the desktop
 *    collectors is a compile-time constant. Nothing typed into the app is ever
 *    interpolated into one.
 * 3. **Read-only by construction.** Every command used is an interrogation —
 *    `netsh advfirewall show`, `sfc /verifyonly`-class queries, `systemsetup
 *    -get…`. Mume never changes a setting; it tells the user what to change and
 *    lets them do it, because a security tool that silently reconfigures a
 *    machine is a security tool nobody can audit.
 * 4. **Bounded.** Every call has a timeout and the process is destroyed if it
 *    overruns, so one wedged system utility cannot hang the scan.
 * 5. **Failure is `null`, never a default.** A command that is missing, times
 *    out or exits non-zero yields `null`, which propagates up as "not
 *    checkable" rather than as a reassuring answer.
 */
internal object Shell {

    /** Default ceiling per command. Generous: WMI and `softwareupdate` are slow. */
    private const val DEFAULT_TIMEOUT_SECONDS = 20L

    /** Guards against a runaway tool filling the heap with output. */
    private const val MAX_OUTPUT_CHARS = 1 shl 20   // 1 MiB

    data class Result(val exitCode: Int, val stdout: String, val stderr: String) {
        val ok: Boolean get() = exitCode == 0
    }

    /**
     * @return the command's output, or `null` if it could not be run to
     *   completion. Callers must treat `null` as "unknown".
     */
    fun run(
        vararg command: String,
        timeoutSeconds: Long = DEFAULT_TIMEOUT_SECONDS,
        workingDir: File? = null
    ): Result? = try {
        val process = ProcessBuilder(command.toList())
            .directory(workingDir)
            .redirectErrorStream(false)
            .start()

        // stdin is closed immediately: nothing here is interactive, and a tool
        // that decides to prompt should hit EOF and exit rather than block
        // until the timeout.
        process.outputStream.close()

        val out = process.inputStream.bufferedReader().use { it.readText().take(MAX_OUTPUT_CHARS) }
        val err = process.errorStream.bufferedReader().use { it.readText().take(MAX_OUTPUT_CHARS) }

        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            null
        } else {
            Result(process.exitValue(), out, err)
        }
    } catch (_: Exception) {
        // Missing binary, denied by policy, sandboxed: all mean "cannot tell".
        null
    }

    /** Convenience: stdout of a successful command, else `null`. */
    fun stdout(vararg command: String, timeoutSeconds: Long = DEFAULT_TIMEOUT_SECONDS): String? =
        run(*command, timeoutSeconds = timeoutSeconds)?.takeIf { it.ok }?.stdout

    /**
     * Runs a PowerShell script.
     *
     * ## Why a temporary file and not -Command or -EncodedCommand
     *
     * Both alternatives were tried on a real machine, and both failed:
     *
     * - **`-Command`**: on Windows, [ProcessBuilder] re-quotes arguments on
     *   their way to `CreateProcess`, so any script containing quotes, braces
     *   or `${'$'}_` arrived subtly different from what was written. The symptom was
     *   not an error but silence: queries returned nothing, which the null
     *   contract faithfully reported as "not checkable" — so the app was
     *   scrupulously honest about facts it had failed to collect for no reason.
     *
     * - **`-EncodedCommand`**: fixes the quoting completely, and gets the whole
     *   application **killed by Microsoft Defender**. Spawning
     *   `powershell.exe -EncodedCommand` is behaviour signature
     *   `Behavior:Win32/PShellEnc.A`; Defender terminates the parent process,
     *   silently, with exit code 0. Which is entirely fair of it. Base64ed
     *   PowerShell issued by another program is a malware technique, and a
     *   security product has no business using one.
     *
     * So the script is written to a file and run with `-File`. There is no
     * quoting layer, so the script that runs is byte-for-byte the one that was
     * written, and the pattern is an ordinary one that endpoint protection has
     * no reason to object to.
     *
     * It is also the most auditable option of the three: while a scan is
     * running, the exact script is a readable file on disk.
     *
     * ## Why -NoProfile
     *
     * More than speed: a user profile can redefine cmdlets, and a scan whose
     * answers depend on someone's `Microsoft.PowerShell_profile.ps1` is not
     * measuring the machine.
     */
    fun powershell(script: String, timeoutSeconds: Long = DEFAULT_TIMEOUT_SECONDS): String? {
        // Written into a fresh randomly-named DIRECTORY, not straight into the
        // shared temp folder.
        //
        // The window between creating the script and executing it is a classic
        // local TOCTOU: another process running as the same user can swap the
        // contents, and if Mume were launched elevated that becomes a privilege
        // escalation -- unprivileged code choosing what an elevated PowerShell
        // runs. Mume never needs elevation and `WindowsProbeTest` asserts no
        // command in the probe requires it, but "does not need to" is not the
        // same as "cannot be", and right-click > Run as administrator exists.
        //
        // A per-run directory does not close the race, and pretending otherwise
        // would be worse than leaving it: an attacker who can enumerate the temp
        // tree fast enough still wins. What it does is remove the predictable
        // path, so the attack needs a race rather than a guess. The real
        // mitigation is not running this elevated, which is documented in the
        // About screen.
        val dir = try {
            java.nio.file.Files.createTempDirectory("mume-").toFile().apply { deleteOnExit() }
        } catch (_: Exception) {
            return null
        }

        val file = try {
            File.createTempFile("probe-", ".ps1", dir).apply { deleteOnExit() }
        } catch (_: Exception) {
            dir.delete()
            return null
        }

        return try {
            // Progress records are written as CLIXML on some hosts and land in
            // the middle of the output. Silenced in-band so no caller has to
            // strip it.
            file.writeText("\$ProgressPreference = 'SilentlyContinue'\r\n" + script, Charsets.UTF_8)
            stdout(
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-File", file.absolutePath,
                timeoutSeconds = timeoutSeconds
            )?.trim()
        } catch (_: Exception) {
            null
        } finally {
            // Deleted immediately rather than left to deleteOnExit: a script
            // that reads security settings should not linger in the temp
            // directory after the scan that needed it.
            runCatching { file.delete() }
            runCatching { dir.delete() }
        }
    }

    /**
     * Runs one script that emits `key=value` lines, and returns them grouped.
     *
     * ## Why one script instead of twenty
     *
     * Each `powershell.exe` launch costs roughly a second of process start and
     * module loading. The Windows collector asks about twenty-five things; one
     * call at a time, that is a scan the user watches for several minutes,
     * which in practice means a scan they do not run. Batching makes it one
     * process and a few seconds.
     *
     * It is also far easier to audit: the whole script can be printed with
     * `Mume --script`, pasted into a terminal, and its output compared against
     * what the app displayed.
     *
     * A key may appear more than once (autorun entries, certificates, ports),
     * so values are lists. An absent key means the query produced nothing,
     * which callers must treat as unknown — never as a negative answer.
     */
    fun powershellKeyValues(
        script: String,
        timeoutSeconds: Long = 90
    ): Map<String, List<String>> {
        val raw = powershell(script, timeoutSeconds) ?: return emptyMap()
        val out = mutableMapOf<String, MutableList<String>>()

        raw.lineSequence().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#<")) return@forEach
            val idx = trimmed.indexOf('=')
            if (idx <= 0) return@forEach
            val value = trimmed.substring(idx + 1).trim()
            if (value.isEmpty()) return@forEach
            out.getOrPut(trimmed.substring(0, idx).trim()) { mutableListOf() } += value
        }
        return out
    }

    /** Reads a small local file, or `null`. Never throws. */
    fun readFile(path: String): String? = try {
        File(path).takeIf { it.isFile && it.canRead() }?.readText()?.take(MAX_OUTPUT_CHARS)
    } catch (_: Exception) {
        null
    }

    /**
     * Parses the loose booleans system tools emit.
     *
     * Deliberately strict: anything unrecognised is `null`, not `false`. `netsh`
     * localises its output, so on a non-English Windows this returns `null` and
     * the rule reports *not checkable* — which is correct. Guessing from a
     * string we do not recognise is how a French machine would be told its
     * firewall is off.
     */
    fun parseBoolean(value: String?): Boolean? = when (value?.trim()?.lowercase()) {
        "true", "1", "on", "yes", "enabled", "enable", "active" -> true
        "false", "0", "off", "no", "disabled", "disable", "inactive" -> false
        else -> null
    }
}
