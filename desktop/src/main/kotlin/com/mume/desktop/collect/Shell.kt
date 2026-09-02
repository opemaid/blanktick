package com.mume.desktop.collect

import java.io.File
import java.io.InputStream
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
 * 3. **The binary is named absolutely.** See [resolve]. This is the difference
 *    between reading the operating system and reading whatever an attacker put
 *    on `PATH`.
 * 4. **Read-only by construction.** Every command used is an interrogation —
 *    `netsh advfirewall show`, `sfc /verifyonly`-class queries, `systemsetup
 *    -get…`. Mume never changes a setting; it tells the user what to change and
 *    lets them do it, because a security tool that silently reconfigures a
 *    machine is a security tool nobody can audit.
 * 5. **Bounded, and bounded for real.** See [drain]: a timeout that can be
 *    evaded by a chatty subprocess is not a timeout.
 * 6. **Failure is `null`, never a default.** A command that is missing, times
 *    out or exits non-zero yields `null`, which propagates up as "not
 *    checkable" rather than as a reassuring answer.
 */
internal object Shell {

    /** Default ceiling per command. Generous: WMI and `softwareupdate` are slow. */
    private const val DEFAULT_TIMEOUT_SECONDS = 20L

    /** Guards against a runaway tool filling the heap with output. */
    private const val MAX_OUTPUT_CHARS = 1 shl 22   // 4 MiB

    /**
     * Set when a command's output hit [MAX_OUTPUT_CHARS] and was cut short.
     *
     * Truncation is not a detail. The probe emits its facts in source order, so
     * a cut-off stream silently deletes *the questions asked last* — and an
     * attacker who can inflate an earlier answer chooses which ones. One
     * installed program with a 4 MiB `DisplayName` would push every autorun
     * entry off the end of the output, and the null contract would faithfully
     * report those as "not checkable" without anyone knowing why.
     *
     * So truncation is recorded, surfaced, and treated as a degraded scan.
     */
    @Volatile
    var lastRunTruncated: Boolean = false
        private set

    data class Result(val exitCode: Int, val stdout: String, val stderr: String) {
        val ok: Boolean get() = exitCode == 0
    }

    // ------------------------------------------------------------- resolution

    /**
     * Directories a system tool is allowed to come from, in search order.
     *
     * ## The attack this closes
     *
     * `ProcessBuilder("powershell.exe", …)` does not name a file, it names a
     * *search*. Windows resolves it through `%PATH%`, and the per-user half of
     * `%PATH%` lives in `HKCU\Environment`, which **any process running as the
     * user can write with no elevation and no prompt**. Prepend a directory,
     * drop a `powershell.exe` in it, and every scan from then on reads its
     * facts from a program the attacker wrote.
     *
     * That is not tampering with one check. The probe returns `key=value` text
     * that Mume parses and displays; a hostile stand-in returns whatever it
     * likes, and the app renders a fully green 100/100 report — the security
     * scanner becomes the alibi. Verified on a real machine: with a
     * user-writable directory prepended to `PATH`, the identical invocation ran
     * the planted binary instead of PowerShell.
     *
     * The same hole existed 18 more times on macOS and Linux, where `csrutil`,
     * `fdesetup` and `spctl` are what decide the SIP, FileVault and Gatekeeper
     * verdicts, and a shell rc file is all it takes to bend `PATH`.
     *
     * Every directory below is one only an administrator can write to. If a
     * tool is not in one of them, it is not run at all and the caller gets
     * `null` — "not checkable", which is the honest answer to "is this the real
     * `csrutil`?" when we cannot tell.
     */
    private val TRUSTED_DIRS: List<String> by lazy {
        val osName = System.getProperty("os.name").orEmpty().lowercase()
        when {
            osName.contains("win") -> {
                val root = windowsRoot()
                listOfNotNull(
                    "$root\\System32",
                    "$root\\System32\\WindowsPowerShell\\v1.0",
                    "$root\\SysWOW64",
                    "$root\\SysWOW64\\WindowsPowerShell\\v1.0",
                    root,
                    // Windows Defender's command-line scanner. Checked before
                    // adding: the directory is owned by TrustedInstaller with
                    // zero write entries for anyone below administrator, and
                    // MpCmdRun.exe is signed by Microsoft Windows.
                    System.getenv("ProgramFiles")?.let { "$it\\Windows Defender" }
                )
            }
            // /usr/libexec carries several of the tools macOS keeps off PATH.
            // /usr/local/bin is deliberately absent here: on an Intel Mac with
            // Homebrew it belongs to the logged-in user, which would make it
            // precisely the writable directory this list exists to exclude.
            osName.contains("mac") || osName.contains("darwin") ->
                listOf("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec")
            // /usr/local/bin is included on Linux, where it is conventionally
            // root-owned — but the convention is not trusted. [isTamperProof]
            // checks the actual ownership at runtime and drops it if not.
            else -> listOf("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin")
        }
    }

    /**
     * `%SystemRoot%`, but only if it really is one.
     *
     * The whole allow-list is built from this string, and it comes from the
     * environment — which the parent of this process chooses. Anything able to
     * launch Mume with `SystemRoot=C:\attacker` would otherwise get the entire
     * trusted set pointed at a directory it owns, which is the same forged-report
     * outcome by a shorter route.
     *
     * Whoever can set that environment can usually do worse, so this is a cheap
     * lock rather than a deep one: the value is accepted only if it contains the
     * file every Windows install has, and falls back to the literal default
     * otherwise.
     */
    private fun windowsRoot(): String {
        val fromEnv = System.getenv("SystemRoot")?.takeIf { it.isNotBlank() }
        val looksReal = fromEnv != null &&
            runCatching { File(fromEnv, "System32\\kernel32.dll").isFile }.getOrDefault(false)
        return if (looksReal) fromEnv!! else "C:\\Windows"
    }

    /**
     * Asks the operating system whether an unprivileged process could have put
     * this file here — rather than assuming it from the path.
     *
     * ## Why the allow-list alone is not enough
     *
     * A list of directory names encodes a belief about who owns them, and the
     * belief is not always right. `/usr/local/bin` is root-owned on a stock
     * Linux and **owned by the logged-in user on an Intel Mac running
     * Homebrew** — on that machine the "trusted" directory is writable by
     * exactly the account an attacker already controls. Distributions and
     * package managers move this ground around, and a hardcoded list cannot
     * follow it.
     *
     * So on POSIX the check is made against reality: the file, and every
     * directory above it, must be owned by `root` and must not be writable by
     * group or by others. The walk goes all the way up because a root-owned
     * binary inside a user-writable directory can simply be unlinked and
     * replaced.
     *
     * On Windows there is no POSIX view to read, and the allow-list resolves
     * inside `%SystemRoot%`, whose ACLs are administrator-only by construction;
     * [windowsRoot] is what keeps that anchored.
     *
     * @return true when the path cannot have been planted without administrator
     *   rights, or when the platform gives us no way to tell (Windows).
     */
    private fun isTamperProof(file: File): Boolean {
        val path = runCatching { file.toPath().toRealPath() }.getOrNull() ?: return false
        val view = java.nio.file.Files.getFileAttributeView(
            path, java.nio.file.attribute.PosixFileAttributeView::class.java
        ) ?: return true    // not a POSIX filesystem: the allow-list is the check

        var current: java.nio.file.Path? = path
        while (current != null) {
            val ok = runCatching {
                val attrs = java.nio.file.Files.readAttributes(
                    current, java.nio.file.attribute.PosixFileAttributes::class.java
                )
                val perms = attrs.permissions()
                attrs.owner().name == "root" &&
                    java.nio.file.attribute.PosixFilePermission.GROUP_WRITE !in perms &&
                    java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE !in perms
            }.getOrDefault(false)

            if (!ok) return false
            current = current.parent
        }
        return true
    }

    /** Windows will run `foo` when handed `foo.exe`; everywhere else, extensions are literal. */
    private val EXE_SUFFIXES: List<String> by lazy {
        if (System.getProperty("os.name").orEmpty().lowercase().contains("win")) listOf("", ".exe")
        else listOf("")
    }

    private val resolutionCache = java.util.concurrent.ConcurrentHashMap<String, String>()

    /**
     * Turns a tool name into an absolute path inside [TRUSTED_DIRS].
     *
     * An absolute path handed in by a caller is accepted only if it is already
     * inside a trusted directory — that is how the probe's own script file,
     * which lives in a temp directory, is *not* mistaken for a system tool.
     *
     * @return `null` if the tool is not present in a directory only an
     *   administrator can write to. Callers treat that as "cannot tell".
     */
    fun resolve(tool: String): String? {
        resolutionCache[tool]?.let { return it }

        val candidates = if (File(tool).isAbsolute) {
            listOf(File(tool))
        } else {
            TRUSTED_DIRS.flatMap { dir -> EXE_SUFFIXES.map { File(dir, tool + it) } }
        }

        val found = candidates.firstOrNull { f ->
            runCatching { f.isFile && f.canExecute() }.getOrDefault(false) &&
                // An absolute path from a caller still has to be somewhere an
                // unprivileged process could not have planted it.
                TRUSTED_DIRS.any { d ->
                    runCatching {
                        f.canonicalPath.startsWith(File(d).canonicalPath + File.separator, ignoreCase = true)
                    }.getOrDefault(false)
                } &&
                // And the directory has to actually be what the list assumes.
                isTamperProof(f)
        } ?: return null

        val path = runCatching { found.canonicalPath }.getOrDefault(found.absolutePath)
        resolutionCache[tool] = path
        return path
    }

    // ------------------------------------------------------------- execution

    /**
     * Reads a stream to exhaustion on its own thread.
     *
     * ## Why this is not just tidiness
     *
     * The previous version read stdout to completion, then stderr, and only
     * then called `waitFor(timeout)`. A pipe holds about 4–64 KiB; once the
     * child has filled the stderr buffer it blocks on write, so it never
     * finishes stdout, so the read never returns, so **the line that enforces
     * the timeout is never reached**. Measured: a command with a 20-second
     * ceiling ran for 44 seconds and would not have stopped on its own. With
     * more output it does not return at all, and the whole scan wedges.
     *
     * Any probed tool that gets noisy on stderr does this by accident. Anything
     * that wants Mume not to finish does it on purpose, which is a cheap way to
     * make a security app produce no verdict at all.
     */
    private fun drain(stream: InputStream): Pair<Thread, StringBuilder> {
        val sink = StringBuilder()
        val thread = Thread {
            runCatching {
                stream.bufferedReader().use { reader ->
                    val buf = CharArray(8192)
                    while (true) {
                        val n = reader.read(buf)
                        if (n < 0) break
                        if (sink.length < MAX_OUTPUT_CHARS) {
                            sink.append(buf, 0, minOf(n, MAX_OUTPUT_CHARS - sink.length))
                        }
                        // Past the cap we keep reading and discarding: stopping
                        // here would block the child on a full pipe, which is
                        // the very deadlock this method exists to avoid.
                    }
                }
            }
        }
        thread.isDaemon = true
        thread.start()
        return thread to sink
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
        // Resolution failure is not an error to report: a machine without
        // `ufw` is a normal machine. It is "cannot tell", same as any other
        // unanswerable question.
        val exe = resolve(command.first())
        if (exe == null) null else {
            val builder = ProcessBuilder(listOf(exe) + command.drop(1))
                .directory(workingDir)
                .redirectErrorStream(false)

            // PSModulePath is inherited, and inheriting the wrong one silently
            // removes cmdlets.
            //
            // Launch Mume from a PowerShell 7 terminal, an IDE or a build tool
            // and the environment carries PowerShell 7's module directories.
            // The Windows PowerShell 5.1 child we spawn then looks for its
            // modules in the wrong place, finds three, and `Get-FileHash`
            // ceases to exist -- in a shell that works perfectly when a person
            // starts it. Measured here, not theorised: the malware hash check
            // reported "not performed" for every file, correctly by the null
            // contract and for a reason that had nothing to do with the machine
            // being scanned.
            //
            // Removing the variable makes PowerShell compute its own default,
            // which is the behaviour of a shell nobody has interfered with.
            // That is what a probe should measure against: a scan must not
            // depend on what launched the app.
            builder.environment().remove("PSModulePath")

            val process = builder.start()

            // stdin is closed immediately: nothing here is interactive, and a
            // tool that decides to prompt should hit EOF and exit rather than
            // block until the timeout.
            process.outputStream.close()

            val (outThread, outBuf) = drain(process.inputStream)
            val (errThread, errBuf) = drain(process.errorStream)

            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                process.waitFor(2, TimeUnit.SECONDS)
                null
            } else {
                // The child is gone; the readers see EOF almost immediately.
                // Bounded anyway, because "almost" is not a guarantee.
                outThread.join(2_000)
                errThread.join(2_000)
                if (outBuf.length >= MAX_OUTPUT_CHARS) lastRunTruncated = true
                Result(process.exitValue(), outBuf.toString(), errBuf.toString())
            }
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
     * module loading. The Windows collector asks about thirty-odd things; one
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
        // Four minutes, not ninety seconds, and the number is measured rather
        // than guessed.
        //
        // The probe grew to about 133 seconds of real work on the development
        // machine -- most of it Get-AuthenticodeSignature, which costs roughly
        // 410 milliseconds a file and is asked about sixty-six of them. At the
        // old ceiling the run was killed, powershellKeyValues returned an empty
        // map, every check reported not-checkable, and the app printed a
        // confident 100/100 off two checks. A ceiling that truncates the entire
        // collection is far worse than a scan that takes longer, and the score
        // is now suppressed when the collection does not finish -- but the
        // right fix is for it to finish.
        timeoutSeconds: Long = 240
    ): Map<String, List<String>> {
        lastRunTruncated = false
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
