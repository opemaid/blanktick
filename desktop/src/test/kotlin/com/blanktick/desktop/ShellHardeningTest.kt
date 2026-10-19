package com.blanktick.desktop

import com.blanktick.desktop.collect.Shell
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The two ways the command layer could be turned against the app.
 *
 * Both were found by attacking the shipped build rather than by reading it, and
 * both were demonstrated on a real machine before being fixed.
 */
class ShellHardeningTest {

    private val onWindows = System.getProperty("os.name").orEmpty().lowercase().contains("win")

    // -------------------------------------------------------- binary hijack

    /**
     * The finding: `ProcessBuilder("powershell.exe")` names a **search**, not a
     * file, and the per-user half of `%PATH%` lives in `HKCU\Environment` —
     * writable by any process running as the user, no elevation, no prompt.
     *
     * Demonstrated: with a user-writable directory prepended to `PATH`, the
     * identical invocation ran a planted binary instead of PowerShell. Since
     * the probe's entire output is `key=value` text that Blanktick parses and
     * renders, a stand-in returns whatever it likes and the app displays a
     * fully green report. The scanner becomes the alibi.
     *
     * The fix is that a tool must resolve inside a directory only an
     * administrator can write.
     */
    @Test
    fun `a tool is resolved from a system directory, not from PATH`() {
        if (!onWindows) return
        val resolved = Shell.resolve("powershell.exe")
        assertNotNull(resolved, "powershell.exe must resolve on Windows")

        val root = System.getenv("SystemRoot") ?: "C:\\Windows"
        assertTrue(
            resolved.startsWith(root, ignoreCase = true),
            "resolved outside the Windows directory, so PATH still decides: $resolved"
        )
        assertTrue(File(resolved).isFile, "resolution must name a real file: $resolved")
    }

    /**
     * A planted binary must not be reachable however the name is spelled.
     *
     * The point of the allow-list is that it is an allow-list: a name that is
     * not in a system directory does not run at all, and the caller gets
     * `null`, which the null contract already renders as *not checkable*.
     */
    @Test
    fun `a binary outside the trusted directories never resolves`() {
        val dir = java.nio.file.Files.createTempDirectory("blanktick-hijack-test-").toFile()
        try {
            val planted = File(dir, if (onWindows) "blanktick-fake-tool.exe" else "blanktick-fake-tool")
            planted.writeText("not a real tool")
            planted.setExecutable(true)

            assertNull(
                Shell.resolve(planted.name),
                "a tool in a user-writable directory must not resolve"
            )
            assertNull(
                Shell.resolve(planted.absolutePath),
                "naming it absolutely must not launder it into the trusted set"
            )
            assertNull(
                Shell.run(planted.absolutePath),
                "and it must not be executed"
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    /**
     * The POSIX half of the guard, which is the half that was never run.
     *
     * The allow-list encodes a *belief* about who owns a directory, and the
     * belief is not reliably true: `/usr/local/bin` is root-owned on a stock
     * Linux and **owned by the logged-in user on an Intel Mac with Homebrew**.
     * On that machine a "trusted" directory is writable by exactly the account
     * an attacker already has.
     *
     * So ownership is checked against the filesystem rather than inferred from
     * the path. This runs for real on Linux and macOS and is skipped on
     * Windows, which has no POSIX view to read.
     */
    @Test
    fun `on POSIX a tool must be root-owned all the way up`() {
        if (onWindows) return

        val resolved = Shell.resolve("id")
        assertNotNull(resolved, "id(1) should exist on any POSIX system")

        // Walk the same chain the guard walks and assert the property it relies
        // on, so a failure here names the directory rather than just the tool.
        var p: java.nio.file.Path? = java.nio.file.Paths.get(resolved).toRealPath()
        while (p != null) {
            val attrs = java.nio.file.Files.readAttributes(
                p, java.nio.file.attribute.PosixFileAttributes::class.java
            )
            assertEquals("root", attrs.owner().name, "$p is not owned by root")
            assertFalse(
                java.nio.file.attribute.PosixFilePermission.GROUP_WRITE in attrs.permissions() ||
                    java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE in attrs.permissions(),
                "$p is writable by someone other than its owner"
            )
            p = p.parent
        }
    }

    /**
     * A root-owned binary in a directory anyone can write is not safe: the file
     * can be unlinked and replaced without ever being modified. The guard walks
     * upwards for that reason, and this proves the walk is load-bearing.
     */
    @Test
    fun `a tool under a world-writable directory is rejected`() {
        if (onWindows) return

        val dir = java.nio.file.Files.createTempDirectory("blanktick-perm-test-")
        try {
            java.nio.file.Files.setPosixFilePermissions(
                dir,
                java.nio.file.attribute.PosixFilePermissions.fromString("rwxrwxrwx")
            )
            val tool = File(dir.toFile(), "id")
            tool.writeText("#!/bin/sh\necho pwned\n")
            tool.setExecutable(true)

            assertNull(
                Shell.resolve(tool.absolutePath),
                "a tool in a world-writable directory resolved anyway"
            )
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    /**
     * The allow-list is built from `%SystemRoot%`, which the *parent* of this
     * process chooses. Launching Blanktick with `SystemRoot=C:ttacker` would
     * otherwise aim the whole trusted set at a directory the attacker owns —
     * the same forged-report outcome by a shorter route.
     */
    @Test
    fun `a bogus SystemRoot does not move the trusted set`() {
        if (!onWindows) return
        val resolved = Shell.resolve("powershell.exe")
        assertNotNull(resolved)
        // Whatever the environment claimed, resolution has to have landed inside
        // a directory that actually contains the Windows kernel — the one file a
        // planted "SystemRoot" would not have.
        val root = generateSequence(File(resolved).parentFile) { it.parentFile }
            .firstOrNull { File(it, "System32\\kernel32.dll").isFile }
        assertNotNull(
            root,
            "resolved to $resolved, which is not inside a real Windows directory"
        )
    }

    // ------------------------------------------------------ timeout evasion

    /**
     * The finding: the previous version read stdout to completion, then stderr,
     * and only then called `waitFor(timeout)`.
     *
     * A pipe holds tens of kilobytes. Once the child has filled the stderr
     * buffer it blocks on write, so it never finishes stdout, so the read never
     * returns, so **the line that enforces the timeout is never reached**.
     * Measured on a real machine: a command with a 20-second ceiling ran for
     * 44.2 seconds and was not going to stop on its own.
     *
     * Any noisy tool triggers it by accident; anything that wants Blanktick not to
     * produce a verdict triggers it on purpose, which is a cheap way to disable
     * a security app without touching a single security setting.
     *
     * Note what the fixed behaviour actually is: the command now **succeeds
     * quickly**. It was never slow — it was blocked, by the reader that was not
     * reading it. Draining both pipes concurrently removes the block, so the
     * same command that could not finish in 44 seconds finishes in about one.
     */
    @Test
    fun `a command that floods stderr completes instead of blocking`() {
        if (!onWindows) return

        val script = "1..40000 | ForEach-Object { [Console]::Error.WriteLine('x' * 200) }; 'done'"
        val started = System.currentTimeMillis()
        val result = Shell.run(
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script,
            timeoutSeconds = 30
        )
        val elapsed = System.currentTimeMillis() - started

        assertNotNull(result, "the command deadlocked and was killed by the timeout")
        assertTrue(result.stdout.contains("done"), "stdout was lost while draining stderr")
        assertTrue(result.stderr.length > 100_000, "stderr was not actually drained")
        assertTrue(
            elapsed < 20_000,
            "took ${elapsed}ms — the reader is still serialising the two pipes"
        )
    }

    /** And the deadline still bites when a command is genuinely slow. */
    @Test
    fun `a command that overruns is killed at the deadline`() {
        if (!onWindows) return

        val started = System.currentTimeMillis()
        val result = Shell.run(
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-Command", "Start-Sleep -Seconds 30",
            timeoutSeconds = 3
        )
        val elapsed = System.currentTimeMillis() - started

        assertNull(result, "an overrunning command must report null, never partial output")
        assertTrue(elapsed < 15_000, "the 3-second deadline took ${elapsed}ms to fire")
    }

    /**
     * ...unless the caller opts in. The probe is one batched command whose
     * output is whole `key=value` lines; on a software-heavy machine it can
     * overrun the ceiling, and dropping everything turned one slow section into
     * a blank report (seen live: 2 of 88 checks, score withheld off nothing).
     * With `allowPartialOnTimeout`, the lines read before the kill come back,
     * flagged `timedOut`.
     */
    @Test
    fun `with partial-on-timeout opted in, an overrun keeps the lines already emitted`() {
        if (!onWindows) return

        val result = Shell.run(
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-Command",
            "[Console]::Out.WriteLine('early-1'); [Console]::Out.WriteLine('early-2'); " +
                "[Console]::Out.Flush(); Start-Sleep -Seconds 30",
            // Headroom for powershell.exe cold-start on a loaded CI runner: the
            // lines are emitted instantly once it runs, but startup alone can eat
            // a 3s window and leave stdout empty. 10s still kills the 30s sleep
            // mid-run, so the "overrun -> partial facts" semantics are unchanged.
            timeoutSeconds = 10,
            allowPartialOnTimeout = true
        )

        assertNotNull(result, "opted-in partial output must not be dropped on timeout")
        assertTrue(result.timedOut, "the result must be flagged as a timeout")
        assertFalse(result.ok, "a timed-out result is never ok")
        assertTrue(
            result.stdout.contains("early-1") && result.stdout.contains("early-2"),
            "the facts emitted before the kill were lost: '${result.stdout}'"
        )
    }

    /**
     * End to end: a probe that times out still yields the facts it collected,
     * and — crucially — does NOT carry `probe.complete`, so the collection
     * reads as unfinished and the score is withheld rather than fabricated.
     */
    @Test
    fun `powershellKeyValues keeps the facts collected before a timeout`() {
        if (!onWindows) return

        val facts = Shell.powershellKeyValues(
            "[Console]::Out.WriteLine('fw.enabled=True'); " +
                "[Console]::Out.WriteLine('av.product=Defender'); " +
                "[Console]::Out.Flush(); Start-Sleep -Seconds 30",
            // 10s (not 3s): headroom for powershell.exe cold-start on a loaded
            // runner, still well under the 30s sleep so the probe is killed
            // mid-run and never reaches the completion sentinel. See the
            // sibling partial-on-timeout test for the full rationale.
            timeoutSeconds = 10
        )

        assertEquals(listOf("True"), facts["fw.enabled"], "a collected fact was dropped on timeout")
        assertEquals(listOf("Defender"), facts["av.product"], "a collected fact was dropped on timeout")
        assertFalse(
            facts.containsKey("probe.complete"),
            "a timed-out probe must not carry the completion sentinel"
        )
    }

    /** Output still has to survive the concurrent reader. */
    @Test
    fun `normal output is captured intact`() {
        if (!onWindows) return
        val out = Shell.stdout(
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-Command", "'alpha'; 'beta'",
            timeoutSeconds = 30
        )
        assertNotNull(out, "a well-behaved command must still return its output")
        assertEquals(listOf("alpha", "beta"), out.trim().lines().map { it.trim() })
    }
}
