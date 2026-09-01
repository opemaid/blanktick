package com.mume.desktop

import com.mume.desktop.collect.Shell
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
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
     * the probe's entire output is `key=value` text that Mume parses and
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
        val dir = java.nio.file.Files.createTempDirectory("mume-hijack-test-").toFile()
        try {
            val planted = File(dir, if (onWindows) "mume-fake-tool.exe" else "mume-fake-tool")
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
     * Any noisy tool triggers it by accident; anything that wants Mume not to
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
