package com.mume.desktop

import com.mume.desktop.collect.WindowsProbe
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Field injection into the probe's output protocol.
 *
 * ## The bug this pins
 *
 * The probe emits `key=value` lines and multi-field rows are TAB separated. The
 * leading field of most of those rows is a string **an attacker chooses**: a
 * program's `DisplayName`, a Run-key value name, a certificate `Subject`, a
 * process name. The sanitiser originally stripped `\r\n` but not `\t`.
 *
 * So a program installed as `Evil<TAB>1.0<TAB>Microsoft Corporation` parsed as
 * `name=Evil, version=1.0, publisher=Microsoft Corporation` — a **forged
 * publisher**, which is the exact field `DSK-SW-002` uses to decide whether
 * something unattributed installed itself where it needed no permission. The
 * same trick on an autorun name forges the Authenticode status and defeats
 * `DSK-AUTO-001`.
 *
 * Neither is remote. Both are a security control disabled by its own input, in a
 * product whose only job is noticing that sort of thing.
 *
 * Found by a pen-testing pass (`master-ethical-hacker`, untrusted-input track).
 * The four-lens design review that preceded it did not look for this and had no
 * reason to — it is not a design question.
 */
class ProbeInjectionTest {

    private val script = WindowsProbe.SCRIPT

    /** As they appear in the PowerShell source: a backslash followed by a letter. */
    private val CR = "\\" + "r"
    private val LF = "\\" + "n"
    private val TAB = "\\" + "t"

    private val emitBody: String
        get() = script.lines()
            .dropWhile { !it.contains("function Emit(") }
            .takeWhile { !it.trimStart().startsWith("function Reg(") }
            .joinToString(System.lineSeparator())

    /** `San` sanitises one field, so it must strip every structural character. */
    @Test
    fun `San strips tab, CR and LF`() {
        val san = script.lines().firstOrNull { it.contains("function San(") }
        assertTrue(san != null, "the per-field sanitiser San() is missing entirely")
        listOf(CR, LF, TAB).forEach {
            assertTrue(san!!.contains(it), "San must strip '$it': $san")
        }
    }

    /**
     * The regression guard, and the more interesting half of this file.
     *
     * The first attempt at the fix stripped tabs inside `Emit`. `Emit` receives a
     * row **after** assembly, so it ate the separators along with the payload:
     * autorun entries silently dropped from 9 to 0 and user-writable programs
     * from 11 to 0, with no error raised anywhere — the app simply reported less
     * and looked fine doing it.
     *
     * Sanitising a composite value is not the same operation as sanitising a
     * field. This pins the difference so the "obvious" fix cannot come back.
     */
    @Test
    fun `Emit must not strip tabs, or it eats the separators`() {
        assertTrue(emitBody.contains(CR) && emitBody.contains(LF), "Emit must strip CR and LF")
        assertTrue(
            !emitBody.contains(TAB),
            "Emit must NOT strip tabs. It sees the assembled row, so stripping " +
                "them deletes the field separators and silently empties every " +
                "multi-field result:" + System.lineSeparator() + emitBody
        )
    }

    /**
     * Every multi-field row must pass at least one field through `San`.
     *
     * Deliberately not "the first field": in `port` and the Startup-folder
     * `autorun` row the leading value is an OS-supplied address or path and the
     * attacker-controlled one comes later. What must never happen is a
     * tab-separated row with no sanitisation at all.
     */
    @Test
    fun `every multi-field row sanitises`() {
        val rows = script.lines()
            .map { it.trim() }
            .filter { it.startsWith("Emit '") && it.contains("`t") }

        assertTrue(rows.size >= 6, "expected at least the six known rows, found ${rows.size}")

        val unsanitised = rows.filterNot { it.contains("(San ") }
        assertTrue(
            unsanitised.isEmpty(),
            "these rows interpolate attacker-controllable text with no sanitiser:" +
                System.lineSeparator() + unsanitised.joinToString(System.lineSeparator())
        )
    }

    /** One exit point: a `Write-Output` outside `Emit` would bypass the sanitiser. */
    @Test
    fun `nothing writes output except Emit`() {
        val writes = script.lines()
            .map { it.trim() }
            .filter { it.startsWith("Write-Output") || it.startsWith("Write-Host") }

        assertTrue(
            writes.size == 1,
            "exactly one Write-Output should exist, inside Emit. Found:" +
                System.lineSeparator() + writes.joinToString(System.lineSeparator())
        )
    }
}
