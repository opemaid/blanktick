package com.mume.desktop

import com.mume.desktop.collect.WindowsProbe
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Pins the properties that make a partial collection distinguishable from a
 * complete one.
 *
 * ## Why this file exists
 *
 * The null contract says an unanswerable question reports as *not checkable*.
 * It holds per fact, and it held here — but it says nothing about the
 * collection as a whole. A probe killed halfway emits output that looks exactly
 * like a successful run of a shorter script: every fact it never reached is
 * correctly marked unknown, and the report is quietly three-quarters empty
 * while still reading as reassuring.
 *
 * Making a security tool stop early is easier than making it lie, and it leaves
 * no trace in the output. These tests pin the markers that give it one.
 */
class ProbeIntegrityTest {

    private val script = WindowsProbe.SCRIPT

    /**
     * Every list-valued query needs a sentinel, or an empty result is
     * ambiguous between "none" and "the query failed".
     *
     * Four of these existed. The other five did not, so a firewall enumeration
     * that died after two profiles reported "both profiles I read are enabled"
     * as though it were the firewall's state, and a truncated administrator
     * group scored the machine on the members it happened to see.
     */
    @Test
    fun `every enumeration emits a completion sentinel`() {
        val required = listOf(
            "fw.enumerated",            // firewall profiles
            "acct.adminEnumerated",     // Administrators group
            "acct.userCount",           // local users
            "port.enumerated",          // listening sockets
            "dns.enumerated",           // resolvers
            "cert.storeRead",           // user trust store
            "drive.enumerated",         // removable drives
            "program.enumerated",       // installed software
            "autorun.read"              // persistence, per source
        )
        val missing = required.filterNot { script.contains(it) }
        assertTrue(
            missing.isEmpty(),
            "these enumerations cannot be told apart from a failed query: $missing"
        )
    }

    /**
     * The script's last emitted line vouches for everything above it.
     *
     * Checked positionally, not just for presence: a completion marker that is
     * not last certifies only the part of the script before it.
     */
    @Test
    fun `probe completion is the final statement`() {
        assertTrue(script.contains("probe.complete"), "no whole-script completion marker")

        val lastEmit = script.lines()
            .map { it.trim() }
            .last { it.startsWith("Emit ") }
        assertTrue(
            lastEmit.contains("probe.complete"),
            "the last Emit is `$lastEmit`; anything emitted after the completion " +
                "marker is not covered by it"
        )
    }

    /**
     * Persistence is read from more than one place, and each reports for itself.
     *
     * The first attempt wrapped all seven sources in one try/catch with a single
     * sentinel. On the development machine that returned *nothing at all*: a few
     * Image File Execution Options subkeys deny read access to a non-elevated
     * user, `Get-ChildItem` raised SecurityException, and one unreadable
     * registry key deleted forty-odd findings from six sources that had worked.
     *
     * An all-or-nothing marker is the wrong shape for a multi-source sweep.
     */
    @Test
    fun `persistence sources report coverage individually`() {
        assertTrue(script.contains("autorun.read"), "no per-source success marker")
        assertTrue(script.contains("autorun.failed"), "no per-source failure marker")
        assertTrue(
            !script.contains("autorun.enumerated"),
            "the single all-or-nothing sentinel is back; one denied registry key " +
                "then deletes every finding from every other source"
        )
    }

    /**
     * The persistence sweep must cover the places things actually start.
     *
     * The shipped version read four: two Run keys and two Startup folders,
     * justified by a comment claiming scheduled tasks and services "need
     * elevation to enumerate reliably". Measured in a plain non-elevated
     * session, `Get-ScheduledTask` returned all 210 tasks and `Win32_Service`
     * all 306 — so the app was performing exactly the partial sweep its own
     * comment warned against, on a premise that was simply false.
     *
     * On that machine the difference was 9 entries shown against 46 that exist.
     */
    @Test
    fun `persistence covers the mechanisms malware actually uses`() {
        val required = mapOf(
            "RunOnce" to "RunOnce",
            "WOW6432Node" to "the 32-bit Run keys",
            "Winlogon" to "Winlogon Shell/Userinit",
            "Image File Execution Options" to "IFEO debugger hijacks",
            "Get-ScheduledTask" to "scheduled tasks",
            "Win32_Service" to "auto-start services"
        )
        val missing = required.filterKeys { !script.contains(it) }.values
        assertTrue(missing.isEmpty(), "persistence sweep does not look at: $missing")
    }

    /**
     * The signature check must not be defeatable by renaming a file.
     *
     * The old extractor used `^(?<p>[^ ]+\.exe)` for unquoted commands — a
     * pattern that cannot match a path containing a space. So
     * `C:\Program Files\Evil\run.exe` yielded no executable, no signature was
     * fetched, the entry reported "unknown", and `DSK-AUTO-001` skips unknowns
     * rather than accusing them. **One space in the filename and the check
     * never ran.**
     */
    @Test
    fun `the executable extractor is not the space-defeated regex`() {
        // Comment lines are excluded: the probe documents the old broken pattern
        // by quoting it, and a check that cannot tell an explanation from an
        // instruction would forbid describing the very bug it guards against.
        val code = script.lines().filterNot { it.trimStart().startsWith("#") }
        assertTrue(
            code.none { it.contains("[^ ]+\\.exe") },
            "the single-token regex is back; a path with a space in it skips the " +
                "signature check entirely"
        )
        assertTrue(script.contains("function ExePath"), "no executable resolver")
        assertTrue(
            script.contains("ExpandEnvironmentVariables"),
            "%APPDATA%-style commands must be expanded before resolution"
        )
    }

    /**
     * Per-entry failures must stay per-entry.
     *
     * `Get-AuthenticodeSignature` throws IOException on a Windows app execution
     * alias — the reparse-point stubs under `WindowsApps` that `Test-Path`
     * confirms exist. Microsoft Teams ships exactly such a Run entry on a stock
     * Windows 11, and one unguarded call to it aborted the enumeration of every
     * other Run key on the machine.
     *
     * Generalised, that is an attack: these paths come from registry values
     * anyone can write, so if one bad target ends the loop then adding a single
     * junk Run entry deletes every other Run finding.
     */
    @Test
    fun `the signature lookup is guarded per entry`() {
        val emitAuto = script.lines()
            .dropWhile { !it.contains("function EmitAuto") }
            .takeWhile { !it.contains("function EmitRun") }
            .joinToString("\n")

        assertTrue(emitAuto.isNotBlank(), "EmitAuto not found")
        assertTrue(
            emitAuto.contains("try {") && emitAuto.contains("catch"),
            "an unguarded Get-AuthenticodeSignature lets one unreadable target " +
                "delete every other entry in its source:\n$emitAuto"
        )
        assertTrue(
            emitAuto.contains("-ErrorAction Stop"),
            "the guard only works if the error is made terminating"
        )
    }

    /**
     * Machine policy outranks user policy, because that is how Windows resolves
     * it.
     *
     * The order was previously HKCU-last, so the per-user key won — and that key
     * needs no administrator rights. An unprivileged process could write the
     * hardened value to HKCU and be told autorun was blocked while the machine
     * policy actually allowed it. Precedence has to match the OS or the check
     * describes a computer that does not exist.
     */
    @Test
    fun `autorun policy reads HKLM last so machine policy wins`() {
        val block = script.lines()
            .dropWhile { !it.contains("NoDriveTypeAutoRun") || !it.contains("foreach") }
            .let { lines ->
                script.lines()
                    .dropWhile { !it.contains("arRaw = ") }
                    .takeWhile { !it.contains("usb.autorunBlocked") }
                    .joinToString("\n")
                    .ifBlank { lines.joinToString("\n") }
            }

        val hkcu = block.indexOf("HKCU:")
        val hklm = block.indexOf("HKLM:")
        assertTrue(hkcu >= 0 && hklm >= 0, "both hives must be read:\n$block")
        assertTrue(
            hklm > hkcu,
            "HKCU is read last and therefore wins, which inverts Windows' own " +
                "precedence and lets an unprivileged key decide the verdict"
        )
    }

    /** A single oversized field must not push later answers out of the stream. */
    @Test
    fun `field sanitisation caps length`() {
        val san = script.lines()
            .dropWhile { !it.contains("function San(") }
            .takeWhile { !it.contains("function Emit(") }
            .joinToString("\n")
        assertTrue(
            san.contains("Substring(0, 512)"),
            "San does not cap length, so one enormous registry value can push " +
                "every later finding past the output ceiling:\n$san"
        )
    }
}
