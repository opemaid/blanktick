package com.mume.desktop

import com.mume.desktop.collect.WindowsProbe
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Guards on the one string in this project that gets handed to a shell.
 *
 * These are cheap, and they exist because the failure they prevent is not a
 * crash — it is a security app quietly changing something on someone's machine.
 * Mume reports; the user decides and acts. A `Set-` that slipped into the probe
 * would break that promise silently and permanently.
 */
class WindowsProbeTest {

    private val script = WindowsProbe.SCRIPT

    /** Statements outside comments, which is what actually runs. */
    private val statements: List<String> = script.lines()
        .map { it.substringBefore('#').trim() }
        .filter { it.isNotEmpty() }

    /**
     * Verbs that change the machine.
     *
     * Not exhaustive as a security boundary — a determined author could still
     * find a way — but it catches the realistic case, which is someone adding a
     * "helpful" fix and not noticing it crossed a line.
     */
    private val mutatingVerbs = listOf(
        "Set-", "New-", "Remove-", "Clear-", "Start-", "Stop-", "Restart-",
        "Disable-", "Enable-", "Install-", "Uninstall-", "Add-", "Rename-",
        "Move-", "Copy-", "Out-File", "Invoke-Expression", "iex ", "Invoke-WebRequest",
        "Invoke-RestMethod", "Start-Process"
    )

    @Test
    fun `the probe never changes anything`() {
        val offenders = statements
            // The two sanctioned exceptions, pinned by the next test.
            .filterNot {
                it.contains("New-Object -ComObject Shell.Application") ||
                    it.contains("New-Object -ComObject Microsoft.Update.Session")
            }
            .filter { line -> mutatingVerbs.any { verb -> line.contains(verb) } }
        assertTrue(
            offenders.isEmpty(),
            "the Windows probe must only query, but found:\n" + offenders.joinToString("\n")
        )
    }

    /**
     * Two COM handles are allowed, and they are named here so that the blanket
     * ban above stays meaningful.
     *
     * Both create an in-process handle and change nothing: `Shell.Application`
     * reads BitLocker status without elevation, `Microsoft.Update.Session`
     * reads the update agent's local catalogue.
     */
    @Test
    fun `every New- in the probe is one of the two sanctioned COM handles`() {
        val newObjects = statements.filter { it.contains("New-Object") }
        assertEquals(2, newObjects.size, "unexpected New-Object: $newObjects")

        // Shell.Application reads BitLocker status without elevation.
        // Microsoft.Update.Session reads the update agent's LOCAL catalogue.
        // Both create an in-process handle and change nothing on the machine;
        // listing them explicitly is what keeps the blanket ban meaningful.
        val sanctioned = listOf("Shell.Application", "Microsoft.Update.Session")
        val unexpected = newObjects.filterNot { line -> sanctioned.any { line.contains(it) } }
        assertTrue(unexpected.isEmpty(), "unsanctioned COM object: $unexpected")
    }

    /**
     * The update agent must be asked offline.
     *
     * Enumerating pending updates normally means contacting Microsoft, which is
     * why this check was reported as never-performed for so long. The agent
     * keeps a local catalogue and `Online = false` searches only that. Left at
     * its default this becomes a network call inside an app whose central
     * promise is that it never makes one — and it would not look like one,
     * because there is no URL and no cmdlet for the other guards to catch.
     */
    @Test
    fun `the update search is explicitly offline`() {
        val usesAgent = statements.any { it.contains("Microsoft.Update.Session") }
        if (!usesAgent) return

        assertTrue(
            statements.any { it.contains("Online") && it.contains("false") },
            "the update searcher must set Online = false, or the probe reaches the network"
        )
        val searches = statements.filter { it.contains(".Search(") }
        assertTrue(searches.isNotEmpty(), "the search call has gone missing")
    }

    /**
     * Nothing may reach the network.
     *
     * The desktop build's bytecode gate covers Kotlin. It cannot see inside a
     * PowerShell string, so the shell script needs its own check.
     */
    @Test
    fun `the probe makes no network request`() {
        val networkCmdlets = listOf(
            "Invoke-WebRequest", "Invoke-RestMethod", "Test-Connection", "Test-NetConnection",
            "New-WebServiceProxy", "Start-BitsTransfer", "curl", "wget",
            "System.Net", "WebClient", "DownloadString", "Resolve-DnsName"
        )
        val offenders = statements.filter { line -> networkCmdlets.any { line.contains(it) } }
        assertTrue(offenders.isEmpty(), "the probe must not touch the network:\n$offenders")
    }

    /**
     * The probe takes no parameters and interpolates nothing.
     *
     * It is a compile-time constant handed to a shell. If it ever gained a
     * substitution point, anything a user typed into the app could reach a
     * command line, which is a different and much worse program.
     */
    @Test
    fun `the probe is a constant with no interpolation`() {
        // Kotlin template syntax would have been expanded at compile time; what
        // must not appear is a placeholder the collector fills in later.
        assertFalse(script.contains("%s"))
        assertFalse(script.contains("{0}=") && script.contains("String.format"))
    }

    /**
     * Every emitted key must be one the collector reads, and vice versa.
     *
     * A typo on either side produces a silent `null`, which the null contract
     * dutifully reports as "not checkable" — the app would be honestly telling
     * the user it could not determine something it had, in fact, measured.
     */
    @Test
    fun `every key the probe emits is one the collector consumes`() {
        // Digits are in the character class deliberately. The first version of
        // this pattern was `[a-zA-Z.]+`, which cannot match `hard.smb1` or
        // `hard.psV2Present` — so those two keys were invisible to the guard
        // entirely, and a typo in either would have produced a permanently null
        // fact that the null contract would have reported, quite honestly, as
        // "not checkable". A parity test with a blind spot is worse than none,
        // because it is trusted.
        val emitted = Regex("""Emit '([A-Za-z0-9._]+)'""")
            .findAll(script)
            .map { it.groupValues[1] }
            .toSortedSet()

        assertEquals(
            sortedSetOf(
                "acct.admin", "acct.adminEnumerated", "acct.currentPasswordRequired", "acct.guestEnabled",
                "acct.passwordless", "acct.sessionIsAdmin", "acct.userCount",
                "autorun", "autorun.read", "autorun.failed",
                "av.antispyware", "av.behaviorMonitor", "av.defenderPresent",
                "av.exclusion", "av.exclusionsReadable", "av.ioavProtection",
                "av.networkInspection", "av.realtimeEnabled", "av.registered",
                "av.signatureAgeDays", "av.tamperProtected", "av.threatActive",
                "av.threatsKnown", "av.threatsRead",
                "bitlocker.protection",
                "cert", "cert.storeRead",
                "dns", "dns.enumerated",
                "drive", "drive.enumerated",
                "fw.enumerated", "hash.selfTest",
                "reachable", "reachable.enumerated", "reachable.unattributed",
                "machinecert", "machinecert.enumerated",
                "update.pendingCount", "update.pendingSeverity", "update.pendingRead",
                "fw.profile",
                "hard.autoAdminLogon", "hard.autoLogonPasswordStored", "hard.consentPrompt",
                "hard.enableLua", "hard.llmnr", "hard.psV2Present", "hard.remoteRegistry",
                "hard.runAsPPL", "hard.settingsRead", "hard.smb1", "hard.wdigest",
                "hard.winrmStatus",
                "lock.screenSaverActive", "lock.screenSaverIsSecure", "lock.screenSaverTimeout",
                "os.build", "ps.languageMode", "probe.complete",
                "avscan", "avscan.enumerated", "av.scannerAvailable",
                "port", "port.enumerated",
                "process", "process.enumerated", "process.pathUnreadable",
                "program", "program.enumerated",
                "proxy.enable", "proxy.server",
                "rdp.denyConnections", "rdp.userAuthentication",
                "secureboot.enabled",
                "smartscreen.explorer", "smartscreen.policy",
                "ssh.status",
                "usb.autorunBlocked", "usbdevice",
                "update.daysSinceLast", "update.noAutoUpdate", "update.serviceStartType"
            ),
            emitted,
            "probe keys changed — update WindowsCollector to match"
        )
    }

    /**
     * Handing a file to the antivirus must never let it change the machine.
     *
     * `MpCmdRun -Scan` **quarantines what it finds** unless remediation is
     * disabled. Measured: "found 1 threats. Cleaning started..." and the file
     * was gone. That would make Mume a program that silently alters your
     * computer as a side effect of asking a question — the one thing it
     * promises not to do, arrived at through a side door rather than a
     * `Set-` cmdlet, which is why the blanket mutation ban above would not have
     * caught it.
     */
    @Test
    fun `every antivirus scan disables remediation`() {
        val scans = statements.filter { it.contains("-Scan") && it.contains("mpCmdRun", true) }

        assertTrue(scans.isNotEmpty(), "the Defender scan invocation has gone missing")
        val unguarded = scans.filterNot { it.contains("-DisableRemediation") }
        assertTrue(
            unguarded.isEmpty(),
            "a scan without -DisableRemediation lets the antivirus quarantine files " +
                "during what is supposed to be a read-only report: " +
                unguarded.joinToString(" | ")
        )
    }

    /**
     * The elevation promise.
     *
     * Mume must work as a standard user. Two cmdlets were removed from earlier
     * drafts for exactly this reason, and this stops them coming back: an app
     * that needs administrator rights in order to tell you not to run as
     * administrator has lost the argument before it starts.
     */
    @Test
    fun `the probe uses no cmdlet that requires elevation`() {
        val needsElevation = listOf("Confirm-SecureBootUEFI", "Get-BitLockerVolume", "manage-bde")
        val offenders = statements.filter { line -> needsElevation.any { line.contains(it) } }
        assertTrue(
            offenders.isEmpty(),
            "these need administrator rights; use the unprivileged route instead:\n$offenders"
        )
    }
}
