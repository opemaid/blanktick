package com.blanktick.desktop.collect

import com.blanktick.desktop.collect.FullPcScan.DriveKind
import com.blanktick.desktop.collect.FullPcScan.DriveOutcome
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The verdict rules for the whole-PC scan.
 *
 * The clean and failure outputs below were captured from MpCmdRun on a real
 * Windows 11 machine. The detection output follows Defender's documented
 * threat-list layout; it could not be captured live, because real-time
 * protection removes a test file the moment it is written.
 */
class FullPcScanTest {

    private val clean = """
        Scan starting...
        Scan finished.
        Scanning C:\Users\me\AppData\Local\Temp\bt-mp-probe found no threats.
    """.trimIndent()

    private val failed =
        "CmdTool: Failed with hr = 0x80070002. Check C:\\Users\\me\\AppData\\Local\\Temp\\MpCmdRun.log for more information"

    private val detected = """
        Scan starting...
        Scan finished.
        Scanning D:\ found 2 threats.

        <===========================LIST OF DETECTED THREATS==========================>
        ----------------------------- Threat information ------------------------------
        Threat                  : Virus:DOS/EICAR_Test_File
        Resources               : 1 total
            file                : D:\test\eicar.com
        -------------------------------------------------------------------------------
        ----------------------------- Threat information ------------------------------
        Threat                  : Trojan:Win32/Example
        Resources               : 2 total
            file                : D:\tools\bad.exe
            file                : D:\tools\bad.dll
        -------------------------------------------------------------------------------
    """.trimIndent()

    @Test
    fun `exit 0 is clean`() {
        assertEquals(DriveOutcome.Clean, FullPcScan.interpret(0, clean))
    }

    @Test
    fun `exit 2 with a failure HRESULT is not scanned, never a threat`() {
        // The trap: MpCmdRun exits 2 for "could not scan" exactly as for a detection.
        assertIs<DriveOutcome.NotScanned>(FullPcScan.interpret(2, failed))
    }

    @Test
    fun `a failure HRESULT wins even over exit 0`() {
        assertIs<DriveOutcome.NotScanned>(FullPcScan.interpret(0, failed))
    }

    @Test
    fun `exit 2 without a failure names every threat and file`() {
        val outcome = assertIs<DriveOutcome.Threats>(FullPcScan.interpret(2, detected))
        assertEquals(listOf("Virus:DOS/EICAR_Test_File", "Trojan:Win32/Example"), outcome.detections.map { it.threat })
        assertEquals(listOf("D:\\test\\eicar.com"), outcome.detections[0].resources)
        assertEquals(listOf("D:\\tools\\bad.exe", "D:\\tools\\bad.dll"), outcome.detections[1].resources)
    }

    @Test
    fun `untranslatable output still reports threats, just unnamed`() {
        val outcome = assertIs<DriveOutcome.Threats>(FullPcScan.interpret(2, "Analyse terminée."))
        assertTrue(outcome.detections.isEmpty())
    }

    @Test
    fun `any other exit code is not scanned`() {
        assertIs<DriveOutcome.NotScanned>(FullPcScan.interpret(1, ""))
        assertIs<DriveOutcome.NotScanned>(FullPcScan.interpret(-1, ""))
    }

    @Test
    fun `drive lines keep fixed and removable, drop the rest`() {
        assertEquals(FullPcScan.Drive("C:\\", DriveKind.FIXED, "Windows"), FullPcScan.parseDrive("C:\t3\tWindows"))
        assertEquals(FullPcScan.Drive("E:\\", DriveKind.REMOVABLE, null), FullPcScan.parseDrive("E:\t2\t"))
        assertNull(FullPcScan.parseDrive("Z:\t4\tshare"))
        assertNull(FullPcScan.parseDrive("garbage"))
    }
}
