package com.blanktick.sensor

import java.io.File

/**
 * Resolves `powershell.exe` to its absolute System32 path instead of trusting
 * `%PATH%`.
 *
 * The sensor cannot reuse the desktop module's hardened `Shell` (it depends only
 * on `:core`), so this is the one piece of that hardening the sensor needs on
 * its own: launching `"powershell"` by bare name lets whoever controls `%PATH%`
 * — an entry a normal user can prepend under HKCU — decide which executable
 * runs. Under the ETW tap that process is **elevated**, so a planted
 * `powershell.exe` would run as administrator. Resolving to the absolute path
 * under `%SystemRoot%\System32` (owned by TrustedInstaller, unwritable below
 * administrator) removes that choice.
 *
 * Returns `null` when no trusted PowerShell can be found; callers must refuse to
 * launch rather than fall back to the PATH.
 */
internal object TrustedPowerShell {
    fun path(): String? {
        val root = System.getenv("SystemRoot") ?: System.getenv("windir") ?: return null
        val candidates = listOf(
            "System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
        )
        for (sub in candidates) {
            val f = File(root, sub)
            if (f.isFile) return f.absolutePath
        }
        return null
    }
}
