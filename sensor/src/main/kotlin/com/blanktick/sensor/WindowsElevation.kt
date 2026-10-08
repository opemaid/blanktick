package com.blanktick.sensor

/**
 * Whether this process is running with administrator rights.
 *
 * Asked once at startup so the harness can pick the right tap and, in the spirit
 * of the free tier, report honestly what it is actually running as — rather than
 * printing a fixed label that reads as a claim.
 */
object WindowsElevation {
    fun isAdmin(): Boolean = try {
        val p = ProcessBuilder(
            "powershell", "-NoProfile", "-Command",
            "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())" +
                ".IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)"
        ).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText().trim()
        p.waitFor()
        out.equals("True", ignoreCase = true)
    } catch (e: Exception) {
        // If we cannot tell, assume not elevated — the honest, safe default.
        false
    }
}
