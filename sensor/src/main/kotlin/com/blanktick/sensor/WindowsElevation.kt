package com.blanktick.sensor

/**
 * Whether this process is running with administrator rights.
 *
 * Asked once at startup so the harness can pick the right tap and, in the spirit
 * of the free tier, report honestly what it is actually running as — rather than
 * printing a fixed label that reads as a claim.
 */
object WindowsElevation {
    fun isAdmin(): Boolean {
        return try {
            // Absolute System32 path, not the PATH (see TrustedPowerShell): this
            // runs at startup and must not be hijackable. No trusted shell → we
            // cannot tell → not elevated, the safe default.
            val psExe = TrustedPowerShell.path() ?: return false
            val p = ProcessBuilder(
                psExe, "-NoProfile", "-Command",
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())" +
                    ".IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)"
            ).redirectErrorStream(true).start()
            // Bounded wait: a hung or planted powershell must not stall sensor
            // startup forever. The output is a single short line, well under the
            // pipe buffer, so reading it after the process exits cannot deadlock.
            if (!p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly()
                return false
            }
            p.inputStream.bufferedReader().readText().trim().equals("True", ignoreCase = true)
        } catch (e: Exception) {
            // If we cannot tell, assume not elevated — the honest, safe default.
            false
        }
    }
}
