package com.blanktick.sensor.providers

import com.blanktick.sensor.SensorEvent

/**
 * Handle-opens to sensitive processes, the signal credential theft from lsass
 * produces. Feeds DYN-CRED-001.
 *
 * A user-level poll of `Win32_Process` cannot see one process opening a handle
 * into another; that needs a source that records cross-process access. The
 * bundled script ([handle-open-provider.ps1]) uses whichever is present, in
 * order: Sysmon ProcessAccess (Event ID 10) — the design spec's source — then
 * the Defender ASR lsass rule's 1121/1122 events. If neither exists it reports
 * `#source=none` and emits nothing, so credential theft is carried as an
 * *unobserved gap* via [status], never as clean.
 *
 * Reading those Operational logs needs administrator rights, so this is an
 * [Privilege.ADMIN] tap. It still opens no socket — it reads the local event
 * log through a child PowerShell — so the no-network gate holds.
 */
class HandleOpenProvider : ScriptTapProvider(
    "/handle-open-provider.ps1",
    "windows-credential (lsass handle via Sysmon EID10 / Defender ASR)",
    Privilege.ADMIN,
    "needs Sysmon ProcessAccess (EID 10) or the Defender ASR lsass rule as its source; " +
        "absent both, credential theft is UNOBSERVED, not clean"
) {
    override fun parse(line: String): SensorEvent? = parseLine(line)

    /** Parse `at<TAB>pid<TAB>image<TAB>targetImage<TAB>access`. */
    internal fun parseLine(line: String): SensorEvent.HandleOpen? {
        if (line.startsWith("#") || line.isBlank()) return null
        val f = line.split('\t')
        if (f.size < 4) return null
        val at = f[0].toLongOrNull() ?: return null
        val pid = f[1].toLongOrNull() ?: -1L
        val image = f[2]
        val targetImage = f[3]
        if (targetImage.isBlank()) return null
        val access = if (f.size >= 5) f[4] else ""
        return SensorEvent.HandleOpen(
            at = at, pid = pid, image = image, targetImage = targetImage, access = access
        )
    }
}
