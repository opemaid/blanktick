package com.blanktick.sensor.providers

import com.blanktick.sensor.FileOp
import com.blanktick.sensor.SensorEvent

/**
 * File-integrity events in the shape ransomware produces. Feeds DYN-RANSOM-001.
 *
 * The bundled script ([file-activity-provider.ps1]) carries two native signals
 * on one stream, each line tagged by a leading token:
 *
 *  * `FILE` — a FileSystemWatcher over the user's document folders, emitting
 *    only writes whose first-4 KB Shannon entropy is in the ciphertext range
 *    (op=ENCRYPT_SUSPECTED). It watches documents and the desktop but NOT the
 *    pictures folder, and skips inherently high-entropy media/archive
 *    extensions, so a bulk photo import or archive extract does not look like
 *    encryption. Without a minifilter the OS does not name the writing process
 *    to a user-level watcher, so these carry `pid = -1`; the burst rule still
 *    fires on a mass-encryption run but, with no process to stop, emits ALERT
 *    rather than KILL. A Sysmon FileCreate (EID 11) or minifilter source would
 *    restore the pid and the KILL response.
 *
 *  * `VSSDEL` — a poll of new processes whose command line deletes shadow copies
 *    or disables recovery. This keeps the real pid, so its response stays kill.
 *
 * [Privilege.USER]: it watches the current user's own files and processes.
 * Admin broadens the process view machine-wide. It opens no socket.
 */
class FileActivityProvider : ScriptTapProvider(
    "/file-activity-provider.ps1",
    "windows-file-integrity (FileSystemWatcher entropy + shadow-copy delete)",
    Privilege.USER,
    "entropy writes are machine-observed but not process-attributed without a minifilter " +
        "(pid unknown → alert, not kill); shadow-copy deletion keeps its pid"
) {
    override fun parse(line: String): SensorEvent? = parseLine(line)

    /**
     * Parse one tagged line:
     *   `FILE<TAB>at<TAB>pid<TAB>image<TAB>path<TAB>op<TAB>highEntropy`
     *   `VSSDEL<TAB>at<TAB>pid<TAB>image<TAB>commandLine`
     * Returns null on a status line or anything malformed rather than guessing.
     */
    internal fun parseLine(line: String): SensorEvent? {
        if (line.startsWith("#") || line.isBlank()) return null
        val f = line.split('\t')
        return when (f.getOrNull(0)) {
            "FILE" -> {
                if (f.size < 7) return null
                val at = f[1].toLongOrNull() ?: return null
                val pid = f[2].toLongOrNull() ?: -1L
                val image = f[3]
                val path = f[4]
                val op = when (f[5]) {
                    "ENCRYPT_SUSPECTED" -> FileOp.ENCRYPT_SUSPECTED
                    "RENAME" -> FileOp.RENAME
                    "WRITE" -> FileOp.WRITE
                    else -> return null
                }
                val highEntropy = f[6] == "true"
                SensorEvent.FileModify(
                    at = at, pid = pid, image = image, path = path, op = op, highEntropy = highEntropy
                )
            }
            "VSSDEL" -> {
                if (f.size < 4) return null
                val at = f[1].toLongOrNull() ?: return null
                val pid = f[2].toLongOrNull() ?: -1L
                val image = f[3]
                val commandLine = if (f.size >= 5) f[4] else ""
                SensorEvent.ShadowCopyDeletion(at = at, pid = pid, image = image, commandLine = commandLine)
            }
            else -> null
        }
    }
}
