package com.blanktick.desktop.collect

import com.blanktick.core.analysis.ExifGps
import java.io.File
import java.nio.file.Files

/**
 * The automatic part of DATA-EXIF-001: counts photos in the user's own Pictures
 * folder that carry a GPS position, so a normal scan answers the check instead
 * of leaving it "not checkable" until someone opens the photo screen.
 *
 * Same contract as the photo screen ([com.blanktick.desktop.AppState.scanPhotos]):
 * reads at most [ExifGps.BYTES_TO_READ] of each file, never extracts a
 * coordinate, never stores a filename. Counts only.
 *
 * ## Offline, really
 *
 * A Pictures folder synced by OneDrive or Dropbox can hold *placeholder* files
 * whose bytes live in the cloud. Opening one makes Windows download it — a
 * network side effect an offline scanner must never cause. Placeholders carry
 * the OFFLINE (0x1000) or RECALL_ON_DATA_ACCESS (0x400000) attribute and are
 * skipped and counted as [Result.skippedCloudOnly], not read.
 */
internal object PhotoSurvey {

    data class Result(val scanned: Int, val withLocation: Int, val unsupported: Int, val skippedCloudOnly: Int)

    /** JPEG is what [ExifGps] parses; the others are counted as unsupported. */
    private val PHOTO_EXTENSIONS = setOf("jpg", "jpeg", "jpe", "heic", "heif", "png", "webp")

    /** A bounded scan: enough to answer the question, not a full library index. */
    const val MAX_FILES = 5_000

    private const val FILE_ATTRIBUTE_OFFLINE = 0x1000
    private const val FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000

    /**
     * `null` when the folder does not exist, or when it holds photos but none in a
     * format the parser can read (e.g. only HEIC) — that is "could not check",
     * not "no photos".
     */
    fun survey(folder: File?): Result? {
        if (folder == null || !folder.isDirectory) return null
        var scanned = 0; var located = 0; var unsupported = 0; var cloud = 0
        folder.walkTopDown()
            .onEnter { !it.isHidden }
            .filter { it.isFile && it.extension.lowercase() in PHOTO_EXTENSIONS }
            .take(MAX_FILES)
            .forEach { file ->
                if (isCloudOnly(file)) { cloud++; return@forEach }
                if (file.length() <= 0) return@forEach
                when (inspect(file)) {
                    ExifGps.Verdict.HAS_LOCATION -> { scanned++; located++ }
                    ExifGps.Verdict.NO_LOCATION -> scanned++
                    ExifGps.Verdict.UNSUPPORTED, ExifGps.Verdict.UNREADABLE -> unsupported++
                }
            }
        if (scanned == 0 && (unsupported > 0 || cloud > 0)) return null
        return Result(scanned, located, unsupported, cloud)
    }

    private fun isCloudOnly(file: File): Boolean = try {
        val attrs = Files.getAttribute(file.toPath(), "dos:attributes") as Int
        attrs and (FILE_ATTRIBUTE_OFFLINE or FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) != 0
    } catch (_: Exception) {
        false   // not Windows, or attribute view unavailable: a normal local file
    }

    private fun inspect(file: File): ExifGps.Verdict = try {
        val head = ByteArray(minOf(file.length(), ExifGps.BYTES_TO_READ.toLong()).toInt())
        file.inputStream().use { it.read(head) }
        ExifGps.inspect(head)
    } catch (_: Exception) {
        ExifGps.Verdict.UNREADABLE
    }
}
