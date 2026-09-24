package com.blanktick.core.analysis

/**
 * Answers one question about a JPEG: **does it carry a GPS position?**
 *
 * ## Why this is not an EXIF library
 *
 * It does not decode the image, does not read the camera model, does not return
 * the coordinates, and cannot be made to. It walks the JPEG segment headers to
 * the EXIF block, follows the GPS IFD pointer, and reports whether latitude and
 * longitude tags exist. That is the entire surface.
 *
 * The narrowness is the security property. A photo-privacy feature that parses
 * arbitrary files from a user's disk is an attack surface pointed at the person
 * it is meant to protect; a full metadata library would give an attacker a large
 * one and would give Blanktick the ability to read things it has no business reading.
 * This reads a handful of big-endian shorts, allocates nothing proportional to
 * the file, and is bounded by [MAX_SCAN_BYTES].
 *
 * And because the coordinates are never extracted, no location can appear in a
 * crash log, a snapshot dump or a bug report. The app can tell you that eight
 * hundred of your photos know where you live without ever knowing itself.
 *
 * ## Scope
 *
 * JPEG only. HEIC, PNG and WebP return [Verdict.UNSUPPORTED], which the caller
 * counts separately and never folds into "clean" — the same null contract the
 * rest of the app follows, applied to file formats.
 */
object ExifGps {

    /** Never read further than this into a file looking for the EXIF block. */
    private const val MAX_SCAN_BYTES = 512 * 1024

    /** Largest EXIF block we will walk. Real ones are a few KiB. */
    private const val MAX_EXIF_BYTES = 256 * 1024

    /** Refuse absurd IFD entry counts rather than trusting the header. */
    private const val MAX_IFD_ENTRIES = 512

    private const val TAG_GPS_IFD = 0x8825
    private const val TAG_GPS_LATITUDE = 0x0002
    private const val TAG_GPS_LONGITUDE = 0x0004

    enum class Verdict {
        /** A GPS latitude and longitude are present. */
        HAS_LOCATION,

        /** Parsed successfully; no GPS tags. */
        NO_LOCATION,

        /** Not a format this reads. Counted separately, never as clean. */
        UNSUPPORTED,

        /** A JPEG we could not parse. Also never counted as clean. */
        UNREADABLE
    }

    /**
     * @param bytes the leading bytes of the file. Callers should pass at most
     *   [MAX_SCAN_BYTES]; EXIF lives in the first segment, so reading the whole
     *   of a 12 MB photo to answer this would be waste, not thoroughness.
     */
    fun inspect(bytes: ByteArray): Verdict {
        if (bytes.size < 4) return Verdict.UNREADABLE
        // SOI marker. Anything else is a format we do not claim to read.
        if (u8(bytes, 0) != 0xFF || u8(bytes, 1) != 0xD8) return Verdict.UNSUPPORTED

        val exifOffset = findExifSegment(bytes) ?: return Verdict.NO_LOCATION
        return try {
            if (hasGpsPosition(bytes, exifOffset)) Verdict.HAS_LOCATION else Verdict.NO_LOCATION
        } catch (_: Exception) {
            // A malformed file is not a clean file. Saying "no location" here
            // would let a corrupt or hostile image quietly pass the check.
            Verdict.UNREADABLE
        }
    }

    /** @return offset of the TIFF header inside the APP1 segment, or null. */
    private fun findExifSegment(b: ByteArray): Int? {
        var i = 2
        val limit = minOf(b.size, MAX_SCAN_BYTES)

        while (i + 4 <= limit) {
            if (u8(b, i) != 0xFF) return null           // desynchronised; give up
            val marker = u8(b, i + 1)

            // Standalone markers carry no length.
            if (marker == 0xD8 || marker == 0x01 || marker in 0xD0..0xD7) {
                i += 2
                continue
            }
            // Start of scan: image data begins, EXIF cannot follow.
            if (marker == 0xDA || marker == 0xD9) return null

            val length = u16(b, i + 2)
            if (length < 2) return null
            val segmentStart = i + 4
            val segmentEnd = i + 2 + length
            if (segmentEnd > limit) return null

            if (marker == 0xE1 && segmentEnd - segmentStart > 6 &&
                b[segmentStart] == 'E'.code.toByte() &&
                b[segmentStart + 1] == 'x'.code.toByte() &&
                b[segmentStart + 2] == 'i'.code.toByte() &&
                b[segmentStart + 3] == 'f'.code.toByte() &&
                b[segmentStart + 4] == 0.toByte()
            ) {
                return segmentStart + 6   // skip "Exif\0\0"
            }

            i = segmentEnd
        }
        return null
    }

    /** Walks IFD0 for a GPS pointer, then that IFD for latitude and longitude. */
    private fun hasGpsPosition(b: ByteArray, tiff: Int): Boolean {
        if (tiff + 8 > b.size) return false

        val little = when {
            b[tiff] == 'I'.code.toByte() && b[tiff + 1] == 'I'.code.toByte() -> true
            b[tiff] == 'M'.code.toByte() && b[tiff + 1] == 'M'.code.toByte() -> false
            else -> return false
        }
        if (read16(b, tiff + 2, little) != 42) return false

        val ifd0 = tiff + read32(b, tiff + 4, little)
        val gpsPointer = findTag(b, tiff, ifd0, little, TAG_GPS_IFD) ?: return false

        val gpsIfd = tiff + gpsPointer
        val lat = findTag(b, tiff, gpsIfd, little, TAG_GPS_LATITUDE)
        val lon = findTag(b, tiff, gpsIfd, little, TAG_GPS_LONGITUDE)

        // Both must be present. A stray latitude with no longitude is not a
        // position and should not scare anyone.
        return lat != null && lon != null
    }

    /**
     * @return the tag's first value as an unsigned int, or null if absent.
     *
     * Only the value *presence* matters to the caller; the numeric result is
     * used solely to follow the GPS IFD pointer.
     */
    private fun findTag(b: ByteArray, tiff: Int, ifd: Int, little: Boolean, tag: Int): Int? {
        if (ifd < tiff || ifd + 2 > b.size) return null
        if (ifd - tiff > MAX_EXIF_BYTES) return null

        val count = read16(b, ifd, little)
        if (count <= 0 || count > MAX_IFD_ENTRIES) return null

        for (n in 0 until count) {
            val entry = ifd + 2 + n * 12
            if (entry + 12 > b.size) return null
            if (read16(b, entry, little) != tag) continue

            val type = read16(b, entry + 2, little)
            return when (type) {
                3 -> read16(b, entry + 8, little)          // SHORT
                4, 13 -> read32(b, entry + 8, little)      // LONG / IFD
                // A rational (GPS coordinates) is stored out-of-line; its
                // offset is enough to prove the tag exists, which is all the
                // caller asked.
                else -> read32(b, entry + 8, little)
            }
        }
        return null
    }

    // ------------------------------------------------------------- byte reads

    private fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xFF

    private fun u16(b: ByteArray, i: Int): Int = (u8(b, i) shl 8) or u8(b, i + 1)

    private fun read16(b: ByteArray, i: Int, little: Boolean): Int =
        if (little) (u8(b, i + 1) shl 8) or u8(b, i) else u16(b, i)

    private fun read32(b: ByteArray, i: Int, little: Boolean): Int =
        if (little) {
            (u8(b, i + 3) shl 24) or (u8(b, i + 2) shl 16) or (u8(b, i + 1) shl 8) or u8(b, i)
        } else {
            (u8(b, i) shl 24) or (u8(b, i + 1) shl 16) or (u8(b, i + 2) shl 8) or u8(b, i + 3)
        }

    /** Bytes worth reading from a file to answer [inspect]. */
    const val BYTES_TO_READ: Int = MAX_SCAN_BYTES
}
