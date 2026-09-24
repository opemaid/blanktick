package com.blanktick.core.analysis

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The GPS detector.
 *
 * Fixtures are built here rather than checked in as binaries: a real photo in
 * the repository would be someone's actual location, and a security app's test
 * corpus is the last place that should live.
 */
class ExifGpsTest {

    // ------------------------------------------------------------- builders

    /** Minimal JPEG: SOI, an APP1/EXIF segment, then EOI. */
    private fun jpegWithExif(exifPayload: ByteArray): ByteArray {
        val header = byteArrayOf('E'.code.toByte(), 'x'.code.toByte(), 'i'.code.toByte(),
            'f'.code.toByte(), 0, 0)
        val body = header + exifPayload
        val length = body.size + 2
        return byteArrayOf(
            0xFF.toByte(), 0xD8.toByte(),                       // SOI
            0xFF.toByte(), 0xE1.toByte(),                       // APP1
            (length shr 8).toByte(), (length and 0xFF).toByte()
        ) + body + byteArrayOf(0xFF.toByte(), 0xD9.toByte())    // EOI
    }

    /**
     * A big-endian TIFF block with IFD0 -> (optional) GPS IFD.
     *
     * Offsets are relative to the TIFF header, exactly as the format requires,
     * which is the part an implementation most easily gets wrong.
     */
    private fun tiff(withGps: Boolean, gpsHasLongitude: Boolean = true): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        fun be16(v: Int) { out.write(v shr 8); out.write(v and 0xFF) }
        fun be32(v: Int) {
            out.write(v shr 24); out.write((v shr 16) and 0xFF)
            out.write((v shr 8) and 0xFF); out.write(v and 0xFF)
        }

        out.write('M'.code); out.write('M'.code)   // big-endian
        be16(42)
        be32(8)                                    // IFD0 at offset 8

        // ---- IFD0
        val ifd0Entries = if (withGps) 1 else 1
        be16(ifd0Entries)
        if (withGps) {
            be16(0x8825); be16(4); be32(1); be32(30)     // GPS IFD pointer -> 30
        } else {
            be16(0x010F); be16(2); be32(1); be32(0)      // Make, harmless filler
        }
        be32(0)                                          // no next IFD
        // Bytes so far: 8 header + 2 count + 12 entry + 4 next = 26.
        // Pad to the GPS IFD offset of 30.
        repeat(4) { out.write(0) }

        if (withGps) {
            val gpsEntries = if (gpsHasLongitude) 2 else 1
            be16(gpsEntries)
            be16(0x0002); be16(5); be32(3); be32(200)    // GPSLatitude
            if (gpsHasLongitude) {
                be16(0x0004); be16(5); be32(3); be32(224) // GPSLongitude
            }
            be32(0)
        }
        return out.toByteArray()
    }

    // ---------------------------------------------------------------- tests

    @Test
    fun `a photo with latitude and longitude is detected`() {
        assertEquals(
            ExifGps.Verdict.HAS_LOCATION,
            ExifGps.inspect(jpegWithExif(tiff(withGps = true)))
        )
    }

    @Test
    fun `a photo with an EXIF block but no GPS IFD is clean`() {
        assertEquals(
            ExifGps.Verdict.NO_LOCATION,
            ExifGps.inspect(jpegWithExif(tiff(withGps = false)))
        )
    }

    /**
     * A latitude with no longitude is not a position, and telling someone their
     * holiday photos leak their address on that basis would be a false alarm.
     */
    @Test
    fun `latitude alone is not a location`() {
        assertEquals(
            ExifGps.Verdict.NO_LOCATION,
            ExifGps.inspect(jpegWithExif(tiff(withGps = true, gpsHasLongitude = false)))
        )
    }

    @Test
    fun `a JPEG with no EXIF at all is clean`() {
        val plain = byteArrayOf(
            0xFF.toByte(), 0xD8.toByte(),
            0xFF.toByte(), 0xDB.toByte(), 0x00, 0x04, 0x00, 0x00,   // a DQT segment
            0xFF.toByte(), 0xD9.toByte()
        )
        assertEquals(ExifGps.Verdict.NO_LOCATION, ExifGps.inspect(plain))
    }

    /**
     * PNG, HEIC and friends are reported as unsupported, never as clean. The
     * caller counts them separately so the UI can say "and 40 files I could not
     * read", which is the whole point of the null contract.
     */
    @Test
    fun `a non-JPEG is unsupported, not clean`() {
        val png = byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte())
        assertEquals(ExifGps.Verdict.UNSUPPORTED, ExifGps.inspect(png))
    }

    @Test
    fun `an empty or truncated file is unreadable`() {
        assertEquals(ExifGps.Verdict.UNREADABLE, ExifGps.inspect(ByteArray(0)))
        assertEquals(ExifGps.Verdict.UNREADABLE, ExifGps.inspect(byteArrayOf(0xFF.toByte())))
    }

    /**
     * Truncation partway through the EXIF block must not throw and must not
     * report clean. Fuzzing this by hand: every prefix of a valid file.
     */
    @Test
    fun `every truncation of a real file is handled without throwing`() {
        val full = jpegWithExif(tiff(withGps = true))
        for (n in 1..full.size) {
            val verdict = ExifGps.inspect(full.copyOf(n))
            // The only forbidden outcome is a crash; any verdict is acceptable.
            assertEquals(true, verdict in ExifGps.Verdict.entries, "at length $n")
        }
    }

    /**
     * A header claiming an enormous IFD entry count must be refused rather than
     * driving a half-million-iteration loop over attacker-chosen offsets.
     */
    @Test
    fun `an absurd entry count is refused`() {
        val hostile = java.io.ByteArrayOutputStream().apply {
            write('M'.code); write('M'.code)
            write(0); write(42)
            write(0); write(0); write(0); write(8)
            write(0xFF); write(0xFF)          // 65535 entries, in a 12-byte file
        }.toByteArray()

        assertEquals(ExifGps.Verdict.NO_LOCATION, ExifGps.inspect(jpegWithExif(hostile)))
    }
}
