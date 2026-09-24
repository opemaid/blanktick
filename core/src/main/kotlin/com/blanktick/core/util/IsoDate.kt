package com.blanktick.core.util

/**
 * Minimal, timezone-free date arithmetic on `yyyy-MM-dd` strings.
 *
 * ## Why not `java.time`
 *
 * The Swift mirror of this module has to produce bit-identical results, and
 * `LocalDate` / `Calendar` drag in locale, timezone and calendar-system
 * behaviour that differs subtly between platforms. Patch-level comparisons are
 * pure civil-date arithmetic with no zone involved, so we implement the two
 * lines of maths directly and get exact parity for free.
 *
 * The algorithm is Howard Hinnant's `days_from_civil`, which is exact for all
 * years in the proleptic Gregorian calendar and trivially portable.
 */
object IsoDate {

    private val PATTERN = Regex("""^(\d{4})-(\d{2})-(\d{2})$""")

    /** @return days since 1970-01-01, or null if [value] is not `yyyy-MM-dd`. */
    fun toEpochDay(value: String): Long? {
        val m = PATTERN.matchEntire(value.trim()) ?: return null
        val y = m.groupValues[1].toInt()
        val mo = m.groupValues[2].toInt()
        val d = m.groupValues[3].toInt()
        if (mo !in 1..12) return null
        if (d < 1 || d > daysInMonth(y, mo)) return null
        return daysFromCivil(y, mo, d)
    }

    /** Days from [from] to [to]; negative when [to] is earlier. Null if unparseable. */
    fun daysBetween(from: String, to: String): Long? {
        val a = toEpochDay(from) ?: return null
        val b = toEpochDay(to) ?: return null
        return b - a
    }

    fun isValid(value: String): Boolean = toEpochDay(value) != null

    private fun isLeap(y: Int): Boolean = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0

    private fun daysInMonth(y: Int, m: Int): Int = when (m) {
        1, 3, 5, 7, 8, 10, 12 -> 31
        4, 6, 9, 11 -> 30
        2 -> if (isLeap(y)) 29 else 28
        else -> 0
    }

    private fun daysFromCivil(year: Int, month: Int, day: Int): Long {
        // Shift the year so that the leap day lands at the end of a 400-year era.
        val y = (if (month <= 2) year - 1 else year).toLong()
        val era = (if (y >= 0) y else y - 399) / 400
        val yoe = y - era * 400                                    // [0, 399]
        val mp = (month + 9) % 12                                  // Mar = 0
        val doy = (153L * mp + 2) / 5 + day - 1                    // [0, 365]
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy            // [0, 146096]
        return era * 146097L + doe - 719468L
    }
}
