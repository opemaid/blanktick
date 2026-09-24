package com.blanktick.core.intel

/**
 * Software whose end of life has **already happened and cannot be reversed**.
 *
 * ## The rule this catalogue obeys, and why it matters
 *
 * Only entries whose EOL date is in the past and final. Nothing here depends on
 * knowing what "current" is.
 *
 * That constraint is the whole design. Blanktick has no network, so it cannot know
 * that Chrome 151 is current — and a bundled "latest version" table would start
 * rotting the day it shipped, turning every up-to-date browser into a false
 * "out of date" claim as the app aged. A list of *permanently dead* software has
 * the opposite failure mode: it can only become **incomplete**, which
 * under-reports. Under-reporting is survivable; crying wolf is not, because a
 * security tool people learn to dismiss protects nobody.
 *
 * The same asymmetry governs `OsCurrencyRules.PatchLag`, which measures only how
 * far *behind* a device is and makes no claim when the device is ahead.
 *
 * ## What is deliberately NOT here
 *
 * - **"Your browser is out of date."** Not checkable offline. Reported as not
 *   performed, like pending OS updates.
 * - **CVE matching.** Needs a feed, needs a server, and version-to-CVE mapping
 *   is wrong often enough to be dangerous without one.
 * - **Anything merely old.** Age is not a vulnerability. Vendor-declared end of
 *   security support is.
 *
 * Refreshes when the app updates, like every other bundled list. The scan states
 * the build date.
 */
object EolCatalog {

    /**
     * @param match matched case-insensitively against the program's display
     *   name as a substring. Kept deliberately loose: installers vary the exact
     *   string ("Adobe Flash Player 32 NPAPI", "Adobe Flash Player ActiveX").
     * @param versionBelow when set, only versions *below* this major are dead —
     *   for software where one line ended and another continues.
     * @param endedYear the year vendor security support actually ended. Shown to
     *   the user, because "unsupported since 2020" is an argument and
     *   "unsupported" is an assertion.
     */
    data class Entry(
        val match: String,
        val product: String,
        val endedYear: Int,
        val why: String,
        val versionBelow: Int? = null
    )

    val ALL: List<Entry> = listOf(
        Entry(
            "adobe flash", "Adobe Flash Player", 2020,
            "Adobe ended it and asked everyone to uninstall it. Every browser " +
                "removed support. Anything still calling it is either broken or hostile."
        ),
        Entry(
            "shockwave", "Adobe Shockwave", 2019,
            "Discontinued, with unpatched flaws still public."
        ),
        Entry(
            "silverlight", "Microsoft Silverlight", 2021,
            "Support ended and no browser will run it any more."
        ),
        Entry(
            "quicktime", "QuickTime for Windows", 2016,
            "Apple stopped patching the Windows version while two critical flaws " +
                "were still open, and advised uninstalling it."
        ),
        Entry(
            "python 2", "Python 2", 2020,
            "The final release was January 2020. Anything still on it receives no " +
                "security fixes at all."
        ),
        Entry(
            "internet explorer", "Internet Explorer", 2022,
            "Retired by Microsoft. It still ships as a component, but as a browser " +
                "it is unsupported."
        ),
        Entry(
            "java", "Java 7 or earlier", 2015,
            "Public updates ended a decade ago. Java of that vintage was one of the " +
                "most reliably exploited things on a desktop.",
            versionBelow = 8
        ),
        Entry(
            "node.js", "Node.js 16 or earlier", 2023,
            "Out of long-term support, so it no longer receives security patches.",
            versionBelow = 18
        )
    )

    /**
     * @return the entry a program matches, or `null`.
     *
     * A `versionBelow` entry only matches when a major version can actually be
     * parsed. An unparseable version means we do not know, and not knowing must
     * never resolve to an accusation.
     */
    fun match(name: String, version: String?): Entry? {
        val lower = name.lowercase()
        return ALL.firstOrNull { entry ->
            if (!lower.contains(entry.match)) return@firstOrNull false
            val floor = entry.versionBelow ?: return@firstOrNull true
            val major = majorOf(version) ?: return@firstOrNull false
            major < floor
        }
    }

    /** Leading integer of a version string, or null if there isn't one. */
    fun majorOf(version: String?): Int? =
        version?.trimStart()?.takeWhile { it.isDigit() }?.takeIf { it.isNotEmpty() }?.toIntOrNull()
}
