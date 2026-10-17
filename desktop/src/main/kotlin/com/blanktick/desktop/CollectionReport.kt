package com.blanktick.desktop

import com.blanktick.core.model.DesktopFacts

/**
 * The single source of truth for how a scan's *completeness* is reported, shared
 * by the GUI (`AppState`/`Dashboard`) and the CLI (`Main`).
 *
 * It used to live only in `AppState`, and the CLI reimplemented a narrower
 * version inline — so the identical scan could show a full score in `--cli` and
 * "No score this time" in the GUI. Both now call [scoreWithheld], so they always
 * agree.
 *
 * The model, unchanged: [caveats] are incompletenesses that WITHHOLD the score
 * (a score is deductions from 100, and a partial scan under-deducts); [notes]
 * are bounded, named gaps where the score still stands.
 */
object CollectionReport {

    /**
     * Why this report may be incomplete, in plain language. Empty when the
     * collection ran end to end. A non-empty list withholds the score.
     */
    fun caveats(d: DesktopFacts?): List<String> = buildList {
        if (d == null) return@buildList
        if (d.collectionCompleted == false) {
            add(
                "The system probe did not run to the end, so this report covers only what it " +
                    "reached before stopping. Anything it never asked about is shown as not " +
                    "checked rather than as a pass."
            )
        }
        if (d.collectionTruncated == true) {
            add(
                "The probe produced more output than Blanktick reads in one pass and was cut short. " +
                    "The checks asked last are the ones missing."
            )
        }
        d.autoRunSourcesUnread?.takeIf { it.isNotEmpty() }?.let { unread ->
            add(
                "Programs that start themselves were read from every place except " +
                    unread.joinToString(", ") + ". Those may hold entries not listed here."
            )
        }
        if (d.probeLanguageMode != null && !d.probeLanguageMode.equals("FullLanguage", true)) {
            add(
                "PowerShell is restricted to " + d.probeLanguageMode + " on this computer, which " +
                    "blocks some of the queries Blanktick uses. The affected checks report as not " +
                    "checked."
            )
        }
    }

    /**
     * Bounded, named gaps that do NOT make the scan incomplete — shown on screen,
     * but the score stands. See [DesktopFacts.autoRunKeysUnread].
     */
    fun notes(d: DesktopFacts?): List<String> = buildList {
        val keys = d?.autoRunKeysUnread?.takeIf { it.isNotEmpty() } ?: return@buildList
        add(
            "Windows would not let a normal user open " +
                (if (keys.size == 1) "one registry key" else "${keys.size} registry keys") +
                " where programs can be set to start: " + keys.joinToString(", ") + ". " +
                "Everything else in those places was read. A hijack could hide in a key that " +
                "cannot be opened, so it is named here rather than counted as clean; running " +
                "Blanktick as administrator would read it."
        )
    }

    /**
     * The one threshold: the score is withheld exactly when there is a
     * score-invalidating caveat. Both surfaces use this, so they cannot drift.
     */
    fun scoreWithheld(d: DesktopFacts?): Boolean = caveats(d).isNotEmpty()
}
