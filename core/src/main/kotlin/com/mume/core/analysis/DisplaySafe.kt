package com.mume.core.analysis

/**
 * Neutralises text that renders as something other than what it is.
 *
 * ## The attack
 *
 * Almost every name Mume puts on screen was chosen by whoever installed the
 * thing being named: a program's `DisplayName`, a Run-key value name, a
 * scheduled task's name, a certificate subject, an Android app's label. That is
 * attacker-controlled text, and it is being shown to a person who is about to
 * decide whether to trust it.
 *
 * Unicode has characters whose only job is to change how the characters around
 * them are displayed. `U+202E RIGHT-TO-LEFT OVERRIDE` reverses everything after
 * it, so the eight bytes `exe.txt` preceded by an override render as `txt.exe`.
 * The zero-width characters are worse in a different way: `Micro<ZWSP>soft`
 * looks exactly like `Microsoft` and compares equal to nothing.
 *
 * In an ordinary application that is a curiosity. In a security scanner it is
 * the whole game — the app's output *is* the user's evidence, and a finding that
 * reads "Microsoft Corporation" when the string is not that is worse than no
 * finding, because the user acted on it.
 *
 * ## What this does about it
 *
 * Strips the characters and says that it did. Silently removing them would fix
 * the spoof and hide the fact that someone tried, and "this name contains
 * hidden characters" is itself one of the more interesting things Mume can tell
 * you about a program.
 *
 * Deliberately **not** a homoglyph check. `Micrоsoft` with a Cyrillic о is a
 * different problem with a different false-positive profile, it is handled for
 * domain names by [Confusables], and applying that judgement to every program
 * name on a machine would flag legitimate non-English software. This class only
 * removes characters that have no business in a displayed name at all.
 */
object DisplaySafe {

    /**
     * Characters that alter the rendering of their neighbours, or are invisible.
     *
     * - `U+00AD` soft hyphen — invisible, breaks string matching
     * - `U+061C` Arabic letter mark
     * - `U+200B`–`U+200F` zero-width space/non-joiner/joiner, LTR/RTL marks
     * - `U+202A`–`U+202E` the embedding and override family, including RLO
     * - `U+2066`–`U+2069` the isolate family
     * - `U+FEFF` zero-width no-break space (byte-order mark)
     */
    private fun isHidden(c: Char): Boolean = when (val cp = c.code) {
        0x00AD, 0x061C, 0xFEFF -> true
        in 0x200B..0x200F -> true
        in 0x202A..0x202E -> true
        in 0x2066..0x2069 -> true
        // C0 and C1 control characters. Tab, CR and LF are included: they are
        // structural in the probe's output format and meaningless in a name.
        else -> cp < 0x20 || cp in 0x7F..0x9F
    }

    data class Result(
        /** Safe to render. Never contains a character that moves its neighbours. */
        val text: String,
        /** True when something was removed, which is worth telling the user. */
        val hadHiddenCharacters: Boolean
    )

    fun inspect(raw: String): Result {
        if (raw.none { isHidden(it) }) return Result(raw, false)
        return Result(raw.filterNot { isHidden(it) }, true)
    }

    /**
     * The common case: a name to display, marked if it was tampered with.
     *
     * The marker is plain language rather than a symbol because it appears
     * beside a program name in a list a non-expert is reading, and "⚠" tells
     * them nothing they can act on.
     */
    fun label(raw: String): String {
        val r = inspect(raw)
        return if (r.hadHiddenCharacters) r.text + " (name contains hidden characters)" else r.text
    }
}
