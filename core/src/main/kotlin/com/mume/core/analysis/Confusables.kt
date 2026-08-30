package com.mume.core.analysis

/**
 * Unicode script classification and confusable folding.
 *
 * ## What this catches
 *
 * Two related attacks, both entirely detectable offline:
 *
 * 1. **Whole-script confusables.** Every character of `раураl.com` is Cyrillic.
 *    The label mixes no scripts, so a naive "mixed script" check misses it, but
 *    folding each character to its Latin lookalike yields the skeleton
 *    `paypal`, which matches a brand exactly.
 * 2. **Mixed-script labels.** `pаypal` with a single Cyrillic `а` among Latin
 *    letters. Legitimate domains essentially never mix Latin with Cyrillic or
 *    Greek inside one label.
 *
 * The confusable table below is a hand-picked subset of the Unicode
 * `confusables.txt` mapping, covering the characters that actually appear in
 * observed homoglyph phishing — Cyrillic and Greek lookalikes, full-width Latin,
 * and the handful of Latin-extended characters used to fake ASCII. A complete
 * table is roughly 6,000 entries; carrying all of it would add ~100 KB for
 * negligible additional coverage of real attacks.
 */
object Confusables {

    enum class Script { LATIN, CYRILLIC, GREEK, ARMENIAN, HEBREW, ARABIC, CJK, COMMON, OTHER }

    /**
     * Maps a confusable code point to the ASCII character it imitates.
     *
     * Keys are stored as `Int` code points so that characters outside the BMP
     * (mathematical alphanumerics, for instance) can be represented.
     */
    private val FOLD: Map<Int, Char> = buildMap {
        // ---- Cyrillic lookalikes -----------------------------------------
        put(0x0430, 'a'); put(0x0410, 'a')   // а А
        put(0x0432, 'b'); put(0x0412, 'b')   // в В  (visually 'B')
        put(0x0441, 'c'); put(0x0421, 'c')   // с С
        put(0x0435, 'e'); put(0x0415, 'e')   // е Е
        put(0x0440, 'p'); put(0x0420, 'p')   // р Р
        put(0x0445, 'x'); put(0x0425, 'x')   // х Х
        put(0x0443, 'y'); put(0x0423, 'y')   // у У
        put(0x043E, 'o'); put(0x041E, 'o')   // о О
        put(0x0456, 'i'); put(0x0406, 'i')   // і І
        put(0x0458, 'j'); put(0x0408, 'j')   // ј Ј
        put(0x0455, 's'); put(0x0405, 's')   // ѕ Ѕ
        put(0x043A, 'k'); put(0x041A, 'k')   // к К
        put(0x043C, 'm'); put(0x041C, 'm')   // м М
        put(0x043D, 'h'); put(0x041D, 'h')   // н Н
        put(0x0442, 't'); put(0x0422, 't')   // т Т
        put(0x0433, 'r')                     // г
        put(0x04CF, 'l')                     // ӏ
        put(0x0499, 'z')                     // ҙ

        // ---- Greek lookalikes ---------------------------------------------
        put(0x03B1, 'a'); put(0x0391, 'a')   // α Α
        put(0x03B2, 'b'); put(0x0392, 'b')   // β Β
        put(0x03B5, 'e'); put(0x0395, 'e')   // ε Ε
        put(0x03BF, 'o'); put(0x039F, 'o')   // ο Ο
        put(0x03C1, 'p'); put(0x03A1, 'p')   // ρ Ρ
        put(0x03C5, 'u')                     // υ
        put(0x03BD, 'v')                     // ν
        put(0x03C4, 't'); put(0x03A4, 't')   // τ Τ
        put(0x0397, 'h')                     // Η
        put(0x039A, 'k')                     // Κ
        put(0x039C, 'm')                     // Μ
        put(0x039D, 'n')                     // Ν
        put(0x0399, 'i')                     // Ι
        put(0x03A7, 'x')                     // Χ
        put(0x0396, 'z')                     // Ζ

        // ---- Latin-extended used to fake ASCII ----------------------------
        put(0x0131, 'i')                     // ı dotless i
        put(0x0142, 'l')                     // ł
        put(0x00E0, 'a'); put(0x00E1, 'a'); put(0x00E2, 'a'); put(0x00E3, 'a')
        put(0x00E4, 'a'); put(0x00E5, 'a')
        put(0x00E8, 'e'); put(0x00E9, 'e'); put(0x00EA, 'e'); put(0x00EB, 'e')
        put(0x00EC, 'i'); put(0x00ED, 'i'); put(0x00EE, 'i'); put(0x00EF, 'i')
        put(0x00F2, 'o'); put(0x00F3, 'o'); put(0x00F4, 'o'); put(0x00F5, 'o')
        put(0x00F6, 'o'); put(0x00F8, 'o')
        put(0x00F9, 'u'); put(0x00FA, 'u'); put(0x00FB, 'u'); put(0x00FC, 'u')
        put(0x00E7, 'c'); put(0x00F1, 'n'); put(0x00FD, 'y'); put(0x00FF, 'y')

        // ---- Digit / letter shape collisions ------------------------------
        // Deliberately NOT folded: '0'->'o' and '1'->'l' produce far too many
        // false matches against ordinary domains that contain digits.

        // ---- Full-width Latin (U+FF41..U+FF5A, U+FF21..U+FF3A) ------------
        for (c in 'a'..'z') put(0xFF41 + (c - 'a'), c)
        for (c in 'a'..'z') put(0xFF21 + (c - 'a'), c)
    }

    fun scriptOf(codePoint: Int): Script = when (codePoint) {
        in 0x0041..0x005A, in 0x0061..0x007A -> Script.LATIN
        in 0x00C0..0x024F -> Script.LATIN
        in 0x0030..0x0039, 0x002D, 0x002E, 0x005F -> Script.COMMON
        in 0x0370..0x03FF, in 0x1F00..0x1FFF -> Script.GREEK
        in 0x0400..0x04FF, in 0x0500..0x052F -> Script.CYRILLIC
        in 0x0530..0x058F -> Script.ARMENIAN
        in 0x0590..0x05FF -> Script.HEBREW
        in 0x0600..0x06FF, in 0x0750..0x077F -> Script.ARABIC
        in 0x2E80..0x9FFF, in 0xAC00..0xD7AF, in 0x3040..0x30FF -> Script.CJK
        in 0xFF21..0xFF3A, in 0xFF41..0xFF5A -> Script.LATIN
        else -> Script.OTHER
    }

    /**
     * Folds a label to its ASCII "skeleton" for comparison against brand names.
     *
     * Characters with no mapping are kept as-is, lowercased. The result is only
     * meaningful when compared against another skeleton or an ASCII brand.
     */
    fun skeleton(label: String): String {
        val sb = StringBuilder(label.length)
        var i = 0
        while (i < label.length) {
            val cp = label.codePointAt(i)
            val folded = FOLD[cp]
            if (folded != null) {
                sb.append(folded)
            } else {
                sb.appendCodePoint(Character.toLowerCase(cp))
            }
            i += Character.charCount(cp)
        }
        return sb.toString()
    }

    /** Scripts present in [label], ignoring [Script.COMMON]. */
    fun scriptsIn(label: String): Set<Script> {
        val scripts = mutableSetOf<Script>()
        var i = 0
        while (i < label.length) {
            val cp = label.codePointAt(i)
            val s = scriptOf(cp)
            if (s != Script.COMMON) scripts.add(s)
            i += Character.charCount(cp)
        }
        return scripts
    }

    /**
     * True when a label mixes scripts in a way that essentially never occurs in
     * a legitimate domain.
     *
     * Note what is deliberately *not* flagged: a label that is entirely Cyrillic,
     * or entirely Greek, or entirely CJK. Those are ordinary domains in most of
     * the world, and flagging them would make Mume useless outside the Latin
     * alphabet — a failure mode worth naming explicitly, because plenty of
     * "security" tools have shipped exactly that bias. Whole-script imitation is
     * caught by the skeleton comparison instead, which needs a brand match and
     * therefore does not fire on ordinary non-Latin domains.
     */
    fun hasSuspiciousScriptMix(label: String): Boolean {
        val scripts = scriptsIn(label)
        if (scripts.size < 2) return false
        // Latin combined with a lookalike script is the actual attack shape.
        val confusableWithLatin = setOf(Script.CYRILLIC, Script.GREEK, Script.ARMENIAN)
        if (Script.LATIN in scripts && scripts.any { it in confusableWithLatin }) return true
        // Cyrillic + Greek together is likewise not a real language.
        return Script.CYRILLIC in scripts && Script.GREEK in scripts
    }

    fun isPureAscii(s: String): Boolean = s.all { it.code < 0x80 }
}
