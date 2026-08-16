package org.layeredencryption.diagnostics

/**
 * The Layer-1 character taxonomy: a **total partition** — every one of the 1,114,112 code points
 * belongs to exactly one class, which the taxonomy tests verify by brute force. Ordinals must
 * match `tools/generate-unicode-tables.py`, which generates the backing tables from a pinned
 * Unicode version.
 *
 * The partition powers two things that must never drift apart: the character-set sweep tests
 * (each class is a sweep group), and the privacy-preserving log fingerprints ([CharacterProfile])
 * that report *which kinds* of characters a string contained without reporting the string.
 */
enum class CharacterClass(val logName: String) {
    ASCII_LETTER("ascii_letters"),
    ASCII_DIGIT("ascii_digits"),
    ASCII_PUNCTUATION("ascii_punctuation"),
    ASCII_WHITESPACE("ascii_whitespace"),
    C0_CONTROL("c0_controls"),
    C1_CONTROL("c1_controls"),
    SURROGATE("surrogates"),
    NONCHARACTER("noncharacters"),
    REPLACEMENT_CHARACTER("replacement_char"),
    PRIVATE_USE("private_use"),
    UNASSIGNED("unassigned"),
    REGIONAL_INDICATOR("regional_indicator"),
    TAG_CHARACTER("emoji_tag_characters"),
    VARIATION_SELECTOR("variation_selectors"),
    BIDI_CONTROL("bidi_controls"),
    FORMAT("format_chars"),
    SEPARATOR("separators"),
    COMBINING_MARK("combining_marks"),
    EMOJI_PRESENTATION("emoji_basic"),
    PICTOGRAPHIC("pictographic"),
    LETTER("letters"),
    NUMBER("numbers"),
    PUNCTUATION("punctuation"),
    SYMBOL("symbols"),
    OTHER("other"),
}

/** Layer-2 overlay flags: non-exclusive per-code-point properties. Bits match the generator. */
enum class CharFlag(internal val bit: Int, val logName: String) {
    EMOJI(1 shl 0, "emoji"),
    EMOJI_PRESENTATION(1 shl 1, "emoji_presentation"),
    EMOJI_MODIFIER(1 shl 2, "emoji_modifier"),
    EMOJI_MODIFIER_BASE(1 shl 3, "emoji_modifier_base"),
    EMOJI_COMPONENT(1 shl 4, "emoji_component"),
    EXTENDED_PICTOGRAPHIC(1 shl 5, "extended_pictographic"),
    COMPATIBILITY(1 shl 6, "compatibility_chars"),
    NORMALIZATION_SENSITIVE(1 shl 7, "normalization_sensitive"),
    WHITE_SPACE(1 shl 8, "unicode_whitespace"),
}

/**
 * Layer-3 features: properties of *sequences*, not characters — detected by a single structural
 * pass, deliberately grammar-based rather than checked against the RGI emoji registry (which
 * changes yearly and answers "does a vendor ship this glyph", not "does this stress our code").
 */
enum class SequenceFeature(val logName: String) {
    UTF16_SURROGATE_PAIR("utf16_surrogate_pair"),
    UNPAIRED_HIGH_SURROGATE("unpaired_high_surrogate"),
    UNPAIRED_LOW_SURROGATE("unpaired_low_surrogate"),
    NON_BMP("non_bmp"),
    UTF8_2BYTE("utf8_2byte"),
    UTF8_3BYTE("utf8_3byte"),
    UTF8_4BYTE("utf8_4byte"),
    EMOJI_TEXT_DEFAULT("emoji_text_default"),
    EMOJI_BMP("emoji_bmp"),
    EMOJI_NON_BMP("emoji_non_bmp"),
    VS16_SEQUENCE("emoji_vs16_sequence"),
    VS15_SEQUENCE("emoji_vs15_sequence"),
    MODIFIER_SEQUENCE("emoji_modifier_sequence"),
    ZWJ_SEQUENCE("emoji_zwj_sequence"),
    MULTI_ZWJ_SEQUENCE("emoji_multi_zwj_sequence"),
    FLAG_SEQUENCE("emoji_flag_sequence"),
    TAG_SEQUENCE("emoji_tag_sequence"),
    KEYCAP_SEQUENCE("emoji_keycap_sequence"),
    GENDER_SEQUENCE("emoji_gender_sequence"),
    HAIR_SEQUENCE("emoji_hair_component"),
    BROKEN_EMOJI_SEQUENCE("emoji_broken_sequence"),
    MIXED_SCRIPTS("mixed_scripts"),
}

/**
 * A privacy-preserving fingerprint of a string: which character classes, flags and sequence
 * features it contained, and how much of each — never the characters themselves.
 *
 * Two renderings, deliberately different in how much they say:
 * - [renderDiagnostic] — everything, with counts. For tests and local debugging.
 * - [renderForLog] — nonzero feature names plus a coarse length bucket only. Exact counts and
 *   exact lengths narrow the space of possible strings far more than feature presence does, so
 *   the log form leans private: it answers "what *kind* of string broke" without helping
 *   reconstruct it.
 */
class CharacterProfile private constructor(
    val codePoints: Int,
    val utf16Units: Int,
    val utf8Bytes: Int,
    val classes: Map<CharacterClass, Int>,
    val flags: Map<CharFlag, Int>,
    val sequences: Map<SequenceFeature, Int>,
) {

    fun has(clazz: CharacterClass): Boolean = (classes[clazz] ?: 0) > 0
    fun has(flag: CharFlag): Boolean = (flags[flag] ?: 0) > 0
    fun has(feature: SequenceFeature): Boolean = (sequences[feature] ?: 0) > 0

    /** Every nonzero feature name, sorted — the shared vocabulary of both renderings. */
    private fun presentNames(): List<String> = buildList {
        classes.forEach { (clazz, n) -> if (n > 0) add(clazz.logName) }
        flags.forEach { (flag, n) -> if (n > 0) add(flag.logName) }
        sequences.forEach { (feature, n) -> if (n > 0) add(feature.logName) }
    }.sorted()

    fun renderDiagnostic(): String {
        val parts = buildList {
            add("codePoints=$codePoints")
            add("utf16=$utf16Units")
            add("utf8=$utf8Bytes")
            classes.forEach { (clazz, n) -> if (n > 0) add("${clazz.logName}=$n") }
            flags.forEach { (flag, n) -> if (n > 0) add("${flag.logName}=$n") }
            sequences.forEach { (feature, n) -> if (n > 0) add("${feature.logName}=$n") }
        }
        return parts.joinToString(" ")
    }

    fun renderForLog(): String {
        val bucket = when {
            codePoints == 0 -> "empty"
            codePoints <= 8 -> "1-8"
            codePoints <= 32 -> "9-32"
            codePoints <= 128 -> "33-128"
            else -> "129+"
        }
        return "chars($bucket){${presentNames().joinToString(", ")}}"
    }

    companion object {

        private const val ZWJ = 0x200D
        private const val VS15 = 0xFE0E
        private const val VS16 = 0xFE0F
        private const val KEYCAP = 0x20E3
        private const val BLACK_FLAG = 0x1F3F4
        private const val TAG_TERMINATOR = 0xE007F
        private val GENDER_SIGNS = setOf(0x2640, 0x2642)
        private val HAIR_COMPONENTS = 0x1F9B0..0x1F9B3
        private val KEYCAP_BASES = (('0'.code)..('9'.code)).toSet() + '#'.code + '*'.code

        fun of(text: String): CharacterProfile {
            val classes = HashMap<CharacterClass, Int>()
            val flags = HashMap<CharFlag, Int>()
            val sequences = HashMap<SequenceFeature, Int>()
            fun bump(map: HashMap<CharacterClass, Int>, key: CharacterClass) = map.put(key, (map[key] ?: 0) + 1)
            fun bumpFlag(key: CharFlag) = flags.put(key, (flags[key] ?: 0) + 1)
            fun bumpSeq(key: SequenceFeature) = sequences.put(key, (sequences[key] ?: 0) + 1)

            // Pass 1: decode UTF-16 units into code points, catching unpaired surrogates —
            // which Kotlin strings can hold but UTF-8 cannot represent.
            val codePoints = ArrayList<Int>(text.length)
            var i = 0
            while (i < text.length) {
                val unit = text[i]
                when {
                    unit.isHighSurrogate() && i + 1 < text.length && text[i + 1].isLowSurrogate() -> {
                        codePoints += ((unit.code - 0xD800) shl 10) + (text[i + 1].code - 0xDC00) + 0x10000
                        bumpSeq(SequenceFeature.UTF16_SURROGATE_PAIR)
                        i += 2
                    }
                    unit.isHighSurrogate() -> {
                        codePoints += unit.code
                        bumpSeq(SequenceFeature.UNPAIRED_HIGH_SURROGATE)
                        i++
                    }
                    unit.isLowSurrogate() -> {
                        codePoints += unit.code
                        bumpSeq(SequenceFeature.UNPAIRED_LOW_SURROGATE)
                        i++
                    }
                    else -> {
                        codePoints += unit.code
                        i++
                    }
                }
            }

            // Pass 2: per-code-point classes and flags.
            var utf8Bytes = 0
            val scriptsSeen = HashSet<Int>()
            val payloads = IntArray(codePoints.size)
            for (index in codePoints.indices) {
                val cp = codePoints[index]
                val payload = UnicodeTables.payloadOf(cp)
                payloads[index] = payload
                bump(classes, CharacterClass.entries[payload and 0x3F])
                val flagBits = payload shr 6
                for (flag in CharFlag.entries) {
                    if (flagBits and flag.bit != 0) bumpFlag(flag)
                }
                val width = when {
                    cp < 0x80 -> 1
                    cp < 0x800 -> 2
                    cp in 0xD800..0xDFFF -> 3 // encoders substitute U+FFFD, itself 3 bytes
                    cp < 0x10000 -> 3
                    else -> 4
                }
                utf8Bytes += width
                when (width) {
                    2 -> bumpSeq(SequenceFeature.UTF8_2BYTE)
                    3 -> bumpSeq(SequenceFeature.UTF8_3BYTE)
                    4 -> bumpSeq(SequenceFeature.UTF8_4BYTE)
                }
                if (cp > 0xFFFF) bumpSeq(SequenceFeature.NON_BMP)
                if (flagBits and CharFlag.EMOJI.bit != 0) {
                    bumpSeq(if (cp > 0xFFFF) SequenceFeature.EMOJI_NON_BMP else SequenceFeature.EMOJI_BMP)
                    if (flagBits and CharFlag.EMOJI_PRESENTATION.bit == 0) bumpSeq(SequenceFeature.EMOJI_TEXT_DEFAULT)
                }
                val script = UnicodeTables.scriptOf(cp)
                if (script > 2) scriptsSeen += script // ignore Common/Inherited/Unknown
            }
            if (scriptsSeen.size > 1) sequences[SequenceFeature.MIXED_SCRIPTS] = scriptsSeen.size

            // Pass 3: the sequence grammar.
            fun isEmoji(index: Int) = index in codePoints.indices && (payloads[index] shr 6) and CharFlag.EMOJI.bit != 0
            fun isModifier(index: Int) = index in codePoints.indices && (payloads[index] shr 6) and CharFlag.EMOJI_MODIFIER.bit != 0
            fun isModifierBase(index: Int) = index in codePoints.indices && (payloads[index] shr 6) and CharFlag.EMOJI_MODIFIER_BASE.bit != 0
            fun isRegionalIndicator(index: Int) = index in codePoints.indices && cpClass(payloads[index]) == CharacterClass.REGIONAL_INDICATOR
            fun isTag(index: Int) = index in codePoints.indices && cpClass(payloads[index]) == CharacterClass.TAG_CHARACTER

            var index = 0
            while (index < codePoints.size) {
                val cp = codePoints[index]
                when {
                    // Keycap: base (+ optional VS16) + U+20E3.
                    cp in KEYCAP_BASES &&
                        (nextIs(codePoints, index + 1, KEYCAP) ||
                            (nextIs(codePoints, index + 1, VS16) && nextIs(codePoints, index + 2, KEYCAP))) -> {
                        bumpSeq(SequenceFeature.KEYCAP_SEQUENCE)
                        index += if (nextIs(codePoints, index + 1, KEYCAP)) 2 else 3
                    }

                    // Flags: regional indicators pair up; an odd one out is a broken sequence.
                    isRegionalIndicator(index) -> {
                        if (isRegionalIndicator(index + 1)) {
                            bumpSeq(SequenceFeature.FLAG_SEQUENCE)
                            index += 2
                        } else {
                            bumpSeq(SequenceFeature.BROKEN_EMOJI_SEQUENCE)
                            index++
                        }
                    }

                    // Tag sequences: black flag + tag characters + tag terminator.
                    cp == BLACK_FLAG && isTag(index + 1) -> {
                        var end = index + 1
                        while (isTag(end) && codePoints[end] != TAG_TERMINATOR) end++
                        if (codePoints.getOrNull(end) == TAG_TERMINATOR) {
                            bumpSeq(SequenceFeature.TAG_SEQUENCE)
                            index = end + 1
                        } else {
                            bumpSeq(SequenceFeature.BROKEN_EMOJI_SEQUENCE)
                            index = end
                        }
                    }

                    // Tag characters outside a tag sequence never stand alone legitimately.
                    isTag(index) -> {
                        bumpSeq(SequenceFeature.BROKEN_EMOJI_SEQUENCE)
                        index++
                    }

                    // A skin-tone modifier with no base to modify. Checked before the general
                    // emoji branch, because modifiers carry the Emoji property themselves and
                    // would otherwise be consumed as innocent standalone units.
                    isModifier(index) -> {
                        bumpSeq(SequenceFeature.BROKEN_EMOJI_SEQUENCE)
                        index++
                    }

                    // An emoji unit: base, optional VS/modifier, optional ZWJ continuations.
                    isEmoji(index) -> {
                        var units = 0
                        var zwjJoins = 0
                        var sawGender = false
                        var sawHair = false
                        var scan = index
                        while (true) {
                            if (codePoints[scan] in GENDER_SIGNS) sawGender = true
                            var next = scan + 1
                            when {
                                nextIs(codePoints, next, VS16) -> { bumpSeq(SequenceFeature.VS16_SEQUENCE); next++ }
                                nextIs(codePoints, next, VS15) -> { bumpSeq(SequenceFeature.VS15_SEQUENCE); next++ }
                            }
                            if (isModifier(next)) {
                                if (isModifierBase(scan)) bumpSeq(SequenceFeature.MODIFIER_SEQUENCE)
                                else bumpSeq(SequenceFeature.BROKEN_EMOJI_SEQUENCE)
                                next++
                            }
                            units++
                            if (nextIs(codePoints, next, ZWJ) && isEmoji(next + 1)) {
                                zwjJoins++
                                if (HAIR_COMPONENTS.contains(codePoints[next + 1])) sawHair = true
                                scan = next + 1
                                continue
                            }
                            if (nextIs(codePoints, next, ZWJ)) {
                                // A ZWJ that joins an emoji to nothing usable dangles.
                                bumpSeq(SequenceFeature.BROKEN_EMOJI_SEQUENCE)
                                next++
                            }
                            index = next
                            break
                        }
                        if (zwjJoins >= 1) bumpSeq(SequenceFeature.ZWJ_SEQUENCE)
                        if (zwjJoins >= 2) bumpSeq(SequenceFeature.MULTI_ZWJ_SEQUENCE)
                        if (zwjJoins >= 1 && sawGender) bumpSeq(SequenceFeature.GENDER_SEQUENCE)
                        if (sawHair) bumpSeq(SequenceFeature.HAIR_SEQUENCE)
                    }

                    else -> index++
                }
            }

            return CharacterProfile(
                codePoints = codePoints.size,
                utf16Units = text.length,
                utf8Bytes = utf8Bytes,
                classes = classes,
                flags = flags,
                sequences = sequences,
            )
        }

        private fun cpClass(payload: Int): CharacterClass = CharacterClass.entries[payload and 0x3F]

        private fun nextIs(codePoints: List<Int>, index: Int, expected: Int): Boolean =
            index < codePoints.size && codePoints[index] == expected
    }
}
