package org.layeredencryption.diagnostics

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The taxonomy's contract: a **total partition** — all 1,114,112 code points, each in exactly one
 * class, verified by brute force on every platform (this file is commonTest, so the identical
 * sweep runs on the JVM, on Android, and in a real browser for Wasm). The pinned version and
 * counts make an accidental regeneration against a different Unicode version loud.
 */
class CharacterTaxonomyTest {

    @Test
    fun theTaxonomyIsPinnedToItsUnicodeVersion() {
        assertEquals("17.0.0", UnicodeTables.UNICODE_VERSION)
        assertEquals(159_801, UnicodeTables.ASSIGNED_CHARACTERS, "the official Unicode 17.0 character count")
        assertEquals(0x110000, UnicodeTables.CODE_POINT_COUNT)
    }

    @Test
    fun everyCodePointHasExactlyOneClass() {
        val census = IntArray(CharacterClass.entries.size)
        for (cp in 0 until UnicodeTables.CODE_POINT_COUNT) {
            val payload = UnicodeTables.payloadOf(cp)
            assertTrue(payload >= 0, "U+${cp.toString(16).uppercase()} is unclassified")
            census[payload and 0x3F]++
        }
        assertEquals(UnicodeTables.CODE_POINT_COUNT, census.sum(), "the partition is total")
        assertEquals(0, census[CharacterClass.OTHER.ordinal], "nothing may fall through to OTHER")
    }

    @Test
    fun theSpecExactClassesHaveTheirSpecExactPopulations() {
        val census = IntArray(CharacterClass.entries.size)
        for (cp in 0 until UnicodeTables.CODE_POINT_COUNT) {
            census[UnicodeTables.payloadOf(cp) and 0x3F]++
        }
        fun population(clazz: CharacterClass) = census[clazz.ordinal]

        assertEquals(2048, population(CharacterClass.SURROGATE), "U+D800..U+DFFF")
        assertEquals(66, population(CharacterClass.NONCHARACTER), "32 in Arabic block + 2 per plane")
        assertEquals(1, population(CharacterClass.REPLACEMENT_CHARACTER))
        assertEquals(26, population(CharacterClass.REGIONAL_INDICATOR))
        assertEquals(6400 + 65534 + 65534, population(CharacterClass.PRIVATE_USE), "BMP PUA + planes 15/16")
        // 65 Cc controls total, but tab/LF/VT/FF/CR live in ASCII_WHITESPACE by design — a log
        // fingerprint should say "contains newlines" as whitespace, not as control characters.
        assertEquals(60, population(CharacterClass.C0_CONTROL) + population(CharacterClass.C1_CONTROL))
        assertEquals(6, population(CharacterClass.ASCII_WHITESPACE), "space, tab, LF, VT, FF, CR")
    }

    // ── The sequence grammar, one case per row of the schema ────────────────────────────────

    private fun profile(text: String) = CharacterProfile.of(text)

    @Test
    fun emojiSequencesAreRecognisedStructurally() {
        assertTrue(profile("👍🏽").has(SequenceFeature.MODIFIER_SEQUENCE), "thumbs up + skin tone")
        assertTrue(profile("👩‍💻").has(SequenceFeature.ZWJ_SEQUENCE), "woman technologist")
        val family = "👨‍👩‍👧‍👦"
        assertTrue(profile(family).has(SequenceFeature.MULTI_ZWJ_SEQUENCE), "family is a multi-ZWJ composition")
        assertTrue(profile("🇬🇧").has(SequenceFeature.FLAG_SEQUENCE), "GB flag")
        assertTrue(profile("1️⃣").has(SequenceFeature.KEYCAP_SEQUENCE), "keycap one")
        assertTrue(profile("❤️").has(SequenceFeature.VS16_SEQUENCE), "heart with emoji presentation")
        assertTrue(profile("❤︎").has(SequenceFeature.VS15_SEQUENCE), "heart with text presentation")
        assertTrue(profile("❤").has(SequenceFeature.EMOJI_TEXT_DEFAULT), "bare heart defaults to text")
        val scotland = "🏴󠁧󠁢󠁳󠁣󠁴󠁿"
        assertTrue(profile(scotland).has(SequenceFeature.TAG_SEQUENCE), "subdivision flag via tag characters")
        val runner = "🏃‍♀️"
        assertTrue(profile(runner).has(SequenceFeature.GENDER_SEQUENCE), "woman running is a gendered ZWJ sequence")
        val redHair = "👨‍🦰"
        assertTrue(profile(redHair).has(SequenceFeature.HAIR_SEQUENCE), "red-haired man uses a hair component")
    }

    @Test
    fun brokenEmojiSequencesAreCalledBroken() {
        assertTrue(profile("🏻").has(SequenceFeature.BROKEN_EMOJI_SEQUENCE), "a skin tone with nothing to modify")
        assertTrue(profile("🇬").has(SequenceFeature.BROKEN_EMOJI_SEQUENCE), "an odd regional indicator")
        assertTrue(profile("😀‍").has(SequenceFeature.BROKEN_EMOJI_SEQUENCE), "a dangling ZWJ")
        assertTrue(profile("󠁧󠁢").has(SequenceFeature.BROKEN_EMOJI_SEQUENCE), "tag characters with no flag base")
        // And the well-formed versions are not smeared by the detector.
        assertFalse(profile("👍🏽").has(SequenceFeature.BROKEN_EMOJI_SEQUENCE))
        assertFalse(profile("🇬🇧").has(SequenceFeature.BROKEN_EMOJI_SEQUENCE))
    }

    @Test
    fun surrogatePairingIsTrackedPositionally() {
        val paired = profile("😀") // 😀
        assertTrue(paired.has(SequenceFeature.UTF16_SURROGATE_PAIR))
        assertFalse(paired.has(SequenceFeature.UNPAIRED_HIGH_SURROGATE))

        val loneHigh = profile("cal\uD800")
        assertTrue(loneHigh.has(SequenceFeature.UNPAIRED_HIGH_SURROGATE))
        assertTrue(loneHigh.has(CharacterClass.SURROGATE))

        val loneLow = profile("\uDC00cal")
        assertTrue(loneLow.has(SequenceFeature.UNPAIRED_LOW_SURROGATE))
    }

    @Test
    fun widthScriptAndNormalizationSignalsArePresent() {
        val mixed = profile("pа") // Latin p + Cyrillic а: the classic confusable pair
        assertTrue(mixed.has(SequenceFeature.MIXED_SCRIPTS))
        assertTrue(mixed.has(SequenceFeature.UTF8_2BYTE))

        assertTrue(profile("日").has(SequenceFeature.UTF8_3BYTE))
        assertTrue(profile("😀").has(SequenceFeature.UTF8_4BYTE))
        assertTrue(profile("é").has(CharacterClass.COMBINING_MARK), "NFD é carries a combining acute")
        assertTrue(profile("é").has(CharFlag.NORMALIZATION_SENSITIVE))
        assertTrue(profile("é").has(CharFlag.NORMALIZATION_SENSITIVE), "NFC é decomposes, so it participates too")
        assertTrue(profile("ﬁ").has(CharFlag.COMPATIBILITY), "the fi ligature changes under NFKC")
        assertTrue(profile(" ").has(CharFlag.WHITE_SPACE), "NBSP is whitespace without being ASCII")
        assertTrue(profile("‮").has(CharacterClass.BIDI_CONTROL), "the RTL override is its own diagnostic class")
    }

    @Test
    fun theLogRenderingNeverContainsTheInput() {
        val private = "Толя's 40th 🎂 @ Anna's"
        val rendered = profile(private).renderForLog()

        // Content must not survive into the fingerprint: no word, name, number or emoji of the
        // input appears. (Single ASCII letters legitimately occur inside feature *names*, so the
        // check is for the input's substance, not its alphabet.)
        for (token in listOf("Толя", "Anna", "40", "🎂", "'s", "@")) {
            assertFalse(rendered.contains(token), "the log form must not leak '$token', got: $rendered")
        }
        for (char in private.filter { it.code > 0x7F }) {
            assertFalse(rendered.contains(char), "no non-ASCII content character may leak")
        }
        assertTrue(rendered.startsWith("chars(9-32)"), "coarse length bucket only, got: $rendered")

        val names = rendered.substringAfter('{').substringBefore('}').split(", ").toSet()
        assertTrue("ascii_letters" in names)
        assertTrue("letters" in names, "Cyrillic surfaces as an unnamed letter class, not as Cyrillic text")
        assertTrue("ascii_digits" in names, "the digits in '40th' surface as a class name only")
        assertTrue("emoji" in names)
    }
}
