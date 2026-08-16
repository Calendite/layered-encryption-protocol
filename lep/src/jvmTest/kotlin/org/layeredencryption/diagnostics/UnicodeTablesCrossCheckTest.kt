package org.layeredencryption.diagnostics

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Cross-checks the generated tables against `java.lang.Character` — an independent Unicode
 * implementation. The JDK tracks an older Unicode version than the tables (JDK 21 ships 15.0,
 * the tables pin 17.0), so the assertions run on the intersection: everything the JDK knows,
 * the newer tables must agree with; code points the tables know and the JDK does not are
 * expected and counted, never asserted on.
 */
class UnicodeTablesCrossCheckTest {

    private fun classOf(cp: Int): CharacterClass =
        CharacterClass.entries[UnicodeTables.payloadOf(cp) and 0x3F]

    @Test
    fun everythingTheJdkKnowsIsAssignedHere() {
        var jdkDefined = 0
        for (cp in 0 until UnicodeTables.CODE_POINT_COUNT) {
            if (!Character.isDefined(cp)) continue
            jdkDefined++
            assertTrue(
                classOf(cp) != CharacterClass.UNASSIGNED,
                "U+${cp.toString(16).uppercase()} is defined in the JDK's Unicode but unassigned in ours — " +
                    "the tables can only be newer, never older",
            )
        }
        assertTrue(jdkDefined in 280_000..UnicodeTables.DESIGNATED_CODE_POINTS, "sanity: JDK saw $jdkDefined")
    }

    @Test
    fun structuralCategoriesAgreeWithTheJdkOnTheIntersection() {
        var checked = 0
        for (cp in 0 until UnicodeTables.CODE_POINT_COUNT) {
            if (!Character.isDefined(cp)) continue
            val ours = classOf(cp)
            when (Character.getType(cp).toByte()) {
                Character.SURROGATE -> assertEquals(CharacterClass.SURROGATE, ours, "U+${cp.toString(16)}")
                Character.PRIVATE_USE -> assertEquals(CharacterClass.PRIVATE_USE, ours, "U+${cp.toString(16)}")
                Character.NON_SPACING_MARK, Character.COMBINING_SPACING_MARK, Character.ENCLOSING_MARK ->
                    assertTrue(
                        ours == CharacterClass.COMBINING_MARK || ours == CharacterClass.VARIATION_SELECTOR,
                        "U+${cp.toString(16)}: a mark must be combining or a variation selector, was $ours",
                    )
                Character.SPACE_SEPARATOR, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR ->
                    assertTrue(
                        ours == CharacterClass.SEPARATOR || ours == CharacterClass.ASCII_WHITESPACE,
                        "U+${cp.toString(16)}: a separator must be SEPARATOR (or ASCII space), was $ours",
                    )
                Character.FORMAT ->
                    assertTrue(
                        ours in setOf(
                            CharacterClass.FORMAT, CharacterClass.BIDI_CONTROL,
                            CharacterClass.TAG_CHARACTER, CharacterClass.VARIATION_SELECTOR,
                        ),
                        "U+${cp.toString(16)}: a format char landed in $ours",
                    )
                else -> continue
            }
            checked++
        }
        assertTrue(checked > 3000, "sanity: the intersection exercised $checked code points")
    }
}
