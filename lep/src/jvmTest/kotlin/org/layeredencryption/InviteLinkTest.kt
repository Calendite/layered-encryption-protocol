package org.layeredencryption

import org.layeredencryption.invite.InviteLink
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class InviteLinkTest {

    @Test
    fun link_roundTripsThroughFragment() {
        val secret = ByteArray(32) { (it + 1).toByte() }
        val fingerprint = ByteArray(16) { (it * 3).toByte() }
        val fragment = InviteLink(secret, fingerprint).fragment()

        val parsed = InviteLink.parse(fragment) ?: error("should parse")
        assertContentEquals(secret, parsed.secret)
        assertContentEquals(fingerprint, parsed.fingerprint)
    }

    @Test
    fun link_canonicalExampleIsStable() {
        // 32 + 16 zero bytes → all-'A' base64url; 43-char secret, 22-char fingerprint.
        val fragment = InviteLink(ByteArray(32), ByteArray(16)).fragment()
        assertEquals("A2.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA", fragment)
        assertEquals(
            "https://calendite.com/join#A2.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA",
            InviteLink(ByteArray(32), ByteArray(16)).url(),
        )
    }

    @Test
    fun link_parsesFromAFullUrl() {
        val url = InviteLink(ByteArray(32) { it.toByte() }, ByteArray(16) { it.toByte() }).url()
        assertContentEquals(ByteArray(32) { it.toByte() }, InviteLink.parse(url)?.secret)
    }

    @Test
    fun link_strictParseRejectsMalformed() {
        val secret43 = "A".repeat(43)
        assertNull(InviteLink.parse("B1.$secret43.AAAAAAAAAAAAAAAAAAAAAA"), "wrong tag")
        assertNull(InviteLink.parse("A2.$secret43"), "too few fields")
        assertNull(InviteLink.parse("A2.$secret43.AAAAAAAAAAAAAAAAAAAAAA.extra"), "too many fields")
        assertNull(InviteLink.parse("A2.${"A".repeat(42)}.AAAAAAAAAAAAAAAAAAAAAA"), "secret decodes to 31 bytes, not 32")
        assertNull(InviteLink.parse("A2.$secret43=.AAAAAAAAAAAAAAAAAAAAAA"), "padding not allowed")
    }

    @Test
    fun link_rejectsLegacyA1Format() {
        // A1 carried an 8-byte secret; rid_async gave the relay an offline 64-bit verifier for it
        // (LEP-01). A1 links must be regenerated, never honoured.
        assertNull(InviteLink.parse("A1.AAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA"), "legacy A1 link")
        assertNull(InviteLink.parse("A1.${"A".repeat(43)}.AAAAAAAAAAAAAAAAAAAAAA"), "A1 tag with a long secret")
    }
}
