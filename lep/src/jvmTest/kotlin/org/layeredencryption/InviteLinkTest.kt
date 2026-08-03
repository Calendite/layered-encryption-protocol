package org.layeredencryption

import org.layeredencryption.invite.InviteLink
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class InviteLinkTest {

    @Test
    fun link_roundTripsThroughFragment() {
        val secret = ByteArray(8) { (it + 1).toByte() }
        val fingerprint = ByteArray(16) { (it * 3).toByte() }
        val fragment = InviteLink(secret, fingerprint).fragment()

        val parsed = InviteLink.parse(fragment) ?: error("should parse")
        assertContentEquals(secret, parsed.secret)
        assertContentEquals(fingerprint, parsed.fingerprint)
    }

    @Test
    fun link_canonicalExampleIsStable() {
        // 8 + 16 zero bytes → all-'A' base64url; 11-char secret, 22-char fingerprint.
        val fragment = InviteLink(ByteArray(8), ByteArray(16)).fragment()
        assertEquals("A1.AAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA", fragment)
        assertEquals("https://calendite.com/join#A1.AAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA", InviteLink(ByteArray(8), ByteArray(16)).url())
    }

    @Test
    fun link_parsesFromAFullUrl() {
        val url = InviteLink(ByteArray(8) { it.toByte() }, ByteArray(16) { it.toByte() }).url()
        assertContentEquals(ByteArray(8) { it.toByte() }, InviteLink.parse(url)?.secret)
    }

    @Test
    fun link_strictParseRejectsMalformed() {
        assertNull(InviteLink.parse("B1.AAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA"), "wrong tag")
        assertNull(InviteLink.parse("A1.AAAAAAAAAAA"), "too few fields")
        assertNull(InviteLink.parse("A1.AAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.extra"), "too many fields")
        assertNull(InviteLink.parse("A1.AAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA"), "secret decodes to 7 bytes, not 8")
        assertNull(InviteLink.parse("A1.AAAAAAAAAAA=.AAAAAAAAAAAAAAAAAAAAAA"), "padding not allowed")
    }
}
