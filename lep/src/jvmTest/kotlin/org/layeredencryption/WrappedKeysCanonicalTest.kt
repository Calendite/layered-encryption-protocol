package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.WrappedKeys
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Canonical wrapped-keys parsing (LEP-09 retest, issue 9.4): the whole blob is validated before
 * any decryption, so a currently-authorised malicious member cannot sign a structure that
 * different consumers would read differently — duplicates, malformed suffixes, or non-canonical
 * identifiers fail the blob even when the caller's own copy is fine.
 */
class WrappedKeysCanonicalTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()
    private val alice = DeviceKeys.generate(provider)
    private val bob = DeviceKeys.generate(provider)
    private val secret = provider.randomBytes(32)

    /** The three framed fields of a single-recipient blob, for rebuilding tampered variants. */
    private fun fieldsOf(blob: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val reader = FrameReader(blob)
        return Triple(reader.readBytes(), reader.readBytes(), reader.readBytes())
    }

    private fun blobOf(id: ByteArray, ct: ByteArray, sealed: ByteArray): ByteArray =
        FrameWriter().putBytes(id).putBytes(ct).putBytes(sealed).toByteArray()

    @Test
    fun multiRecipientBlobUnwrapsForEachRecipient() {
        val blob = WrappedKeys.wrapFor(provider, listOf(alice.identity, bob.identity), secret)
        assertContentEquals(secret, WrappedKeys.unwrapFor(provider, blob, alice))
        assertContentEquals(secret, WrappedKeys.unwrapFor(provider, blob, bob))
        assertEquals(2, WrappedKeys.recipientsOf(blob).size)
    }

    @Test
    fun malformedSuffixAfterTheCallersCopyFailsTheWholeBlob() {
        val blob = WrappedKeys.wrapFor(provider, listOf(alice.identity), secret)
        // Alice's copy is first and valid; the garbage after it must still fail the blob —
        // the earlier implementation returned success without ever looking at the suffix.
        val suffixed = blob + byteArrayOf(1, 2, 3)
        assertNull(WrappedKeys.unwrapFor(provider, suffixed, alice))
        assertTrue(WrappedKeys.recipientsOf(suffixed).isEmpty())
    }

    @Test
    fun duplicateRecipientsFailTheBlob() {
        val once = WrappedKeys.wrapFor(provider, listOf(alice.identity), secret)
        val again = WrappedKeys.wrapFor(provider, listOf(alice.identity), secret)
        val duplicated = once + again
        assertNull(WrappedKeys.unwrapFor(provider, duplicated, alice))
        assertTrue(WrappedKeys.recipientsOf(duplicated).isEmpty())
    }

    @Test
    fun nonCanonicalMemberIdentifiersFailTheBlob() {
        val (id, ct, sealed) = fieldsOf(WrappedKeys.wrapFor(provider, listOf(alice.identity), secret))

        val uppercase = id.decodeToString().uppercase().encodeToByteArray()
        assertNull(WrappedKeys.unwrapFor(provider, blobOf(uppercase, ct, sealed), alice), "uppercase hex")

        assertNull(WrappedKeys.unwrapFor(provider, blobOf(id.copyOf(id.size - 2), ct, sealed), alice), "short id")

        val invalidUtf8 = id.copyOf().also { it[0] = 0xFF.toByte() }
        assertNull(WrappedKeys.unwrapFor(provider, blobOf(invalidUtf8, ct, sealed), alice), "invalid UTF-8")

        val nonHex = id.copyOf().also { it[0] = 'g'.code.toByte() }
        assertNull(WrappedKeys.unwrapFor(provider, blobOf(nonHex, ct, sealed), alice), "non-hex character")
    }

    @Test
    fun everyCopyIsValidatedNotJustTheCallers() {
        // A wrong-size KEM ciphertext in *another member's* copy fails the blob, even though the
        // caller's own copy is untouched and would open.
        val (bobId, bobCt, bobSealed) = fieldsOf(WrappedKeys.wrapFor(provider, listOf(bob.identity), secret))
        val aliceBlob = WrappedKeys.wrapFor(provider, listOf(alice.identity), secret)
        val corruptBob = blobOf(bobId, bobCt.copyOf(bobCt.size - 1), bobSealed)
        assertNull(WrappedKeys.unwrapFor(provider, corruptBob + aliceBlob, alice))
    }

    @Test
    fun sealedPayloadMustBeExactlyTheCanonicalSize() {
        val (id, ct, sealed) = fieldsOf(WrappedKeys.wrapFor(provider, listOf(alice.identity), secret))
        assertEquals(WrappedKeys.SEALED_BYTES, sealed.size, "the wrap side produces the canonical size")
        assertNull(WrappedKeys.unwrapFor(provider, blobOf(id, ct, ByteArray(sealed.size + 1)), alice), "one byte long")
        assertNull(WrappedKeys.unwrapFor(provider, blobOf(id, ct, ByteArray(sealed.size - 1)), alice), "one byte short")
    }

    @Test
    fun totalBudgetAppliesOnEveryPath() {
        val oversize = ByteArray(ProtocolLimits.MAX_WRAPPED_KEYS_BYTES + 1)
        assertNull(WrappedKeys.unwrapFor(provider, oversize, alice), "direct unwrap is budgeted")
        assertTrue(WrappedKeys.recipientsOf(oversize).isEmpty(), "direct recipient listing is budgeted")
    }

    @Test
    fun wrapForRejectsANonContextKeySecret() {
        assertFailsWith<IllegalArgumentException> {
            WrappedKeys.wrapFor(provider, listOf(alice.identity), provider.randomBytes(16))
        }
    }

    @Test
    fun wrapForRejectsDuplicateRecipients() {
        assertFailsWith<IllegalArgumentException> {
            WrappedKeys.wrapFor(provider, listOf(alice.identity, alice.identity), secret)
        }
    }
}
