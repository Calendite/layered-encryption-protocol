package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.WrappedKeys
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Handing a rotated context key to everyone who remains.
 *
 * This is the piece that makes removing somebody mean anything. If it were wrapped under the
 * identity's classical X25519 key it would work exactly as well today and fall to a quantum
 * adversary later, and a rotation is long-lived material: it goes into a log that is replicated
 * and kept indefinitely.
 */
class WrappedKeysTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    @Test
    fun `each recipient recovers the secret and only their own copy`() {
        val sarah = DeviceKeys.generate(provider)
        val mum = DeviceKeys.generate(provider)
        val secret = provider.randomBytes(32)

        val blob = WrappedKeys.wrapFor(provider, listOf(sarah.identity, mum.identity), secret)

        assertContentEquals(secret, WrappedKeys.unwrapFor(provider, blob, sarah))
        assertContentEquals(secret, WrappedKeys.unwrapFor(provider, blob, mum))
    }

    /** The whole point: someone left out of the rotation cannot read what it carried. */
    @Test
    fun `a member who was not a recipient gets nothing`() {
        val remaining = DeviceKeys.generate(provider)
        val removed = DeviceKeys.generate(provider)

        val blob = WrappedKeys.wrapFor(provider, listOf(remaining.identity), provider.randomBytes(32))

        assertNull(WrappedKeys.unwrapFor(provider, blob, removed), "a revoked device must not recover the new key")
        assertNotNull(WrappedKeys.unwrapFor(provider, blob, remaining))
    }

    /**
     * The recipient's identity is the associated data, so a copy addressed to one member cannot be
     * relabelled as another's, even by somebody who can rewrite the log.
     */
    @Test
    fun `a copy cannot be re-addressed to a different member`() {
        val sarah = DeviceKeys.generate(provider)
        val mum = DeviceKeys.generate(provider)
        val secret = provider.randomBytes(32)

        val sarahOnly = WrappedKeys.wrapFor(provider, listOf(sarah.identity), secret)
        val sarahId = sarah.identity.signingPublicKey.toHexString()
        val mumId = mum.identity.signingPublicKey.toHexString()

        // Swap the addressee, leaving the sealed bytes alone.
        val reAddressed = sarahOnly.decodeToString().replace(sarahId, mumId).encodeToByteArray()

        assertNull(WrappedKeys.unwrapFor(provider, reAddressed, mum), "the tag covers who it was for")
    }

    @Test
    fun `recipients can be listed without opening anything`() {
        val a = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)

        val blob = WrappedKeys.wrapFor(provider, listOf(a.identity, b.identity), provider.randomBytes(32))

        assertEquals(
            listOf(a.identity.signingPublicKey.toHexString(), b.identity.signingPublicKey.toHexString()),
            WrappedKeys.recipientsOf(blob),
        )
    }

    @Test
    fun `malformed input yields nothing rather than throwing`() {
        val device = DeviceKeys.generate(provider)

        assertNull(WrappedKeys.unwrapFor(provider, ByteArray(0), device))
        assertNull(WrappedKeys.unwrapFor(provider, provider.randomBytes(200), device))
        assertEquals(emptyList(), WrappedKeys.recipientsOf(provider.randomBytes(9)))
    }

    // ── The identity that makes it possible ───────────────────────────────────────────────────

    @Test
    fun `an identity carries a hybrid KEM key and binds it`() {
        val device = DeviceKeys.generate(provider)

        assertEquals(1216, device.identity.xWingPublicKey.size, "1184 B ML-KEM-768 + 32 B X25519")
        assertTrue(device.identity.verifyBinding(provider))
    }

    /**
     * The KEM key must be inside the binding signature. If it were not, an attacker could splice
     * their own KEM key into somebody else's identity and receive the rotations meant for them.
     */
    @Test
    fun `swapping the KEM key breaks the identity binding`() {
        val honest = DeviceKeys.generate(provider)
        val attacker = DeviceKeys.generate(provider)

        val spliced = org.layeredencryption.identity.DeviceIdentity(
            signingPublicKey = honest.identity.signingPublicKey,
            x25519IdentityPublicKey = honest.identity.x25519IdentityPublicKey,
            xWingPublicKey = attacker.identity.xWingPublicKey,
            bindingSignature = honest.identity.bindingSignature,
        )

        assertTrue(!spliced.verifyBinding(provider), "the binding must cover the KEM key")
    }
}
