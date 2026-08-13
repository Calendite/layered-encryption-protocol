package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.identity.DeviceKeys
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Explicit end-of-life for long-lived secret holders (b12169b review, issue 3): `destroy()`
 * zeroes the held material and every later secret read throws — ownership is unambiguous, and a
 * destroyed holder cannot quietly keep serving keys.
 */
class SecretDestructionTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    @Test
    fun deviceKeys_destroyEndsPrivateKeyAccessButNotTheIdentity() {
        val device = DeviceKeys.generate(provider)
        val message = "still signable".encodeToByteArray()
        val signature = HybridSignature.sign(provider, device.signingKeyPair.privateKey, message)

        device.destroy()
        device.destroy() // idempotent

        assertFailsWith<IllegalStateException> { device.signingPrivateKey }
        assertFailsWith<IllegalStateException> { device.x25519IdentityPrivateKey }
        assertFailsWith<IllegalStateException> { device.xWingPrivateKey }
        assertFailsWith<IllegalStateException> { device.signingKeyPair }

        // The public identity is public material and survives.
        assertTrue(device.identity.verifyBinding(provider))
        assertTrue(HybridSignature.verify(provider, device.identity.signingPublicKey, message, signature))
    }

    @Test
    fun epochKeys_destroyEndsKeyAccess() {
        val master = provider.randomBytes(32)
        val keys = EpochKeys.founding(master).withNextEpoch(provider.randomBytes(32))
        val copyTakenBefore = keys.currentKey

        keys.destroy()
        keys.destroy() // idempotent

        assertFailsWith<IllegalStateException> { keys.currentKey }
        assertFailsWith<IllegalStateException> { keys[0] }
        assertFailsWith<IllegalStateException> { keys.serialise() }
        assertFailsWith<IllegalStateException> { keys.withNextEpoch(provider.randomBytes(32)) }

        // Copies handed out earlier are the caller's responsibility — documented best effort.
        assertTrue(copyTakenBefore.any { it != 0.toByte() })
    }

    @Test
    fun epochKeys_derivedInstancesAreIndependentOfTheDestroyedParent() {
        val keys = EpochKeys.founding(provider.randomBytes(32))
        val rotatedKey = provider.randomBytes(32)
        val rotated = keys.withNextEpoch(rotatedKey)

        keys.destroy()
        assertContentEquals(rotatedKey, rotated.currentKey, "the derived set holds its own copies")
    }
}
