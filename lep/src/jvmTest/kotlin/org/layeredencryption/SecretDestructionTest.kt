package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.pairing.ExistingCalendar
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.InviterConfirm
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingException
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

    // ── Pairing sessions scrub on every terminal path (57a2f38 review, issue 5) ───────────────

    @Test
    fun pairingSessions_scrubOnSuccessAndKeepTheirResults() {
        val inviterDevice = DeviceKeys.generate(provider)
        val joinerDevice = DeviceKeys.generate(provider)
        val code = PairingCode.generate(provider)
        val inviter = Inviter(provider, inviterDevice, code)
        val joiner = Joiner(provider, joinerDevice, code)

        val response = joiner.onInviterHello(inviter.hello())
        val confirm = inviter.onJoinerResponse(response)
        joiner.onInviterConfirm(confirm)
        joiner.onInviterComplete(inviter.complete(inviter.confirmSas()), joiner.confirmSas()) // terminal on both sides

        // Further protocol steps are dead...
        assertFailsWith<IllegalStateException> { inviter.hello() }
        assertFailsWith<IllegalStateException> { inviter.confirmSas() }
        assertFailsWith<IllegalStateException> { joiner.onInviterConfirm(confirm) }

        // ...but the ceremony's results belong to the application and survive.
        assertContentEquals(inviter.masterKey(), joiner.masterKey())
        assertTrue(inviter.membershipLog() != null && joiner.membershipLog() != null)
        assertTrue(inviter.shortAuthString == joiner.shortAuthString)

        inviter.destroy() // idempotent
        joiner.destroy()
    }

    @Test
    fun pairingSessions_failurePathScrubIsTerminal() {
        val code = PairingCode.generate(provider)
        val wrongCode = PairingCode.generate(provider)
        val inviter = Inviter(provider, DeviceKeys.generate(provider), code)
        val joiner = Joiner(provider, DeviceKeys.generate(provider), wrongCode)

        // Wrong code: the inviter rejects the joiner's MAC; both sides then destroy, as the
        // ferry does in its finally.
        val response = joiner.onInviterHello(inviter.hello())
        assertFailsWith<PairingException> { inviter.onJoinerResponse(response) }
        inviter.destroy()
        joiner.destroy()

        assertFailsWith<IllegalStateException> { inviter.onJoinerResponse(response) }
        assertFailsWith<IllegalStateException> { joiner.onInviterConfirm(InviterConfirm(ByteArray(32), ByteArray(32))) }
    }

    @Test
    fun pairingSessions_destroyDoesNotTouchAnExistingCalendarsKeys() {
        val device = DeviceKeys.generate(provider)
        val existingKeys = EpochKeys.founding(provider.randomBytes(32))
        val existingLog = MembershipLog.found(provider, device.identity, device.signingKeyPair)
        val inviter = Inviter(provider, device, PairingCode.generate(provider), ExistingCalendar(existingKeys, existingLog))

        inviter.destroy()
        // The context keys are the application's, merely referenced by the session.
        assertTrue(existingKeys.currentKey.any { it != 0.toByte() })
    }
}
