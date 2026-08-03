package org.layeredencryption

import org.layeredencryption.BouncyCastleCryptoProvider
import org.layeredencryption.Cascade
import org.layeredencryption.CryptoProvider
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.invite.AsyncDelivery
import org.layeredencryption.invite.AsyncInviteState
import org.layeredencryption.invite.AsyncInviter
import org.layeredencryption.invite.AsyncJoiner
import org.layeredencryption.invite.AsyncJoinerResponse
import org.layeredencryption.invite.InviteBundle
import org.layeredencryption.invite.ResponseOutcome
import org.layeredencryption.pairing.PairingException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AsyncPairingProtocolTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()
    private val now = 1_000_000L
    private val expiry = now + 7 * 86_400L

    private fun inviter() = AsyncInviter.create(provider, DeviceKeys.generate(provider), expiry)
    private fun joiner() = AsyncJoiner(provider, DeviceKeys.generate(provider))

    // 1
    @Test
    fun async_happyPathSharesMasterKeyWithMatchingSas() {
        val inviter = inviter()
        val joiner = joiner()

        val response = joiner.onBundle(inviter.link, inviter.bundle, now)
        val outcome = inviter.onResponse(response, now)

        assertTrue(outcome is ResponseOutcome.Claimed)
        assertEquals(AsyncInviteState.CLAIMED, inviter.state)
        assertEquals(joiner.shortAuthString, outcome.shortAuthString)

        joiner.onDelivery(inviter.approve())
        assertEquals(AsyncInviteState.APPROVED, inviter.state)
        assertContentEquals(inviter.masterKey(), joiner.masterKey())

        val blob = Cascade.seal(provider, inviter.masterKey(), "shared".encodeToByteArray())
        assertContentEquals("shared".encodeToByteArray(), Cascade.open(provider, joiner.masterKey(), blob))
    }

    // 2
    @Test
    fun async_badMacDroppedWithoutStateChange() {
        val inviter = inviter()
        val response = joiner().onBundle(inviter.link, inviter.bundle, now)
        val tampered = AsyncJoinerResponse(
            response.kemCiphertext,
            response.deviceIdentityS,
            response.joinerMac.copyOf().also { it[0] = (it[0] + 1).toByte() },
        )
        assertEquals(ResponseOutcome.Invalid, inviter.onResponse(tampered, now))
        assertEquals(AsyncInviteState.PENDING, inviter.state)
    }

    // 3
    @Test
    fun async_fingerprintMismatchAbortsAtJoiner() {
        val inviter = inviter()
        val otherBundle = inviter().bundle // different identity ⇒ fingerprint won't match inviter.link
        assertFailsWith<PairingException> { joiner().onBundle(inviter.link, otherBundle, now) }
    }

    // 4
    @Test
    fun async_tamperedBundleFailsSignature() {
        val inviter = inviter()
        val tampered = InviteBundle(
            inviter.bundle.inviteXWingPublicKey,
            inviter.bundle.deviceIdentityA,
            inviter.bundle.expiryEpochSeconds + 1, // signed field changed
            inviter.bundle.signature,
        )
        assertFailsWith<PairingException> { joiner().onBundle(inviter.link, tampered, now) }
    }

    // 5
    @Test
    fun async_expiryRejectedOnBothSides() {
        val inviter = inviter()
        // Joiner rejects a bundle past expiry + skew.
        assertFailsWith<PairingException> { joiner().onBundle(inviter.link, inviter.bundle, expiry + 400) }

        // Inviter refuses a response once expired.
        val response = joiner().onBundle(inviter.link, inviter.bundle, now)
        assertEquals(ResponseOutcome.Expired, inviter.onResponse(response, expiry + 1))
        assertEquals(AsyncInviteState.EXPIRED, inviter.state)
    }

    // 6
    @Test
    fun async_secondValidResponseIsAlreadyClaimed() {
        val inviter = inviter()
        val first = joiner().onBundle(inviter.link, inviter.bundle, now)
        val second = joiner().onBundle(inviter.link, inviter.bundle, now)

        assertTrue(inviter.onResponse(first, now) is ResponseOutcome.Claimed)
        assertEquals(ResponseOutcome.AlreadyClaimed, inviter.onResponse(second, now))
    }

    // 7
    @Test
    fun async_substitutedJoinerIdentityIsRejected() {
        val inviter = inviter()
        val response = joiner().onBundle(inviter.link, inviter.bundle, now)
        // Swap in a different (validly-bound) identity ⇒ dh1 + transcript differ ⇒ MAC fails.
        val substituted = AsyncJoinerResponse(response.kemCiphertext, DeviceKeys.generate(provider).identity, response.joinerMac)
        assertEquals(ResponseOutcome.Invalid, inviter.onResponse(substituted, now))
        assertEquals(AsyncInviteState.PENDING, inviter.state)
    }

    // 8
    @Test
    fun async_nonContributoryDh1IsRejected() {
        // The explicit guard rejects an all-zero secret...
        assertFailsWith<PairingException> {
            org.layeredencryption.invite.AsyncHandshake.requireContributory(ByteArray(32))
        }
        // ...and X25519 against the all-zero (low-order) peer key fails closed, mapped to PairingException.
        assertFailsWith<PairingException> {
            org.layeredencryption.invite.AsyncHandshake.contributoryDh(provider, provider.randomBytes(32), ByteArray(32))
        }
    }

    // 9
    @Test
    fun async_tamperedDeliveryIsRejected() {
        val inviter = inviter()
        val joiner = joiner()
        inviter.onResponse(joiner.onBundle(inviter.link, inviter.bundle, now), now)
        val delivery = inviter.approve()

        val badMac = AsyncDelivery(delivery.inviterMac.copyOf().also { it[0] = (it[0] + 1).toByte() }, delivery.serialisedMembershipLog)
        assertFailsWith<PairingException> { joiner.onDelivery(badMac) }

        val badLog = AsyncDelivery(delivery.inviterMac, delivery.serialisedMembershipLog.copyOf().also { it[it.lastIndex] = (it[it.lastIndex] + 1).toByte() })
        assertFailsWith<PairingException> { joiner.onDelivery(badLog) }
    }

    // 10
    @Test
    fun async_tamperedIdentityBindingIsRejected() {
        val inviter = inviter()
        val response = joiner().onBundle(inviter.link, inviter.bundle, now)
        val real = response.deviceIdentityS
        val tamperedIdentity = DeviceIdentity(
            real.ed25519PublicKey,
            real.x25519IdentityPublicKey,
            real.bindingSignature.copyOf().also { it[0] = (it[0] + 1).toByte() },
        )
        val response2 = AsyncJoinerResponse(response.kemCiphertext, tamperedIdentity, response.joinerMac)
        assertEquals(ResponseOutcome.Invalid, inviter.onResponse(response2, now))
    }

    // 11
    @Test
    fun async_keyReleaseIsApprovalGated() {
        val inviter = inviter()
        // No claim yet ⇒ approve() is not possible, so no delivery/key can be produced.
        assertFailsWith<PairingException> { inviter.approve() }

        val joiner = joiner()
        inviter.onResponse(joiner.onBundle(inviter.link, inviter.bundle, now), now)
        // Claimed but not approved ⇒ the joiner still has no master key.
        assertFailsWith<PairingException> { joiner.masterKey() }

        // Rejecting yields no delivery either.
        inviter.reject()
        assertEquals(AsyncInviteState.REJECTED, inviter.state)
    }
}
