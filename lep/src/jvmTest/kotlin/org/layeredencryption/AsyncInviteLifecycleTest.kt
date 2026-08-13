package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.invite.AsyncDelivery
import org.layeredencryption.invite.AsyncHandshake
import org.layeredencryption.invite.AsyncInviteState
import org.layeredencryption.invite.AsyncInviter
import org.layeredencryption.invite.AsyncJoiner
import org.layeredencryption.invite.AsyncJoinerResponse
import org.layeredencryption.invite.AsyncRendezvous
import org.layeredencryption.invite.InMemoryInviteStore
import org.layeredencryption.invite.InviteStore
import org.layeredencryption.invite.ResponseOutcome
import org.layeredencryption.pairing.PairingException
import java.util.concurrent.CyclicBarrier
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The invite lifecycle and protocol-boundary hardening: malformed peer input
 * never escapes as an exception, terminal invites leave no stored material, transitions are
 * table-checked, and approve/reject cannot race.
 */
class AsyncInviteLifecycleTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()
    private val now = 1_000_000L
    private val expiry = now + 7 * 86_400L

    private fun inviter(store: InviteStore? = null) =
        AsyncInviter.create(provider, DeviceKeys.generate(provider), nowEpochSeconds = now, expiryEpochSeconds = expiry, store = store)

    private fun joiner() = AsyncJoiner(provider, DeviceKeys.generate(provider))

    /** A response a *link holder* can craft: a valid link proof over otherwise chosen fields. */
    private fun linkHolderResponse(inviter: AsyncInviter, kemCiphertext: ByteArray, identity: org.layeredencryption.identity.DeviceIdentity, joinerMac: ByteArray): AsyncJoinerResponse {
        val rid = AsyncRendezvous.id(provider, inviter.link.secret)
        val proof = AsyncHandshake.linkProofMac(provider, inviter.link.secret, rid, kemCiphertext, identity)
        return AsyncJoinerResponse(kemCiphertext, identity, proof, joinerMac)
    }

    // ── No exception escapes the protocol boundary ────────────────────────────────────────────

    @Test
    fun garbageKemCiphertextFromLinkHolderIsInvalidNotAnException() {
        val inviter = inviter()
        val response = linkHolderResponse(
            inviter,
            kemCiphertext = provider.randomBytes(XWing.CIPHERTEXT_SIZE),
            identity = DeviceKeys.generate(provider).identity,
            joinerMac = provider.randomBytes(32),
        )
        assertEquals(ResponseOutcome.Invalid, inviter.onResponse(response, now))
        assertEquals(AsyncInviteState.PENDING, inviter.state)
    }

    @Test
    fun lowOrderX25519LegIsInvalidNotAnException() {
        val inviter = inviter()
        val real = joiner().onBundle(inviter.link, inviter.bundle, now)
        // The all-zero X25519 point in the ciphertext tail makes the provider throw inside
        // decapsulation; that must come back as Invalid, not escape and kill a service loop.
        val ct = real.kemCiphertext.copyOf().also { it.fill(0, it.size - 32, it.size) }
        val tampered = linkHolderResponse(inviter, ct, real.deviceIdentityS, real.joinerMac)
        assertEquals(ResponseOutcome.Invalid, inviter.onResponse(tampered, now))
        assertEquals(AsyncInviteState.PENDING, inviter.state)
    }

    @Test
    fun malformedDeliveryLogIsAPairingExceptionNotAParserCrash() {
        val inviter = inviter()
        val joiner = joiner()
        inviter.onResponse(joiner.onBundle(inviter.link, inviter.bundle, now), now)
        val delivery = inviter.approve()

        // Valid MAC, garbage log bytes: the parser failure must surface as PairingException.
        val garbage = AsyncDelivery(delivery.inviterMac, provider.randomBytes(64))
        assertFailsWith<PairingException> { joiner.onDelivery(garbage) }

        // The failure is not terminal for the joiner: the genuine delivery still completes.
        joiner.onDelivery(delivery)
        assertContentEquals(inviter.masterKey(), joiner.masterKey())
    }

    // ── Terminal states leave no material behind ──────────────────────────────────────────────

    @Test
    fun approvedInviteIsRemovedFromStoreAndScrubbedButDeliversTheMasterKey() {
        val store = InMemoryInviteStore()
        val inviter = inviter(store)
        assertEquals(AsyncInviteState.PENDING, store.all().single().state)

        val joiner = joiner()
        inviter.onResponse(joiner.onBundle(inviter.link, inviter.bundle, now), now)
        assertEquals(AsyncInviteState.CLAIMED, store.all().single().state)

        val delivery = inviter.approve()
        assertTrue(store.all().isEmpty(), "an approved invite must leave no stored record")
        assertTrue(inviter.link.secret.all { it == 0.toByte() }, "the link secret must be zeroed")

        // The master key survives the scrub on both sides — it is the deliverable.
        joiner.onDelivery(delivery)
        assertContentEquals(inviter.masterKey(), joiner.masterKey())
    }

    @Test
    fun rejectedInviteIsRemovedFromStoreAndScrubbed() {
        val store = InMemoryInviteStore()
        val inviter = inviter(store)
        inviter.onResponse(joiner().onBundle(inviter.link, inviter.bundle, now), now)

        inviter.reject()
        assertEquals(AsyncInviteState.REJECTED, inviter.state)
        assertTrue(store.all().isEmpty(), "a rejected invite must leave no stored record")
        assertTrue(inviter.link.secret.all { it == 0.toByte() }, "the link secret must be zeroed")
    }

    @Test
    fun expiredInviteIsRemovedFromStoreAndScrubbed() {
        val store = InMemoryInviteStore()
        val inviter = inviter(store)
        val response = joiner().onBundle(inviter.link, inviter.bundle, now)

        assertEquals(ResponseOutcome.Expired, inviter.onResponse(response, expiry + 1))
        assertEquals(AsyncInviteState.EXPIRED, inviter.state)
        assertTrue(store.all().isEmpty(), "an expired invite must leave no stored record")
        assertTrue(inviter.link.secret.all { it == 0.toByte() }, "the link secret must be zeroed")
    }

    @Test
    fun illegalTransitionsAreRejected() {
        // PENDING → REJECTED is not a legal step.
        assertFailsWith<PairingException> { inviter().reject() }

        // Nothing follows APPROVED.
        val approved = inviter()
        approved.onResponse(joiner().onBundle(approved.link, approved.bundle, now), now)
        approved.approve()
        assertFailsWith<PairingException> { approved.reject() }
        assertFailsWith<PairingException> { approved.approve() }

        // Nothing follows REJECTED.
        val rejected = inviter()
        rejected.onResponse(joiner().onBundle(rejected.link, rejected.bundle, now), now)
        rejected.reject()
        assertFailsWith<PairingException> { rejected.approve() }
    }

    @Test
    fun concurrentApproveAndRejectResolveToExactlyOneOutcome() {
        repeat(20) {
            val inviter = inviter()
            inviter.onResponse(joiner().onBundle(inviter.link, inviter.bundle, now), now)

            val barrier = CyclicBarrier(2)
            var approved = false
            var rejected = false
            val approver = thread { barrier.await(); approved = runCatching { inviter.approve() }.isSuccess }
            val rejecter = thread { barrier.await(); rejected = runCatching { inviter.reject() }.isSuccess }
            approver.join()
            rejecter.join()

            assertTrue(approved xor rejected, "exactly one of approve/reject must win, got approved=$approved rejected=$rejected")
            val expected = if (approved) AsyncInviteState.APPROVED else AsyncInviteState.REJECTED
            assertEquals(expected, inviter.state)
        }
    }

    @Test
    fun masterKeyGettersReturnDefensiveCopies() {
        val inviter = inviter()
        val joiner = joiner()
        inviter.onResponse(joiner.onBundle(inviter.link, inviter.bundle, now), now)
        joiner.onDelivery(inviter.approve())

        // If these were views rather than copies, the two mutations would diverge the keys.
        inviter.masterKey().fill(23)
        joiner.masterKey().fill(42)
        assertContentEquals(inviter.masterKey(), joiner.masterKey())
    }
}
