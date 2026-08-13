package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.invite.AsyncInviteState
import org.layeredencryption.invite.AsyncInviter
import org.layeredencryption.invite.AsyncJoiner
import org.layeredencryption.invite.InMemoryInviteStore
import org.layeredencryption.invite.InviteStore
import org.layeredencryption.invite.PendingInvite
import org.layeredencryption.invite.ResponseOutcome
import org.layeredencryption.pairing.PairingException
import java.util.concurrent.CyclicBarrier
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The storage failure model and the non-resumable-claim policy (LEP-07 retest, issues 7.2/7.3):
 * store operations may throw at any transition, and no failure may diverge memory from durable
 * state, skip scrubbing, resurrect an invite, or lose an approved delivery. `PENDING` is the
 * only state at rest, and [AsyncInviter.resume] is the only way back in.
 */
class AsyncInviteStorageFaultTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()
    private val now = 1_000_000L
    private val expiry = now + 7 * 86_400L

    /** A store whose operations can be made to throw, like a real keystore or database. */
    private class FaultyStore(private val delegate: InviteStore = InMemoryInviteStore()) : InviteStore {
        var failPut = false
        var failRemove = false
        override fun put(invite: PendingInvite) {
            if (failPut) throw RuntimeException("store down (put)")
            delegate.put(invite)
        }
        override fun get(ridAsyncHex: String): PendingInvite? = delegate.get(ridAsyncHex)
        override fun all(): List<PendingInvite> = delegate.all()
        override fun remove(ridAsyncHex: String) {
            if (failRemove) throw RuntimeException("store down (remove)")
            delegate.remove(ridAsyncHex)
        }
    }

    private fun inviter(device: DeviceKeys = DeviceKeys.generate(provider), store: InviteStore? = null) =
        AsyncInviter.create(provider, device, nowEpochSeconds = now, expiryEpochSeconds = expiry, store = store)

    private fun joiner() = AsyncJoiner(provider, DeviceKeys.generate(provider))

    // ── Failure at each transition ────────────────────────────────────────────────────────────

    @Test
    fun createFailsClosedWhenPutThrows() {
        val store = FaultyStore().apply { failPut = true }
        assertFailsWith<RuntimeException> { inviter(store = store) }
        assertTrue(store.all().isEmpty(), "a failed create must leave nothing behind")
    }

    @Test
    fun claimTimeRemoveFailureLeavesTheInviteFullyClaimable() {
        val store = FaultyStore()
        val inviter = inviter(store = store)
        val response = joiner().onBundle(inviter.link, inviter.bundle, now)

        store.failRemove = true
        assertFailsWith<RuntimeException>("a storage fault is not a peer verdict") {
            inviter.onResponse(response, now)
        }
        assertEquals(AsyncInviteState.PENDING, inviter.state, "nothing may be published on a failed claim")
        assertEquals(AsyncInviteState.PENDING, store.all().single().state, "the durable record must survive")
        assertFalse(inviter.isScrubbed(), "the invite must remain live")

        // The same response claims cleanly once the store recovers.
        store.failRemove = false
        assertTrue(inviter.onResponse(response, now) is ResponseOutcome.Claimed)
        assertTrue(store.all().isEmpty(), "the recovered claim burns the record")
    }

    @Test
    fun terminalRemoveFailureScrubsSurfacesCleanupAndKeepsTheDelivery() {
        val store = FaultyStore()
        val inviter = inviter(store = store)
        val joiner = joiner()
        // Claim with a working store, then plant a stale PENDING snapshot (as a rollback or an
        // interrupted earlier cleanup would leave) and make removal fail at the terminal step.
        inviter.onResponse(joiner.onBundle(inviter.link, inviter.bundle, now), now)
        store.put(staleSnapshotOf(inviter))
        store.failRemove = true

        val delivery = inviter.approve() // must not throw, must not lose the delivery
        assertEquals(AsyncInviteState.APPROVED, inviter.state)
        assertTrue(inviter.isScrubbed(), "scrubbing must happen even when deletion throws")
        assertTrue(inviter.requiresStoreCleanup, "the deletion failure must be surfaced")
        joiner.onDelivery(delivery)
        assertContentEquals(inviter.masterKey(), joiner.masterKey(), "the delivery survives the fault")

        // Approving again is still an illegal transition — the invite was not resurrected.
        assertFailsWith<PairingException> { inviter.approve() }

        // Cleanup retries once the store recovers.
        store.failRemove = false
        inviter.retryStoreCleanup()
        assertFalse(inviter.requiresStoreCleanup)
        assertTrue(store.all().isEmpty(), "the stale record is gone after retry")
    }

    @Test
    fun concurrentApproveRejectWithFailingStoreStillHasExactlyOneWinner() {
        repeat(5) {
            val store = FaultyStore()
            val inviter = inviter(store = store)
            inviter.onResponse(joiner().onBundle(inviter.link, inviter.bundle, now), now)
            store.failRemove = true

            val barrier = CyclicBarrier(2)
            var approved = false
            var rejected = false
            val a = thread { barrier.await(); approved = runCatching { inviter.approve() }.isSuccess }
            val r = thread { barrier.await(); rejected = runCatching { inviter.reject() }.isSuccess }
            a.join(); r.join()

            assertTrue(approved xor rejected, "exactly one of approve/reject must win under storage faults")
            assertTrue(inviter.isScrubbed(), "the loser's path must not have skipped scrubbing")
        }
    }

    // ── Resume: the only way back in, and only for PENDING ────────────────────────────────────

    @Test
    fun pendingInviteResumesAndCompletesTheCeremony() {
        val device = DeviceKeys.generate(provider)
        val store = InMemoryInviteStore()
        val original = inviter(device, store)
        val linkSentToPartner = original.link.url() // what the partner already received

        // Process death: all that survives is the store. Resume from it.
        val record = store.all().single()
        val resumed = AsyncInviter.resume(provider, device, record, nowEpochSeconds = now, store = store)

        // The partner's link still matches the resumed invite (same secret, same identity pin).
        val joiner = joiner()
        val parsedLink = org.layeredencryption.invite.InviteLink.parseUrl(linkSentToPartner) ?: error("link must parse")
        val outcome = resumed.onResponse(joiner.onBundle(parsedLink, resumed.bundle, now), now)
        assertTrue(outcome is ResponseOutcome.Claimed)
        assertTrue(store.all().isEmpty(), "the resumed claim burns the record")

        joiner.onDelivery(resumed.approve())
        assertContentEquals(resumed.masterKey(), joiner.masterKey())
        assertContentEquals(original.masterKey(), joiner.masterKey(), "the resumed invite delivers the original context key")
    }

    @Test
    fun expiredRecordIsNotResumedAndIsRemoved() {
        val device = DeviceKeys.generate(provider)
        val store = InMemoryInviteStore()
        inviter(device, store)

        val record = store.all().single()
        assertFailsWith<PairingException> {
            AsyncInviter.resume(provider, device, record, nowEpochSeconds = expiry + 1, store = store)
        }
        assertTrue(store.all().isEmpty(), "an expired record is removed, not resurrected")
    }

    @Test
    fun onlyPendingRecordsAreResumable() {
        val device = DeviceKeys.generate(provider)
        val store = InMemoryInviteStore()
        inviter(device, store)
        val record = store.all().single()

        val forged = PendingInvite(
            ridAsync = record.ridAsync,
            secret = record.secret,
            inviteXWingPublicKey = record.inviteXWingPublicKey,
            inviteXWingPrivateKey = record.inviteXWingPrivateKey,
            masterKey = record.masterKey,
            expiryEpochSeconds = record.expiryEpochSeconds,
            state = AsyncInviteState.CLAIMED,
        )
        assertFailsWith<PairingException> {
            AsyncInviter.resume(provider, device, forged, nowEpochSeconds = now)
        }
    }

    /** A stale PENDING snapshot with this inviter's rid, as a rollback/leftover would look. */
    private fun staleSnapshotOf(inviter: AsyncInviter): PendingInvite {
        // Rebuild a plausible record: only the rid matters for removal bookkeeping.
        val rid = org.layeredencryption.invite.AsyncRendezvous.id(provider, inviter.link.secret)
        return PendingInvite(
            ridAsync = rid,
            secret = inviter.link.secret,
            inviteXWingPublicKey = inviter.bundle.inviteXWingPublicKey,
            inviteXWingPrivateKey = ByteArray(32),
            masterKey = ByteArray(32),
            expiryEpochSeconds = expiry,
            state = AsyncInviteState.PENDING,
        )
    }
}
