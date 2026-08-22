package org.layeredencryption

import org.layeredencryption.invite.AsyncInviteState
import org.layeredencryption.invite.InMemoryInviteStore
import org.layeredencryption.invite.InviteStore
import org.layeredencryption.invite.PendingInvite
import java.util.concurrent.CyclicBarrier
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The contract every [InviteStore] adapter must satisfy — most importantly that [InviteStore.consume]
 * is a single-winner atomic operation, because it is the claim gate that makes an async invite a
 * single-use capability across resumed instances.
 *
 * A production adapter (platform keystore + database) should subclass this and override
 * [createStore]; passing this suite is necessary but not sufficient — cross-*process* atomicity,
 * encryption at rest, rollback protection, and tombstoning cannot be proven from inside one JVM
 * and need adapter-specific tests (see the `InviteStore` interface docs).
 */
abstract class InviteStoreConformanceTest {

    protected abstract fun createStore(): InviteStore

    private fun record(seed: Int): PendingInvite = PendingInvite(
        ridAsync = ByteArray(32) { (seed + it).toByte() },
        secret = ByteArray(32) { (seed * 2 + it).toByte() },
        inviteXWingPublicKey = ByteArray(1216),
        inviteXWingPrivateKey = ByteArray(32) { (seed * 3 + it).toByte() },
        masterKey = ByteArray(32) { (seed * 5 + it).toByte() },
        expiryEpochSeconds = 1_000_000L,
        state = AsyncInviteState.PENDING,
        suiteId = org.layeredencryption.suite.SuiteId(1u),
    )

    @Test
    fun putGetAllRoundTrip() {
        val store = createStore()
        val invite = record(1)
        store.put(invite)

        val loaded = store.get(invite.ridAsyncHex) ?: error("stored record must load")
        assertContentEquals(invite.secret, loaded.secret)
        assertContentEquals(invite.masterKey, loaded.masterKey)
        assertEquals(invite.expiryEpochSeconds, loaded.expiryEpochSeconds)
        assertEquals(1, store.all().size)
        assertNull(store.get(record(2).ridAsyncHex), "an unknown id loads nothing")
    }

    @Test
    fun consumeIsSingleWinnerSequentially() {
        val store = createStore()
        val invite = record(1)
        store.put(invite)

        assertTrue(store.consume(invite.ridAsyncHex), "the first consume wins")
        assertFalse(store.consume(invite.ridAsyncHex), "the second must observe nothing")
        assertNull(store.get(invite.ridAsyncHex), "a consumed record is gone")
        assertFalse(store.consume(record(2).ridAsyncHex), "consuming an unknown id never wins")
    }

    @Test
    fun consumeIsSingleWinnerUnderConcurrency() {
        repeat(20) { round ->
            val store = createStore()
            val invite = record(round)
            store.put(invite)

            val contenders = 8
            val barrier = CyclicBarrier(contenders)
            val wins = IntArray(contenders)
            (0 until contenders).map { i ->
                thread {
                    barrier.await()
                    if (store.consume(invite.ridAsyncHex)) wins[i] = 1
                }
            }.forEach { it.join() }

            assertEquals(1, wins.sum(), "exactly one contender may win the consume")
        }
    }

    @Test
    fun removeIsIdempotentAndNeverResurrects() {
        val store = createStore()
        val invite = record(1)
        store.put(invite)

        assertTrue(store.consume(invite.ridAsyncHex))
        store.remove(invite.ridAsyncHex) // cleanup after consumption: a no-op, not an error
        store.remove(invite.ridAsyncHex) // and again
        assertNull(store.get(invite.ridAsyncHex))
        assertFalse(store.consume(invite.ridAsyncHex), "cleanup must not have revived the record")
    }

    @Test
    fun putCannotResurrectAConsumedId() {
        val store = createStore()
        val invite = record(1)
        store.put(invite)
        assertTrue(store.consume(invite.ridAsyncHex))

        // The rollback threat: a stale snapshot (a restored backup) re-inserted after consumption.
        assertFailsWith<IllegalStateException>("a consumed id is permanently tombstoned") {
            store.put(invite)
        }
        assertNull(store.get(invite.ridAsyncHex))
        assertFalse(store.consume(invite.ridAsyncHex))
    }

    @Test
    fun returnedRecordsAreSnapshots() {
        val store = createStore()
        val invite = record(1)
        store.put(invite)

        val loaded = store.get(invite.ridAsyncHex)!!
        loaded.secret.fill(9)
        loaded.masterKey.fill(9)
        assertContentEquals(invite.secret, store.get(invite.ridAsyncHex)!!.secret)
        assertContentEquals(invite.masterKey, store.get(invite.ridAsyncHex)!!.masterKey)
    }
}

/** The reference implementation must pass its own conformance suite. */
class InMemoryInviteStoreConformanceTest : InviteStoreConformanceTest() {
    override fun createStore(): InviteStore = InMemoryInviteStore()
}
