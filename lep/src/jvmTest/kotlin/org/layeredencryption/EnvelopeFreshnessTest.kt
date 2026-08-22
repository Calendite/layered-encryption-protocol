package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.FreshnessStore
import org.layeredencryption.envelope.InMemoryFreshnessStore
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.envelope.ReplayException
import java.util.concurrent.CyclicBarrier
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Envelope freshness (LEP-04): AEAD proves an envelope was never modified; [LaneEnvelope.openAndValidate]
 * additionally proves it is new. A malicious relay replaying, reordering, or re-serving stale
 * state must be refused — with [ReplayException], distinctly from tamper — and refused cheaply,
 * before the cascade runs.
 */
class EnvelopeFreshnessTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()
    private val masterKey = provider.randomBytes(32)
    private val keys = EpochKeys.founding(masterKey)

    private fun envelope(seq: Int, keys: EpochKeys = this.keys, lane: String = "device-1", payload: String = "op-$seq") =
        LaneEnvelope.seal(provider, keys, "ctx", lane, seq, payload.encodeToByteArray())

    private fun LaneEnvelope.openFresh(store: InMemoryFreshnessStore, keys: EpochKeys = this@EnvelopeFreshnessTest.keys) =
        openAndValidate(provider, keys, "ctx", "device-1", store) { it }

    // ── The assessment's list ─────────────────────────────────────────────────────────────────

    @Test
    fun replayOfTheSameEnvelopeIsRejected() {
        val store = InMemoryFreshnessStore()
        val envelope = envelope(seq = 1)

        assertContentEquals("op-1".encodeToByteArray(), envelope.openFresh(store))
        assertFailsWith<ReplayException>("the exact same valid envelope must not open twice") {
            envelope.openFresh(store)
        }
    }

    @Test
    fun duplicateSequenceFromADifferentEnvelopeIsRejected() {
        val store = InMemoryFreshnessStore()
        envelope(seq = 1, payload = "first").openFresh(store)

        val duplicate = envelope(seq = 1, payload = "second, same seq")
        assertFailsWith<ReplayException> { duplicate.openFresh(store) }
    }

    @Test
    fun sequenceRegressionIsRejectedButGapsAreAllowed() {
        val store = InMemoryFreshnessStore()
        envelope(seq = 5).openFresh(store) // a gap from nowhere to 5: allowed, the consumer owns gap policy
        assertFailsWith<ReplayException>("an older op arriving after a newer one is stale") {
            envelope(seq = 3).openFresh(store)
        }
        envelope(seq = 8).openFresh(store) // forward gaps continue to be allowed
    }

    @Test
    fun wrongContextAndWrongLaneAreRejectedBeforeDecryption() {
        val store = InMemoryFreshnessStore()
        val other = LaneEnvelope.seal(provider, keys, "other-ctx", "device-1", 1, "x".encodeToByteArray())
        assertFailsWith<ReplayException> { other.openAndValidate(provider, keys, "ctx", "device-1", store) { it } }

        val otherLane = envelope(seq = 1, lane = "device-2")
        assertFailsWith<ReplayException> { otherLane.openAndValidate(provider, keys, "ctx", "device-1", store) { it } }
    }

    @Test
    fun staleEpochIsRejectedOnceANewerEpochWasAccepted() {
        val store = InMemoryFreshnessStore()
        val rotated = keys.withNextEpoch(provider.randomBytes(32))

        envelope(seq = 1, keys = rotated).openFresh(store, rotated) // epoch 1 accepted on the lane

        // An envelope sealed under the retired epoch 0 — what an attacker holding only a stolen
        // old epoch key can forge — is refused even with a fresh sequence number.
        val staleEpoch = envelope(seq = 2, keys = keys)
        assertFailsWith<ReplayException>("a retired epoch must not authenticate new ops") {
            staleEpoch.openFresh(store, rotated)
        }

        // The rotation direction stays legal: newer epoch, newer seq.
        envelope(seq = 3, keys = rotated).openFresh(store, rotated)
    }

    // ── Ordering properties the design commits to ─────────────────────────────────────────────

    @Test
    fun staleInputNeverReachesDecryption() {
        val counting = object : CryptoProvider by provider {
            var opens = 0
            override fun aes256GcmOpen(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray {
                opens++
                return provider.aes256GcmOpen(key, nonce, ciphertextAndTag, aad)
            }
        }
        val store = InMemoryFreshnessStore()
        val envelope = envelope(seq = 1)
        envelope.openAndValidate(counting, keys, "ctx", "device-1", store) { it }

        counting.opens = 0
        assertFailsWith<ReplayException> { envelope.openAndValidate(counting, keys, "ctx", "device-1", store) { it } }
        assertEquals(0, counting.opens, "a replay must be rejected before any decryption work")
    }

    @Test
    fun forgedEnvelopesCannotBurnSequenceNumbers() {
        val store = InMemoryFreshnessStore()
        // A relay forges a high-sequence envelope with garbage ciphertext: AEAD rejects it, and
        // because acceptance is recorded only after authentication, the sequence is NOT burned.
        val forged = LaneEnvelope(LaneEnvelope.VERSION, "ctx", "device-1", 100, 0, provider.randomBytes(64), org.layeredencryption.suite.SuiteId(1u))
        assertFailsWith<CryptoException> { forged.openFresh(store) }

        // The real op at seq 100 still goes through.
        assertContentEquals("op-100".encodeToByteArray(), envelope(seq = 100).openFresh(store))
    }

    @Test
    fun concurrentOpensOfTheSameSequenceSpendItExactlyOnce() {
        repeat(10) {
            val store = InMemoryFreshnessStore()
            val envelope = envelope(seq = 1)
            val barrier = CyclicBarrier(2)
            val results = arrayOfNulls<Boolean>(2)
            (0..1).map { i ->
                thread {
                    barrier.await()
                    results[i] = runCatching { envelope.openFresh(store) }.isSuccess
                }
            }.forEach { it.join() }

            // The delivery transaction serializes the racers: exactly one delivers, the loser
            // is refused as a replay, and the sequence is spent afterwards.
            assertEquals(1, results.count { it == true }, "exactly one racer may deliver the envelope")
            assertFailsWith<ReplayException> { envelope.openFresh(store) }
        }
    }

    /**
     * The crash contract (retest §2): the watermark advances only after delivery, so an
     * application that dies before durably taking custody has not spent the sequence — the
     * peer's re-send recovers the operation instead of being refused as stale.
     */
    @Test
    fun aFailedDeliveryLeavesTheEnvelopeFresh() {
        val store = InMemoryFreshnessStore()
        val envelope = envelope(seq = 1)

        assertFailsWith<IllegalStateException> {
            envelope.openAndValidate(provider, keys, "ctx", "device-1", store) {
                error("the application died before persisting")
            }
        }

        assertContentEquals("op-1".encodeToByteArray(), envelope.openFresh(store))
    }

    /**
     * The ordering contract (6ddd7e4 retest, finding 2): two *different* sequences racing the
     * delivery transaction can end 1-then-2, or 2-with-1-refused — never 1 delivered after 2.
     * Idempotency cannot save that case (they are distinct operations), so the transaction must.
     */
    @Test
    fun aStaleSequenceIsNeverDeliveredAfterANewerOne() {
        repeat(20) {
            val store = InMemoryFreshnessStore()
            val delivered = java.util.Collections.synchronizedList(mutableListOf<Int>())
            val barrier = CyclicBarrier(2)
            listOf(1, 2).map { seq ->
                thread {
                    barrier.await()
                    store.deliverIfFresh("ctx", "device-1", seq, 0) { delivered += seq }
                }
            }.forEach { it.join() }

            assertTrue(
                delivered == listOf(1, 2) || delivered == listOf(2),
                "sequence 1 must never be delivered after sequence 2, got $delivered",
            )
        }
    }

    /** An envelope that goes stale between the advisory check and the transaction never delivers. */
    @Test
    fun deliveryNeverRunsForASequenceTheTransactionRefuses() {
        val envelope = envelope(seq = 1)
        val stale = object : FreshnessStore {
            override fun wouldAccept(contextId: String, lane: String, seq: Int, epoch: Int) = true
            override fun accept(contextId: String, lane: String, seq: Int, epoch: Int) = false
            override fun deliverIfFresh(contextId: String, lane: String, seq: Int, epoch: Int, deliver: () -> Unit) = false
        }

        var deliverRan = false
        assertFailsWith<ReplayException> {
            envelope.openAndValidate(provider, keys, "ctx", "device-1", stale) { deliverRan = true }
        }
        assertFalse(deliverRan, "a refused sequence must never reach the delivery callback")
    }

    @Test
    fun freshnessStateIsPerLaneAndPerContext() {
        val store = InMemoryFreshnessStore()
        envelope(seq = 5).openFresh(store)

        // Another lane in the same context starts its own watermark.
        LaneEnvelope.seal(provider, keys, "ctx", "device-2", 1, "x".encodeToByteArray())
            .openAndValidate(provider, keys, "ctx", "device-2", store) { it }

        // Same lane name in a different context is independent too.
        LaneEnvelope.seal(provider, keys, "ctx2", "device-1", 1, "x".encodeToByteArray())
            .openAndValidate(provider, keys, "ctx2", "device-1", store) { it }
    }

    @Test
    fun statelessOpenStillWorksAndIsDocumentedAsReplayable() {
        // The stateless API remains for trusted-transport use: it opens a replay happily, which
        // is exactly why openAndValidate exists.
        val envelope = envelope(seq = 1)
        assertContentEquals(envelope.openWithoutReplayProtection(provider, keys), envelope.openWithoutReplayProtection(provider, keys))
        assertTrue(true)
    }
}
