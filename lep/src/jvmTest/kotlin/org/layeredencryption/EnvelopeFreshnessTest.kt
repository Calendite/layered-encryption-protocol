package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.InMemoryFreshnessStore
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.envelope.ReplayException
import java.util.concurrent.CyclicBarrier
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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
        openAndValidate(provider, keys, "ctx", "device-1", store)

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
        assertFailsWith<ReplayException> { other.openAndValidate(provider, keys, "ctx", "device-1", store) }

        val otherLane = envelope(seq = 1, lane = "device-2")
        assertFailsWith<ReplayException> { otherLane.openAndValidate(provider, keys, "ctx", "device-1", store) }
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
        envelope.openAndValidate(counting, keys, "ctx", "device-1", store)

        counting.opens = 0
        assertFailsWith<ReplayException> { envelope.openAndValidate(counting, keys, "ctx", "device-1", store) }
        assertEquals(0, counting.opens, "a replay must be rejected before any decryption work")
    }

    @Test
    fun forgedEnvelopesCannotBurnSequenceNumbers() {
        val store = InMemoryFreshnessStore()
        // A relay forges a high-sequence envelope with garbage ciphertext: AEAD rejects it, and
        // because acceptance is recorded only after authentication, the sequence is NOT burned.
        val forged = LaneEnvelope(LaneEnvelope.VERSION, "ctx", "device-1", 100, 0, provider.randomBytes(64))
        assertFailsWith<CryptoException> { forged.openFresh(store) }

        // The real op at seq 100 still goes through.
        assertContentEquals("op-100".encodeToByteArray(), envelope(seq = 100).openFresh(store))
    }

    @Test
    fun concurrentOpensOfTheSameSequenceAcceptExactlyOne() {
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

            assertEquals(1, results.count { it == true }, "exactly one concurrent open may accept a sequence")
        }
    }

    @Test
    fun freshnessStateIsPerLaneAndPerContext() {
        val store = InMemoryFreshnessStore()
        envelope(seq = 5).openFresh(store)

        // Another lane in the same context starts its own watermark.
        LaneEnvelope.seal(provider, keys, "ctx", "device-2", 1, "x".encodeToByteArray())
            .openAndValidate(provider, keys, "ctx", "device-2", store)

        // Same lane name in a different context is independent too.
        LaneEnvelope.seal(provider, keys, "ctx2", "device-1", 1, "x".encodeToByteArray())
            .openAndValidate(provider, keys, "ctx2", "device-1", store)
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
