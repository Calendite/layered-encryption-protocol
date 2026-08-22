package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.FreshnessStore
import org.layeredencryption.envelope.InMemoryFreshnessStore
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.storage.FileBackedFreshnessStore
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Freshness ordering is lexicographic by `(epoch, seq)` (LEP-R1), in every implementation.
 *
 * The regression these exist for: the old rule compared sequence first and treated epoch only as
 * a floor, which let a retired epoch key poison a lane permanently. Both stores are exercised
 * identically — two implementations that disagree about "newer" is the same bug wearing a
 * different hat.
 */
class FreshnessOrderingTest {

    private val provider = BouncyCastleCryptoProvider()

    private fun stores(): List<Pair<String, FreshnessStore>> {
        val dir = Files.createTempDirectory("freshness-ordering")
        dir.toFile().deleteOnExit()
        return listOf(
            "in-memory" to InMemoryFreshnessStore(),
            "file-backed" to FileBackedFreshnessStore.withoutRollbackDetection(
                dir.resolve("freshness.store"), provider, provider.randomBytes(32),
            ),
        )
    }

    private fun forEachStore(check: (String, FreshnessStore) -> Unit) =
        stores().forEach { (name, store) -> check(name, store) }

    // ── The attack this fix exists for ────────────────────────────────────────────────────────

    @Test
    fun retiredEpochCannotPoisonALanePermanently() = forEachStore { name, store ->
        // A revoked member kept the epoch-4 key and seals into the victim's lane with the highest
        // possible sequence. The receiver still holds epoch 4 for history, so the AEAD tag
        // verifies and the envelope reaches the freshness gate.
        assertTrue(store.accept("ctx", "victim-lane", seq = Int.MAX_VALUE, epoch = 4), name)

        // Before the fix this was fatal: no epoch-5 envelope could ever exceed MAX_VALUE, so the
        // lane was dead forever. Epoch-first ordering makes the first genuine post-rotation
        // envelope newer than anything from the retired epoch.
        assertTrue(store.wouldAccept("ctx", "victim-lane", seq = 0, epoch = 5), "$name: lane must recover")
        assertTrue(store.accept("ctx", "victim-lane", seq = 0, epoch = 5), name)
        assertTrue(store.accept("ctx", "victim-lane", seq = 1, epoch = 5), "$name: and keep going")
    }

    @Test
    fun retiredEpochIsRefusedOnceTheLaneHasMovedOn() = forEachStore { name, store ->
        assertTrue(store.accept("ctx", "lane", seq = 5, epoch = 5), name)
        // The same retained key, used after the lane has seen the new epoch: nothing it can
        // choose is newer, at any sequence.
        assertFalse(store.wouldAccept("ctx", "lane", seq = Int.MAX_VALUE, epoch = 4), name)
        assertFalse(store.accept("ctx", "lane", seq = Int.MAX_VALUE, epoch = 4), name)
    }

    // ── The ordering rules ────────────────────────────────────────────────────────────────────

    @Test
    fun higherEpochIsNewerWhateverTheSequence() = forEachStore { name, store ->
        assertTrue(store.accept("ctx", "lane", seq = 900, epoch = 1), name)
        assertTrue(store.accept("ctx", "lane", seq = 0, epoch = 2), "$name: epoch dominates")
    }

    @Test
    fun withinAnEpochSequencesMustStrictlyIncrease() = forEachStore { name, store ->
        assertTrue(store.accept("ctx", "lane", seq = 7, epoch = 3), name)
        assertFalse(store.accept("ctx", "lane", seq = 7, epoch = 3), "$name: replay")
        assertFalse(store.accept("ctx", "lane", seq = 6, epoch = 3), "$name: regression")
        assertTrue(store.accept("ctx", "lane", seq = 8, epoch = 3), name)
    }

    @Test
    fun lowerEpochIsNeverNewer() = forEachStore { name, store ->
        assertTrue(store.accept("ctx", "lane", seq = 2, epoch = 4), name)
        assertFalse(store.accept("ctx", "lane", seq = 3, epoch = 3), name)
    }

    @Test
    fun lanesAndContextsAreIndependent() = forEachStore { name, store ->
        assertTrue(store.accept("ctx", "lane-a", seq = 9, epoch = 2), name)
        assertTrue(store.accept("ctx", "lane-b", seq = 1, epoch = 1), "$name: other lane unaffected")
        assertTrue(store.accept("other-ctx", "lane-a", seq = 1, epoch = 1), "$name: other context unaffected")
    }

    @Test
    fun negativeValuesAreRefusedAtEveryEntryPoint() = forEachStore { name, store ->
        // A negative watermark would make every later value look fresh — the precise state a
        // freshness store exists to prevent, so it fails loudly rather than being absorbed.
        assertFailsWith<IllegalArgumentException>("$name: negative seq") {
            store.wouldAccept("ctx", "lane", seq = -1, epoch = 0)
        }
        assertFailsWith<IllegalArgumentException>("$name: negative epoch") {
            store.accept("ctx", "lane", seq = 0, epoch = -1)
        }
        assertFailsWith<IllegalArgumentException>("$name: negative in delivery") {
            store.deliverIfFresh("ctx", "lane", seq = -5, epoch = 0) { }
        }
    }

    // ── End to end, through the envelope path ─────────────────────────────────────────────────

    @Test
    fun aRotatedContextKeepsDeliveringAfterARetiredEpochInjection() {
        val epoch0Key = provider.randomBytes(32)
        val epoch1Key = provider.randomBytes(32)
        val keys = EpochKeys.of(mapOf(0 to epoch0Key, 1 to epoch1Key))
        val store = InMemoryFreshnessStore()

        // The retired-key holder seals a real, authenticated envelope into someone else's lane
        // at the maximum sequence. It opens — every key holder can author for any lane, which is
        // the accepted boundary documented in the threat model — and burns the epoch-0 watermark.
        val injected = LaneEnvelope.seal(
            provider, EpochKeys.founding(epoch0Key), "ctx", "victim", Int.MAX_VALUE,
            "injected".encodeToByteArray(),
        )
        assertContentEquals(
            "injected".encodeToByteArray(),
            injected.openAndValidate(provider, keys, "ctx", "victim", store) { it },
        )

        // The victim's next genuine op is in the new epoch, and it still gets through.
        val genuine = LaneEnvelope.seal(provider, keys, "ctx", "victim", seq = 0, plaintext = "real".encodeToByteArray())
        assertContentEquals(
            "real".encodeToByteArray(),
            genuine.openAndValidate(provider, keys, "ctx", "victim", store) { it },
        )
    }
}
