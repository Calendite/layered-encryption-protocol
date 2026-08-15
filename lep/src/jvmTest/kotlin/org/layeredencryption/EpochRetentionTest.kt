package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.InMemoryFreshnessStore
import org.layeredencryption.envelope.LaneEnvelope
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * RT-06: the retention-policy primitive. Pruning drops exactly the chosen history, keeps the
 * sealing key, survives serialisation, and makes dropped-epoch envelopes as unreadable here as
 * they are on a device that never held those epochs.
 */
class EpochRetentionTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private fun threeEpochs(): Pair<EpochKeys, List<ByteArray>> {
        val keys = listOf(provider.randomBytes(32), provider.randomBytes(32), provider.randomBytes(32))
        return EpochKeys.founding(keys[0]).withNextEpoch(keys[1]).withNextEpoch(keys[2]) to keys
    }

    @Test
    fun pruningDropsOldEpochsAndKeepsTheRest() {
        val (keys, raw) = threeEpochs()
        val pruned = keys.retainingFrom(1)

        assertEquals(listOf(1, 2), pruned.epochs)
        assertNull(pruned[0], "the dropped epoch answers null, same as a late-added device")
        assertContentEquals(raw[1], pruned[1])
        assertContentEquals(raw[2], pruned.currentKey)
        assertEquals(2, pruned.current, "epoch numbering is preserved, not re-indexed")

        // The original is untouched until the caller destroys it — and destroying it does not
        // reach into the pruned set's independent copies.
        assertContentEquals(raw[0], keys[0]!!)
        keys.destroy()
        assertContentEquals(raw[2], pruned.currentKey)
    }

    @Test
    fun pruningTheCurrentEpochIsRefused() {
        val (keys, _) = threeEpochs()
        assertFailsWith<IllegalArgumentException> { keys.retainingFrom(3) }
    }

    @Test
    fun prunedSetsSurviveSerialisation() {
        val (keys, raw) = threeEpochs()
        val restored = EpochKeys.deserialise(keys.retainingFrom(2).serialise())
            ?: error("a pruned set must round-trip")
        assertEquals(listOf(2), restored.epochs)
        assertContentEquals(raw[2], restored.currentKey)
    }

    @Test
    fun droppedEpochEnvelopesStopOpeningAndCurrentOnesDoNot() {
        val (keys, _) = threeEpochs()
        val old = LaneEnvelope.seal(provider, EpochKeys.founding(keys[0]!!), "ctx", "lane", 1, "old".encodeToByteArray())
        val fresh = LaneEnvelope.seal(provider, keys, "ctx", "lane", 2, "new".encodeToByteArray())

        val pruned = keys.retainingFrom(1)
        assertFailsWith<CryptoException> { old.openWithoutReplayProtection(provider, pruned) }
        assertContentEquals(
            "new".encodeToByteArray(),
            fresh.openAndValidate(provider, pruned, "ctx", "lane", InMemoryFreshnessStore()),
        )
    }
}
