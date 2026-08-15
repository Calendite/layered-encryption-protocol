package org.layeredencryption.envelope

import org.layeredencryption.ProtocolLock

/**
 * Thrown by [LaneEnvelope.openAndValidate] for an envelope that is cryptographically valid but
 * **not fresh**: a replay, a duplicate or regressed sequence number, a retired epoch, or a
 * header naming a different context/lane than expected. Distinct from
 * [org.layeredencryption.CryptoException] (tamper) on purpose — a consumer may want to treat
 * replay as a hostile-relay signal rather than corruption.
 */
class ReplayException(message: String) : Exception(message)

/**
 * Tracks the highest accepted `(seq, epoch)` per `(context, lane)` — the state that turns AEAD's
 * "this envelope was never modified" into "and it is also *new*" (LEP-04). AEAD cannot provide
 * this: a malicious relay can replay an old valid envelope, deliver a stale one late, or suppress
 * newer ones, all without touching a byte.
 *
 * The acceptance rule per lane: sequence numbers strictly increase (gaps are allowed — whether a
 * gap means suppression or not-yet-delivered is knowledge only the consumer has), and the epoch
 * never decreases. Epoch monotonicity is a real defence, not bookkeeping: [LaneEnvelope.open]
 * accepts any epoch this device holds a key for, so an attacker holding one *retired* epoch key
 * could otherwise forge fresh-looking ops for a lane forever; monotonicity ends that the moment
 * any newer-epoch op has been accepted on the lane.
 *
 * ### Production contract
 * The production implementation on JVM/Android is
 * `org.layeredencryption.storage.FileBackedFreshnessStore` (RT-03): [deliverIfFresh] and
 * [accept] are durable atomic transactions, fsync'd before they return true, atomic across
 * processes, and rollback-evident via a revision witness — a restored old snapshot, which
 * silently re-enables every replay this store had refused, fails loudly instead.
 * [InMemoryFreshnessStore] is the in-memory reference used in tests; its state dies with the
 * process.
 *
 * The delivery contract (`6ddd7e4` retest, finding 2): the freshness *decision*, the
 * application taking custody, and the watermark advance are one serialized transaction per
 * store. Delivery is at-least-once — a crash after the callback but before the watermark
 * commits re-delivers exactly once on re-send — so callbacks must be idempotent by
 * `(context, lane, seq)`. What can never happen: a sequence delivered after a higher sequence
 * on its lane already committed, because the decision is re-checked inside the transaction.
 */
interface FreshnessStore {

    /**
     * Cheap pre-check with **no recording**: would this `(seq, epoch)` currently be accepted for
     * the lane? Called before decryption so a replayed envelope is rejected at header-read cost.
     * Advisory only — [deliverIfFresh] re-checks atomically.
     */
    fun wouldAccept(contextId: String, lane: String, seq: Int, epoch: Int): Boolean

    /**
     * Atomically checks and records: accepts iff `seq` is strictly greater than the lane's
     * highest accepted sequence and `epoch` is not below its highest accepted epoch. Exactly one
     * of two racing calls with the same `seq` wins. Prefer [deliverIfFresh] when the acceptance
     * must be tied to the application taking custody of a plaintext.
     */
    fun accept(contextId: String, lane: String, seq: Int, epoch: Int): Boolean

    /**
     * The delivery transaction: re-checks freshness while no competing sequence can race the
     * decision, runs [deliver], and advances the watermark only after it returns. Returns false
     * — **without invoking [deliver]** — when the sequence went stale between the caller's
     * advisory check and the transaction, which is precisely the window where an unserialized
     * caller would apply a stale operation after a newer one.
     *
     * [deliver] runs under the store's transaction and must not call back into the store. If it
     * throws, nothing is recorded and the exception propagates — the sequence stays fresh for
     * the peer's re-send.
     */
    fun deliverIfFresh(contextId: String, lane: String, seq: Int, epoch: Int, deliver: () -> Unit): Boolean
}

/** The reference [FreshnessStore]: in-memory, lock-synchronised. State dies with the process. */
class InMemoryFreshnessStore : FreshnessStore {
    private val lock = ProtocolLock()
    private val lanes = mutableMapOf<Pair<String, String>, Watermark>()

    private class Watermark(var seq: Int, var epoch: Int)

    override fun wouldAccept(contextId: String, lane: String, seq: Int, epoch: Int): Boolean =
        lock.withLock { admissible(lanes[contextId to lane], seq, epoch) }

    override fun accept(contextId: String, lane: String, seq: Int, epoch: Int): Boolean = lock.withLock {
        acceptLocked(contextId, lane, seq, epoch)
    }

    override fun deliverIfFresh(contextId: String, lane: String, seq: Int, epoch: Int, deliver: () -> Unit): Boolean =
        lock.withLock {
            if (!admissible(lanes[contextId to lane], seq, epoch)) return@withLock false
            deliver()
            acceptLocked(contextId, lane, seq, epoch)
        }

    private fun acceptLocked(contextId: String, lane: String, seq: Int, epoch: Int): Boolean {
        val current = lanes[contextId to lane]
        if (!admissible(current, seq, epoch)) return false
        if (current == null) {
            lanes[contextId to lane] = Watermark(seq, epoch)
        } else {
            current.seq = seq
            current.epoch = epoch
        }
        return true
    }

    private fun admissible(current: Watermark?, seq: Int, epoch: Int): Boolean =
        current == null || (seq > current.seq && epoch >= current.epoch)
}
