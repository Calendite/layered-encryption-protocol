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
 * `org.layeredencryption.storage.FileBackedFreshnessStore` (RT-03): [accept] is a durable atomic
 * compare-and-advance, fsync'd before it returns true, atomic across processes, and
 * rollback-evident via a revision witness — a restored old snapshot, which silently re-enables
 * every replay this store had refused, fails loudly instead. [InMemoryFreshnessStore] is the
 * in-memory reference used in tests; its state dies with the process.
 *
 * Whatever the store, consumers must stay idempotent by `(context, lane, seq)`: a crash between
 * a successful accept and the application applying the operation loses that delivery, and the
 * peer's re-send is the recovery path.
 */
interface FreshnessStore {

    /**
     * Cheap pre-check with **no recording**: would this `(seq, epoch)` currently be accepted for
     * the lane? Called before decryption so a replayed envelope is rejected at header-read cost.
     * Advisory only — [accept] re-checks atomically.
     */
    fun wouldAccept(contextId: String, lane: String, seq: Int, epoch: Int): Boolean

    /**
     * Atomically checks and records: accepts iff `seq` is strictly greater than the lane's
     * highest accepted sequence and `epoch` is not below its highest accepted epoch. Exactly one
     * of two racing calls with the same `seq` wins.
     */
    fun accept(contextId: String, lane: String, seq: Int, epoch: Int): Boolean
}

/** The reference [FreshnessStore]: in-memory, lock-synchronised. State dies with the process. */
class InMemoryFreshnessStore : FreshnessStore {
    private val lock = ProtocolLock()
    private val lanes = mutableMapOf<Pair<String, String>, Watermark>()

    private class Watermark(var seq: Int, var epoch: Int)

    override fun wouldAccept(contextId: String, lane: String, seq: Int, epoch: Int): Boolean =
        lock.withLock { admissible(lanes[contextId to lane], seq, epoch) }

    override fun accept(contextId: String, lane: String, seq: Int, epoch: Int): Boolean = lock.withLock {
        val current = lanes[contextId to lane]
        if (!admissible(current, seq, epoch)) return@withLock false
        if (current == null) {
            lanes[contextId to lane] = Watermark(seq, epoch)
        } else {
            current.seq = seq
            current.epoch = epoch
        }
        true
    }

    private fun admissible(current: Watermark?, seq: Int, epoch: Int): Boolean =
        current == null || (seq > current.seq && epoch >= current.epoch)
}
