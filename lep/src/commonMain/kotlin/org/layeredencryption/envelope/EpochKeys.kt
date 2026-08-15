package org.layeredencryption.envelope

import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLimits
import org.layeredencryption.intToBytes
import org.layeredencryption.bytesToInt

/**
 * Every master key a context has ever had, indexed by the epoch it belongs to.
 *
 * A context has one key until somebody is removed. Removing a member has to rotate it, or removal
 * would be cosmetic: the person walks away still holding the key, and on a relay-backed context
 * they can keep reading the mailbox indefinitely. Rotation is what makes "they stop seeing your
 * events" a statement about cryptography rather than about good manners.
 *
 * The old keys have to be kept, though, or the rotation would take the shared history with it. So
 * a device holds them all: it **seals** with [currentKey] and **opens** with whichever epoch the
 * envelope names.
 *
 * Passing this around instead of a bare key is deliberate. With a single `ByteArray` there is
 * nothing to stop a caller sealing under a key that has since been retired, which would produce
 * envelopes nobody can read and no error to say so.
 *
 * ### Retention policy (RT-06)
 *
 * Retention is **indefinite by default and bounded by choice**: the library never prunes on its
 * own, because "how much history a device can read" is a product decision, not a cryptographic
 * one. Who holds what:
 *
 * - a **founding or synchronously-paired device** holds every epoch — sync pairing transfers the
 *   full serialised set, because both sides belong to the same person;
 * - a **member added later** (a membership-log `ADD`, or an async invite — which founds a fresh
 *   context of its own) starts at its join epoch: rotation entries wrap exactly one 32-byte key,
 *   pre-join epochs are simply absent here, and [get] answering null for them is the designed
 *   behaviour, not data loss;
 * - an application enforcing a retention window prunes with [retainingFrom] and destroys the
 *   superseded instance — with the at-rest copy rewritten (the sealed-file stores rewrite
 *   wholesale), that is cryptographic erasure of the dropped epochs on this device.
 *
 * The security consequences, stated plainly: within the retained window there is **no forward
 * secrecy** — compromising a device exposes every epoch it holds, which is the accepted price of
 * readable history. Across rotations there **is** post-compromise security: an attacker excluded
 * from a rotation cannot read anything sealed after it, and epoch monotonicity in the freshness
 * store stops a retired-epoch holder forging fresh traffic. An attacker holding a *current*
 * member's key material keeps reading until that member is revoked.
 */
class EpochKeys private constructor(byEpoch: Map<Int, ByteArray>) {

    // Keys are copied in and copied out: a caller mutating what it passed or what it read
    // cannot corrupt the held set.
    private val byEpoch: Map<Int, ByteArray> = byEpoch.mapValues { it.value.copyOf() }

    init {
        require(this.byEpoch.isNotEmpty()) { "A context has at least one key" }
        require(this.byEpoch.keys.all { it >= 0 }) { "Epochs count up from zero" }
    }

    /** The newest epoch, which is the one to seal under. */
    val current: Int = this.byEpoch.keys.max()

    private var destroyed = false

    /** The key for [current], as a defensive copy. */
    val currentKey: ByteArray get() = guarded(byEpoch.getValue(current))

    /** Every epoch held, ascending. */
    val epochs: List<Int> get() = byEpoch.keys.sorted()

    /**
     * Zeroes every held key and makes later key reads throw [IllegalStateException] — for when a
     * context is torn down. Idempotent, and best-effort like all in-memory scrubbing: copies
     * already handed out are beyond reach. Instances derived via [withNextEpoch] are independent.
     */
    fun destroy() {
        destroyed = true
        byEpoch.values.forEach { it.fill(0) }
    }

    private fun guarded(key: ByteArray): ByteArray {
        check(!destroyed) { "EpochKeys has been destroyed" }
        return key.copyOf()
    }

    /**
     * The key for [epoch] (a defensive copy), or null if this device does not hold it.
     *
     * Null is a legitimate answer, not a fault: a device added after a rotation never receives the
     * keys from before it, so envelopes from those epochs are not readable here and never will be.
     * Callers should treat that as "not for me" rather than as corruption.
     */
    operator fun get(epoch: Int): ByteArray? = byEpoch[epoch]?.let { guarded(it) }

    /** This set plus [key] at the next epoch. Used when a rotation happens. */
    fun withNextEpoch(key: ByteArray): EpochKeys {
        check(!destroyed) { "EpochKeys has been destroyed" }
        return EpochKeys(byEpoch + (current + 1 to key))
    }

    /**
     * This set without any epoch below [oldestRetained] — the retention-policy primitive (RT-06).
     *
     * Envelopes from the dropped epochs become permanently unreadable on this device, exactly as
     * they already are on a device added after those rotations. Erasure is only as real as the
     * caller's follow-through: [destroy] the superseded instance and rewrite the at-rest copy
     * (the sealed-file stores rewrite wholesale on every commit). [current] always survives —
     * pruning the sealing key is dissolution, not retention.
     */
    fun retainingFrom(oldestRetained: Int): EpochKeys {
        check(!destroyed) { "EpochKeys has been destroyed" }
        require(oldestRetained <= current) { "Retaining from $oldestRetained would drop the current epoch $current" }
        return EpochKeys(byEpoch.filterKeys { it >= oldestRetained })
    }

    /** `epoch ‖ key` pairs, framed, ascending. Encrypted at rest by whatever stores it. */
    fun serialise(): ByteArray {
        check(!destroyed) { "EpochKeys has been destroyed" }
        val writer = FrameWriter()
        for (epoch in epochs) {
            writer.putBytes(intToBytes(epoch))
            writer.putBytes(byEpoch.getValue(epoch))
        }
        return writer.toByteArray()
    }

    companion object {
        /** A context that has never rotated: one key, at epoch zero. */
        fun founding(masterKey: ByteArray): EpochKeys = EpochKeys(mapOf(0 to masterKey))

        fun of(byEpoch: Map<Int, ByteArray>): EpochKeys = EpochKeys(byEpoch)

        /** One rotation per revoke: even an absurdly churned context stays far below this. */
        private const val MAX_EPOCHS = 10_000

        private const val EPOCH_BYTES = 4
        private const val KEY_BYTES = 32

        /**
         * Reads [serialise]. Returns null rather than throwing on anything malformed — and
         * "malformed" is strict: epochs must be exactly 4 bytes and strictly ascending (which
         * makes them unique and the encoding canonical), keys exactly 32 bytes, and the count
         * bounded. Accepting a duplicate epoch would let later bytes silently replace an
         * earlier key.
         */
        fun deserialise(bytes: ByteArray): EpochKeys? = runCatching {
            require(bytes.size <= ProtocolLimits.MAX_EPOCH_KEYS_BYTES) {
                "EpochKeys blob of ${bytes.size} bytes exceeds the ${ProtocolLimits.MAX_EPOCH_KEYS_BYTES}-byte limit"
            }
            val reader = FrameReader(bytes)
            val byEpoch = mutableMapOf<Int, ByteArray>()
            var previousEpoch = -1
            while (reader.hasRemaining()) {
                require(byEpoch.size < MAX_EPOCHS) { "More than $MAX_EPOCHS epochs" }
                val epochBytes = reader.readBytes()
                require(epochBytes.size == EPOCH_BYTES) { "Epoch must be $EPOCH_BYTES bytes" }
                val epoch = bytesToInt(epochBytes, 0)
                require(epoch > previousEpoch) { "Epochs must be unique and ascending" }
                val key = reader.readBytes()
                require(key.size == KEY_BYTES) { "Epoch key must be $KEY_BYTES bytes" }
                byEpoch[epoch] = key
                previousEpoch = epoch
            }
            EpochKeys(byEpoch)
        }.getOrNull()
    }
}
