package org.layeredencryption.storage

import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.envelope.FreshnessStore
import java.nio.file.Path

/**
 * The production [FreshnessStore] (RT-03): per-`(context, lane)` watermarks in one sealed,
 * crash-safe, rollback-evident file (see [SealedStateFile] for the storage discipline).
 *
 * [accept] is a durable atomic compare-and-advance: when it returns `true`, the advanced
 * watermark is fsync'd on disk and mirrored to the witness, so process death immediately after
 * cannot resurrect the envelope. The consumer-side contract from the retest still applies and
 * belongs to the *caller*: a crash after decryption but before the application applies the
 * operation re-delivers nothing (the watermark is already advanced), so apply-then-accept
 * orderings must be idempotent by `(context, lane, seq)`.
 *
 * [key] must come from the platform keystore in production; on Android keep [file] and the
 * witness under `noBackupFilesDir` — a restored freshness store silently re-enables every replay
 * it had refused, which is precisely what the witness turns into a loud [StoreRollbackException].
 */
class FileBackedFreshnessStore private constructor(
    private val engine: SealedStateFile,
) : FreshnessStore {

    /**
     * The production constructor: rollback detection is required, not optional — a freshness
     * store without a witness silently re-enables every refused replay when a stale snapshot is
     * restored. Storage without detection exists only under its honest name,
     * [withoutRollbackDetection].
     */
    constructor(
        file: Path,
        provider: CryptoProvider,
        key: ByteArray,
        witness: RevisionWitness,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ) : this(SealedStateFile(file, provider, key, STORE_KIND, witness, namespace))

    companion object {
        /**
         * A store whose rollback protection is somebody else's job — a platform without a second
         * storage location, or a test. Restoring a stale snapshot of this store re-enables every
         * replay it had refused, without detection; the name is the consent form.
         */
        fun withoutRollbackDetection(
            file: Path,
            provider: CryptoProvider,
            key: ByteArray,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): FileBackedFreshnessStore =
            FileBackedFreshnessStore(SealedStateFile(file, provider, key, STORE_KIND, witness = null, namespace = namespace))

        private const val STORE_KIND = "freshness-store"
        private const val MAX_FIELD = 4096
    }

    private class Watermark(val seq: Int, val epoch: Int)

    override fun wouldAccept(contextId: String, lane: String, seq: Int, epoch: Int): Boolean =
        engine.transact { loaded, _ ->
            admissible(parse(loaded.state)[contextId to lane], seq, epoch)
        }

    override fun accept(contextId: String, lane: String, seq: Int, epoch: Int): Boolean =
        engine.transact { loaded, commit ->
            val lanes = parse(loaded.state)
            if (!admissible(lanes[contextId to lane], seq, epoch)) return@transact false
            lanes[contextId to lane] = Watermark(seq, epoch)
            commit(serialise(lanes))
            true
        }

    private fun admissible(current: Watermark?, seq: Int, epoch: Int): Boolean =
        current == null || (seq > current.seq && epoch >= current.epoch)

    private fun parse(bytes: ByteArray?): LinkedHashMap<Pair<String, String>, Watermark> {
        val lanes = LinkedHashMap<Pair<String, String>, Watermark>()
        if (bytes == null) return lanes
        try {
            val reader = FrameReader(bytes)
            repeat(u32FromBytes(reader.readBytes(4))) {
                val context = reader.readBytes(MAX_FIELD).decodeToString()
                val lane = reader.readBytes(MAX_FIELD).decodeToString()
                val seq = u32FromBytes(reader.readBytes(4))
                val epoch = u32FromBytes(reader.readBytes(4))
                lanes[context to lane] = Watermark(seq, epoch)
            }
            require(!reader.hasRemaining()) { "Trailing bytes after the watermarks" }
        } catch (e: Exception) {
            throw StoreCorruptionException("Freshness-store state failed to parse", e)
        }
        return lanes
    }

    private fun serialise(lanes: Map<Pair<String, String>, Watermark>): ByteArray {
        val writer = FrameWriter().putBytes(u32ToBytes(lanes.size))
        for ((key, watermark) in lanes) {
            writer.putBytes(key.first.encodeToByteArray())
                .putBytes(key.second.encodeToByteArray())
                .putBytes(u32ToBytes(watermark.seq))
                .putBytes(u32ToBytes(watermark.epoch))
        }
        return writer.toByteArray()
    }

}
