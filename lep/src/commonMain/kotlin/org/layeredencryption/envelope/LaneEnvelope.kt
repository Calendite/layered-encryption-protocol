package org.layeredencryption.envelope

import org.layeredencryption.Cascade
import org.layeredencryption.CryptoException
import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.decodeUtf8Strict

/**
 * One encrypted op in a device's lane (docs/Protocol.md §7.1).
 *
 * ```
 * device-<id>/op-<seq>.bin   envelope { v, context_id, lane, seq, epoch, ciphertext }
 * ```
 *
 * Only the ciphertext is secret; the envelope header is plaintext so peers can reconcile without
 * decrypting. The header is bound into the payload as AEAD associated data, so a relay cannot
 * re-label an op (move it to another lane, seq or epoch) without the tag failing.
 *
 * ### The epoch
 * [epoch] says which master key sealed this, because that key changes: removing a member rotates
 * it (see [EpochKeys]). Naming the epoch rather than having the reader try every key it holds keeps
 * opening a lookup instead of a search, and being inside the associated data makes it a fact about
 * the message rather than a hint that could be rewritten in flight.
 */
class LaneEnvelope(
    val version: Int,
    val contextId: String,
    val lane: String,
    val seq: Int,
    val epoch: Int,
    val ciphertext: ByteArray,
) {
    fun serialise(): ByteArray = FrameWriter()
        .putBytes(version.toString().encodeToByteArray())
        .putBytes(contextId.encodeToByteArray())
        .putBytes(lane.encodeToByteArray())
        .putBytes(seq.toString().encodeToByteArray())
        .putBytes(epoch.toString().encodeToByteArray())
        .putBytes(ciphertext)
        .toByteArray()

    /** The header bytes bound as AEAD associated data — re-labelling an op breaks decryption. */
    internal fun associatedData(): ByteArray = FrameWriter()
        .putBytes(version.toString().encodeToByteArray())
        .putBytes(contextId.encodeToByteArray())
        .putBytes(lane.encodeToByteArray())
        .putBytes(seq.toString().encodeToByteArray())
        .putBytes(epoch.toString().encodeToByteArray())
        .toByteArray()

    companion object {
        /** v2 added [epoch]. A v1 reader would take that field for the ciphertext. */
        const val VERSION = 2

        /** Generous bound on the id/lane strings; real values are ~64-char hex names. */
        private const val MAX_NAME_BYTES = 1024

        /**
         * Strict: the version must be exactly [VERSION] (an unknown version is rejected *here*,
         * before any of its fields are believed), numeric fields must be canonical non-negative
         * decimal, strings must be valid UTF-8 within [MAX_NAME_BYTES], and the frame must be
         * fully consumed. Every failure is an [IllegalArgumentException].
         */
        fun deserialise(bytes: ByteArray): LaneEnvelope {
            val reader = FrameReader(bytes)
            val version = canonicalNonNegativeInt(reader.readBytes())
            require(version == VERSION) { "Unsupported envelope version $version" }
            val envelope = LaneEnvelope(
                version = version,
                contextId = readName(reader),
                lane = readName(reader),
                seq = canonicalNonNegativeInt(reader.readBytes()),
                epoch = canonicalNonNegativeInt(reader.readBytes()),
                ciphertext = reader.readBytes(),
            )
            reader.expectEnd()
            return envelope
        }

        private fun readName(reader: FrameReader): String {
            val bytes = reader.readBytes()
            require(bytes.size <= MAX_NAME_BYTES) { "Envelope name field exceeds $MAX_NAME_BYTES bytes" }
            return bytes.decodeUtf8Strict()
        }

        /** Exactly the digits [Int.toString] produces: no sign, no leading zero, no whitespace. */
        private fun canonicalNonNegativeInt(bytes: ByteArray): Int {
            val text = bytes.decodeUtf8Strict()
            val value = text.toIntOrNull()
            require(value != null && value >= 0 && value.toString() == text) {
                "Non-canonical integer field: $text"
            }
            return value
        }

        /**
         * Seals [plaintext] into an envelope for [lane]/[seq] under the context master key.
         *
         * Deliberately bytes rather than a typed payload: what the plaintext *means* is the
         * caller's business, and keeping the library ignorant of it is what makes the envelope
         * reusable and auditable on its own terms.
         */
        fun seal(
            provider: CryptoProvider,
            keys: EpochKeys,
            contextId: String,
            lane: String,
            seq: Int,
            plaintext: ByteArray,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): LaneEnvelope {
            // Always the newest key. Taking the whole set rather than one key is what stops a
            // caller sealing under a retired epoch and producing envelopes nobody can open.
            val epoch = keys.current
            val header = LaneEnvelope(VERSION, contextId, lane, seq, epoch, ByteArray(0))
            val ciphertext = Cascade.seal(
                provider, keys.currentKey, plaintext, aad = header.associatedData(), namespace = namespace,
            )
            return LaneEnvelope(VERSION, contextId, lane, seq, epoch, ciphertext)
        }
    }

    /**
     * Opens this envelope, verifying both cascade tags and the header binding, and returns the
     * plaintext bytes. Throws [CryptoException] on tamper — there is no path that returns
     * unauthenticated bytes.
     */
    fun open(
        provider: CryptoProvider,
        keys: EpochKeys,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray {
        val key = keys[epoch] ?: throw CryptoException(
            "No key for epoch $epoch: this device was added after that rotation",
        )
        return Cascade.open(provider, key, ciphertext, aad = associatedData(), namespace = namespace)
    }
}
