package org.layeredencryption.envelope

import org.layeredencryption.Cascade
import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter

/**
 * One encrypted op in a device's lane (docs/Protocol.md §7.1).
 *
 * ```
 * device-<id>/op-<seq>.bin   envelope { v, calendar_id, lane, seq, ciphertext }
 * ```
 *
 * Only the ciphertext is secret; the envelope header is plaintext so peers can reconcile without
 * decrypting. The header is bound into the payload as AEAD associated data, so a relay cannot
 * re-label an op (move it to another lane or seq) without the tag failing.
 */
class LaneEnvelope(
    val version: Int,
    val calendarId: String,
    val lane: String,
    val seq: Int,
    val ciphertext: ByteArray,
) {
    fun serialise(): ByteArray = FrameWriter()
        .putBytes(version.toString().encodeToByteArray())
        .putBytes(calendarId.encodeToByteArray())
        .putBytes(lane.encodeToByteArray())
        .putBytes(seq.toString().encodeToByteArray())
        .putBytes(ciphertext)
        .toByteArray()

    /** The header bytes bound as AEAD associated data — re-labelling an op breaks decryption. */
    internal fun associatedData(): ByteArray = FrameWriter()
        .putBytes(version.toString().encodeToByteArray())
        .putBytes(calendarId.encodeToByteArray())
        .putBytes(lane.encodeToByteArray())
        .putBytes(seq.toString().encodeToByteArray())
        .toByteArray()

    companion object {
        const val VERSION = 1

        fun deserialise(bytes: ByteArray): LaneEnvelope {
            val reader = FrameReader(bytes)
            return LaneEnvelope(
                version = reader.readBytes().decodeToString().toInt(),
                calendarId = reader.readBytes().decodeToString(),
                lane = reader.readBytes().decodeToString(),
                seq = reader.readBytes().decodeToString().toInt(),
                ciphertext = reader.readBytes(),
            )
        }

        /**
         * Seals [plaintext] into an envelope for [lane]/[seq] under the calendar master key.
         *
         * Deliberately bytes rather than a typed payload: what the plaintext *means* is the
         * caller's business, and keeping the library ignorant of it is what makes the envelope
         * reusable and auditable on its own terms.
         */
        fun seal(
            provider: CryptoProvider,
            masterKey: ByteArray,
            calendarId: String,
            lane: String,
            seq: Int,
            plaintext: ByteArray,
        ): LaneEnvelope {
            val header = LaneEnvelope(VERSION, calendarId, lane, seq, ByteArray(0))
            val ciphertext = Cascade.seal(provider, masterKey, plaintext, aad = header.associatedData())
            return LaneEnvelope(VERSION, calendarId, lane, seq, ciphertext)
        }
    }

    /**
     * Opens this envelope, verifying both cascade tags and the header binding, and returns the
     * plaintext bytes. Throws [CryptoException] on tamper — there is no path that returns
     * unauthenticated bytes.
     */
    fun open(provider: CryptoProvider, masterKey: ByteArray): ByteArray =
        Cascade.open(provider, masterKey, ciphertext, aad = associatedData())
}
