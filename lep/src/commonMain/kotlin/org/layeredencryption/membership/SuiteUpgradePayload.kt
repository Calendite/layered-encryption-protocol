package org.layeredencryption.membership

import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLimits
import org.layeredencryption.bytesToInt
import org.layeredencryption.intToBytes
import org.layeredencryption.suite.SuiteId

/**
 * The payload a [MembershipOp.SUITE_UPGRADE] entry carries in its wrapped-keys slot
 * (the migration brief §5). One signed entry binds the transition completely:
 *
 * ```
 * framed( formatVersion(1)=0x01
 *       ‖ oldSuiteId(2 BE)      — must equal the suite active at this entry
 *       ‖ newSuiteId(2 BE)      — known to the verifier, strictly greater than old
 *       ‖ transitionEpoch(4 BE) — cross-checked against the chain walk, never trusted
 *       ‖ wrappedKeys           — a fresh context key sealed for every retained member,
 *                                 under the NEW suite's construction
 *       ‖ keyTransitions )      — MUST be empty in v1; reserved for versioned-identity
 *                                 KeyTransition records (the next migration phase)
 * ```
 *
 * The entry's [MembershipEntry.unsignedBytes] covers the whole payload and the chain hash
 * covers the entry, so the suite change and its fresh keys are atomic: no valid log prefix can
 * show the suite changed without the keys, and truncating inside the entry breaks framing or
 * the signature. Suite transitions are **monotonic in id** — ids are assigned chronologically,
 * and returning to an older construction is the recovery procedure the brief says must never be
 * an ordinary operation. Deliberately not strength-ordered: an equal-strength implementation-
 * diversity migration is legal.
 */
class SuiteUpgradePayload(
    val oldSuite: SuiteId,
    val newSuite: SuiteId,
    val transitionEpoch: Int,
    wrappedKeys: ByteArray,
) {
    private val _wrappedKeys = wrappedKeys.copyOf()

    val wrappedKeys: ByteArray get() = _wrappedKeys.copyOf()

    init {
        require(transitionEpoch >= 1) { "A suite upgrade always follows at least the founding epoch" }
        require(wrappedKeys.size <= ProtocolLimits.MAX_WRAPPED_KEYS_BYTES) { "Wrapped keys exceed the size budget" }
    }

    fun serialise(): ByteArray = FrameWriter()
        .putBytes(byteArrayOf(FORMAT_VERSION.toByte()))
        .putBytes(oldSuite.toWireBytes())
        .putBytes(newSuite.toWireBytes())
        .putBytes(intToBytes(transitionEpoch))
        .putBytes(_wrappedKeys)
        .putBytes(EMPTY_TRANSITIONS)
        .toByteArray()

    companion object {
        const val FORMAT_VERSION = 1

        private val EMPTY_TRANSITIONS = ByteArray(0)
        private const val VERSION_BYTES = 1
        private const val SUITE_ID_BYTES = 2
        private const val EPOCH_BYTES = 4

        /**
         * Strict parse; null on **anything** malformed — the verifier turns null into an invalid
         * log, never a guess. The version byte is gated before any other field is interpreted;
         * a non-empty keyTransitions field is malformed in v1 (an unverifiable transition blob
         * must not ride along before the machinery that verifies one exists).
         */
        fun parse(bytes: ByteArray): SuiteUpgradePayload? = runCatching {
            val reader = FrameReader(bytes)
            val version = reader.readBytes(VERSION_BYTES)
            require(version.size == VERSION_BYTES && version[0].toInt() == FORMAT_VERSION) { "Unknown payload version" }
            val oldSuite = readSuiteId(reader)
            val newSuite = readSuiteId(reader)
            val epochBytes = reader.readBytes(EPOCH_BYTES)
            require(epochBytes.size == EPOCH_BYTES) { "Transition epoch must be $EPOCH_BYTES bytes" }
            val transitionEpoch = bytesToInt(epochBytes, 0)
            val wrappedKeys = reader.readBytes(ProtocolLimits.MAX_WRAPPED_KEYS_BYTES)
            val transitions = reader.readBytes(1)
            require(transitions.isEmpty()) { "Key transitions are not valid in payload v1" }
            reader.expectEnd()
            SuiteUpgradePayload(oldSuite, newSuite, transitionEpoch, wrappedKeys)
        }.getOrNull()

        private fun readSuiteId(reader: FrameReader): SuiteId {
            val bytes = reader.readBytes(SUITE_ID_BYTES)
            require(bytes.size == SUITE_ID_BYTES) { "Suite id must be $SUITE_ID_BYTES bytes" }
            return SuiteId((((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)).toUShort())
        }
    }
}
