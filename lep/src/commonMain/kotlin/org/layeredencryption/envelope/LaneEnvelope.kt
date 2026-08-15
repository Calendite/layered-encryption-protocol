package org.layeredencryption.envelope

import org.layeredencryption.Cascade
import org.layeredencryption.CryptoException
import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLimits
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
    ciphertext: ByteArray,
) {
    private val _ciphertext = ciphertext.copyOf()

    /** A defensive copy; the envelope's own bytes cannot be mutated after construction. */
    val ciphertext: ByteArray get() = _ciphertext.copyOf()

    fun serialise(): ByteArray = FrameWriter()
        .putBytes(version.toString().encodeToByteArray())
        .putBytes(contextId.encodeToByteArray())
        .putBytes(lane.encodeToByteArray())
        .putBytes(seq.toString().encodeToByteArray())
        .putBytes(epoch.toString().encodeToByteArray())
        .putBytes(_ciphertext)
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
            require(bytes.size <= ProtocolLimits.MAX_ENVELOPE_BYTES) {
                "Envelope of ${bytes.size} bytes exceeds the ${ProtocolLimits.MAX_ENVELOPE_BYTES}-byte limit"
            }
            val reader = FrameReader(bytes)
            val version = canonicalNonNegativeInt(reader.readBytes(MAX_INT_DIGITS))
            require(version == VERSION) { "Unsupported envelope version $version" }
            val envelope = LaneEnvelope(
                version = version,
                contextId = readName(reader),
                lane = readName(reader),
                seq = canonicalNonNegativeInt(reader.readBytes(MAX_INT_DIGITS)),
                epoch = canonicalNonNegativeInt(reader.readBytes(MAX_INT_DIGITS)),
                ciphertext = reader.readBytes(),
            )
            reader.expectEnd()
            return envelope
        }

        /** `Int.MAX_VALUE` is 10 decimal digits; a longer field cannot be a canonical int. */
        private const val MAX_INT_DIGITS = 10

        private fun readName(reader: FrameReader): String =
            reader.readBytes(MAX_NAME_BYTES).decodeUtf8Strict()

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
     *
     * The name is the warning (RT-04): this is the *stateless* open — it proves the envelope was
     * never modified, and nothing else. A previously valid envelope replayed by a relay opens
     * here happily. It exists for exactly two jobs: re-reading envelopes from **trusted local
     * storage** this device already accepted once, and recovery flows replaying a store it
     * trusts. Anything arriving over a transport — relay, LAN peer, backup restore — must go
     * through [openAndValidate], which also proves the envelope is *new*.
     */
    fun openWithoutReplayProtection(
        provider: CryptoProvider,
        keys: EpochKeys,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray {
        val key = keys[epoch] ?: throw CryptoException(
            "No key for epoch $epoch: this device was added after that rotation",
        )
        return Cascade.open(provider, key, _ciphertext, aad = associatedData(), namespace = namespace)
    }

    /**
     * The stateful open (LEP-04), and the normal way to open an envelope: everything
     * [openWithoutReplayProtection] does, plus proof of freshness against the caller's
     * expectations and the lane's accepted watermark.
     *
     * Rejected with [ReplayException], in order, before any decryption:
     * 1. a header naming a different [expectedContextId] or [expectedLane] — AEAD binds the
     *    header to the ciphertext, but only the caller knows which lane it *meant* to read;
     * 2. a `(seq, epoch)` the [freshness] store would refuse — replays, duplicate or regressed
     *    sequences, and retired epochs die at header-read cost, before the cascade runs.
     *
     * **[deliver] is where the application takes durable custody of the plaintext**, and the
     * watermark advances only after it returns. That ordering is the crash contract: die
     * before or inside [deliver] and the envelope is still fresh, so the peer's re-send simply
     * delivers it; die after [deliver] but before the watermark commits and the re-send
     * re-delivers it exactly once. Either way an authenticated operation is never *lost* —
     * which is why [deliver] must be idempotent per `(context, lane, seq)`: at-least-once is
     * the deliberate choice, because the watermark-first alternative silently discards an
     * operation whenever a crash lands in the window, with retransmission refused as stale.
     * The same idempotency covers two in-process racers of one envelope: each may deliver, the
     * watermark advances once.
     *
     * Authentication still precedes any recording — unauthenticated garbage with a high
     * sequence number must not burn a lane's sequences and suppress real operations.
     *
     * What this deliberately does not decide: whether a sequence *gap* is relay suppression or
     * ordinary not-yet-delivered reordering, and whether the lane's author is still an active
     * member — adopt membership via `MembershipLog.resolveFork` and check `activeIdentities`
     * before honouring a lane; both remain the consumer's synchronisation policy, stated here
     * so the boundary is explicit rather than implied.
     */
    fun <T> openAndValidate(
        provider: CryptoProvider,
        keys: EpochKeys,
        expectedContextId: String,
        expectedLane: String,
        freshness: FreshnessStore,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        deliver: (ByteArray) -> T,
    ): T {
        if (contextId != expectedContextId) {
            throw ReplayException("Envelope is for context '$contextId', expected '$expectedContextId'")
        }
        if (lane != expectedLane) {
            throw ReplayException("Envelope is for lane '$lane', expected '$expectedLane'")
        }
        if (!freshness.wouldAccept(contextId, lane, seq, epoch)) {
            throw ReplayException("Stale envelope for lane '$lane': seq=$seq epoch=$epoch is not fresh")
        }

        val plaintext = openWithoutReplayProtection(provider, keys, namespace)
        val delivered = deliver(plaintext)

        // The watermark advances last, and losing this atomic race is not an error: the racer
        // that won also delivered, and delivery is idempotent by contract.
        freshness.accept(contextId, lane, seq, epoch)
        return delivered
    }
}
