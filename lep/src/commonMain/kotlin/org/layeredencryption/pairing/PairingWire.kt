package org.layeredencryption.pairing

import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLimits
import org.layeredencryption.XWing
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.suite.Suite1
import org.layeredencryption.suite.SuiteId
import org.layeredencryption.suite.SuiteRegistry
import org.layeredencryption.suite.SuiteResolver

/**
 * Wire encodings for the pairing ceremony (docs/Protocol.md §6.3).
 *
 * Every frame is `tag(1) ‖ length-framed fields`. Tags are wire constants; an unknown tag, or one
 * that differs from what the protocol step expects, fails closed — there is no skip-and-continue.
 *
 * Only the ceremony lives here. Whatever an application sends *after* pairing is its own affair,
 * and it should pick tags outside this range (the reference implementation uses 10+).
 */
object PairingWire {

    const val TAG_INVITER_HELLO = 1
    const val TAG_JOINER_RESPONSE = 2
    const val TAG_INVITER_CONFIRM = 3
    const val TAG_SAS_CONFIRMED = 4
    const val TAG_INVITER_COMPLETE = 5
    const val TAG_SUITE_OFFER = 6
    const val TAG_SUITE_ACCEPT = 7

    private const val TAG_BYTES = 1
    private const val LENGTH_PREFIX = 4
    private const val MAC_BYTES = 32
    private const val SAS_COMMITMENT_BYTES = 32
    private const val SAS_NONCE_BYTES = 32

    // Every ceremony message except InviterComplete has exactly one legal size (LEP-09 retest,
    // issue 9.2): all fields are fixed-width, so both the total and each field are checked, and
    // a frame that trades bytes between fields while keeping the total is still rejected.
    // Identity sizes are per-suite runtime values now (identities are self-describing); the
    // ceremony currently sizes its frames for Suite 1 until the decoders take the negotiated
    // suite explicitly.
    private val IDENTITY_BYTES = DeviceIdentity.serialisedSize(Suite1)
    private val INVITER_HELLO_BYTES = TAG_BYTES +
        LENGTH_PREFIX + XWing.PUBLIC_KEY_SIZE +
        LENGTH_PREFIX + IDENTITY_BYTES +
        LENGTH_PREFIX + SAS_COMMITMENT_BYTES
    private val JOINER_RESPONSE_BYTES = TAG_BYTES +
        LENGTH_PREFIX + XWing.CIPHERTEXT_SIZE +
        LENGTH_PREFIX + IDENTITY_BYTES +
        LENGTH_PREFIX + MAC_BYTES
    private const val INVITER_CONFIRM_BYTES = TAG_BYTES +
        LENGTH_PREFIX + MAC_BYTES +
        LENGTH_PREFIX + SAS_NONCE_BYTES
    private const val SAS_CONFIRMED_BYTES = TAG_BYTES
    private const val INVITER_COMPLETE_MAX_BYTES = TAG_BYTES +
        LENGTH_PREFIX + ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES

    // Negotiation frames (the migration brief §3): version byte, 32-byte nonce, a u16 suite list
    // whose count is derived from the field length (a separate count would be a second encoding
    // of the same fact — a canonicality hazard), and the sender's policy floor.
    private const val NEGOTIATION_FORMAT_VERSION = 1
    private const val NEGOTIATION_VERSION_BYTES = 1
    private const val SUITE_ID_BYTES = 2
    private const val SUITE_OFFER_MAX_BYTES = TAG_BYTES +
        LENGTH_PREFIX + NEGOTIATION_VERSION_BYTES +
        LENGTH_PREFIX + SuiteNegotiator.NONCE_SIZE +
        LENGTH_PREFIX + SUITE_ID_BYTES * SuiteNegotiator.MAX_SUITES +
        LENGTH_PREFIX + SUITE_ID_BYTES
    private const val SUITE_ACCEPT_MAX_BYTES = SUITE_OFFER_MAX_BYTES +
        LENGTH_PREFIX + SUITE_ID_BYTES

    // ── Pairing messages ──────────────────────────────────────────────────────────────────────

    fun encode(message: InviterHello): ByteArray = FrameWriter()
        .putByte(TAG_INVITER_HELLO)
        .putBytes(message.xWingPublicKey)
        .putBytes(message.inviterDeviceIdentity.serialise())
        .putBytes(message.sasCommitment)
        .toByteArray()

    fun decodeInviterHello(frame: ByteArray, resolver: SuiteResolver = SuiteRegistry): InviterHello =
        expect(frame, TAG_INVITER_HELLO, exactBytes = INVITER_HELLO_BYTES) { reader ->
            InviterHello(
                sized(reader.readBytes(XWing.PUBLIC_KEY_SIZE), XWing.PUBLIC_KEY_SIZE),
                DeviceIdentity.deserialise(reader.readBytes(IDENTITY_BYTES), resolver),
                sized(reader.readBytes(SAS_COMMITMENT_BYTES), SAS_COMMITMENT_BYTES),
            )
        }

    fun encode(message: JoinerResponse): ByteArray = FrameWriter()
        .putByte(TAG_JOINER_RESPONSE)
        .putBytes(message.kemCiphertext)
        .putBytes(message.joinerDeviceIdentity.serialise())
        .putBytes(message.joinerMac)
        .toByteArray()

    fun decodeJoinerResponse(frame: ByteArray, resolver: SuiteResolver = SuiteRegistry): JoinerResponse =
        expect(frame, TAG_JOINER_RESPONSE, exactBytes = JOINER_RESPONSE_BYTES) { reader ->
            JoinerResponse(
                sized(reader.readBytes(XWing.CIPHERTEXT_SIZE), XWing.CIPHERTEXT_SIZE),
                DeviceIdentity.deserialise(reader.readBytes(IDENTITY_BYTES), resolver),
                sized(reader.readBytes(MAC_BYTES), MAC_BYTES),
            )
        }

    fun encode(message: InviterConfirm): ByteArray = FrameWriter()
        .putByte(TAG_INVITER_CONFIRM)
        .putBytes(message.inviterMac)
        .putBytes(message.sasNonce)
        .toByteArray()

    fun decodeInviterConfirm(frame: ByteArray): InviterConfirm = expect(frame, TAG_INVITER_CONFIRM, exactBytes = INVITER_CONFIRM_BYTES) { reader ->
        InviterConfirm(
            sized(reader.readBytes(MAC_BYTES), MAC_BYTES),
            sized(reader.readBytes(SAS_NONCE_BYTES), SAS_NONCE_BYTES),
        )
    }

    fun encodeSasConfirmed(): ByteArray = FrameWriter().putByte(TAG_SAS_CONFIRMED).toByteArray()

    fun decodeSasConfirmed(frame: ByteArray) {
        expect(frame, TAG_SAS_CONFIRMED, exactBytes = SAS_CONFIRMED_BYTES) { }
    }

    fun encode(message: InviterComplete): ByteArray = FrameWriter()
        .putByte(TAG_INVITER_COMPLETE)
        .putBytes(message.membershipLog)
        .toByteArray()

    fun decodeInviterComplete(frame: ByteArray): InviterComplete = expect(frame, TAG_INVITER_COMPLETE, maxBytes = INVITER_COMPLETE_MAX_BYTES) { reader ->
        InviterComplete(reader.readBytes(ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES))
    }

    fun encode(message: SuiteOffer): ByteArray = FrameWriter()
        .putByte(TAG_SUITE_OFFER)
        .putBytes(byteArrayOf(NEGOTIATION_FORMAT_VERSION.toByte()))
        .putBytes(message.nonce)
        .putBytes(suiteIdListBytes(message.supportedSuites))
        .putBytes(message.minimumSuite.toWireBytes())
        .toByteArray()

    fun decodeSuiteOffer(frame: ByteArray): SuiteOffer = expect(frame, TAG_SUITE_OFFER, maxBytes = SUITE_OFFER_MAX_BYTES) { reader ->
        requireNegotiationVersion(reader)
        SuiteOffer(
            sized(reader.readBytes(SuiteNegotiator.NONCE_SIZE), SuiteNegotiator.NONCE_SIZE),
            readSuiteIdList(reader),
            readSuiteId(reader),
        )
    }

    fun encode(message: SuiteAccept): ByteArray = FrameWriter()
        .putByte(TAG_SUITE_ACCEPT)
        .putBytes(byteArrayOf(NEGOTIATION_FORMAT_VERSION.toByte()))
        .putBytes(message.nonce)
        .putBytes(suiteIdListBytes(message.supportedSuites))
        .putBytes(message.minimumSuite.toWireBytes())
        .putBytes(message.selectedSuite.toWireBytes())
        .toByteArray()

    fun decodeSuiteAccept(frame: ByteArray): SuiteAccept = expect(frame, TAG_SUITE_ACCEPT, maxBytes = SUITE_ACCEPT_MAX_BYTES) { reader ->
        requireNegotiationVersion(reader)
        SuiteAccept(
            sized(reader.readBytes(SuiteNegotiator.NONCE_SIZE), SuiteNegotiator.NONCE_SIZE),
            readSuiteIdList(reader),
            readSuiteId(reader),
            readSuiteId(reader),
        )
    }

    /** An unknown negotiation format version fails closed — there is no version fallback. */
    private fun requireNegotiationVersion(reader: FrameReader) {
        val version = sized(reader.readBytes(NEGOTIATION_VERSION_BYTES), NEGOTIATION_VERSION_BYTES)[0].toInt()
        require(version == NEGOTIATION_FORMAT_VERSION) { "Unsupported negotiation format version $version" }
    }

    private fun suiteIdListBytes(ids: List<SuiteId>): ByteArray {
        val out = ByteArray(ids.size * SUITE_ID_BYTES)
        ids.forEachIndexed { index, id -> id.toWireBytes().copyInto(out, index * SUITE_ID_BYTES) }
        return out
    }

    /** Count derived from the field length; structural rules mirror the message constructors. */
    private fun readSuiteIdList(reader: FrameReader): List<SuiteId> {
        val bytes = reader.readBytes(SUITE_ID_BYTES * SuiteNegotiator.MAX_SUITES)
        require(bytes.size % SUITE_ID_BYTES == 0) { "Suite list must be whole u16 ids" }
        val ids = List(bytes.size / SUITE_ID_BYTES) { index -> suiteIdAt(bytes, index * SUITE_ID_BYTES) }
        require(ids.isNotEmpty()) { "Suite list must not be empty" }
        require(ids.toSet().size == ids.size) { "Duplicate suite id in list" }
        return ids
    }

    private fun readSuiteId(reader: FrameReader): SuiteId =
        suiteIdAt(sized(reader.readBytes(SUITE_ID_BYTES), SUITE_ID_BYTES), 0)

    private fun suiteIdAt(bytes: ByteArray, offset: Int): SuiteId =
        SuiteId((((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)).toUShort())

    /**
     * The single decode boundary: the frame's size budget is checked before anything is copied,
     * the tag must match, the fields must consume the frame exactly (trailing bytes rejected),
     * and any malformed-frame failure surfaces as [PairingException] — a hostile frame cannot
     * pick which exception type escapes.
     */
    private inline fun <T> expect(frame: ByteArray, tag: Int, exactBytes: Int = -1, maxBytes: Int = -1, read: (FrameReader) -> T): T {
        try {
            require(exactBytes < 0 || frame.size == exactBytes) { "Message $tag must be exactly $exactBytes bytes, was ${frame.size}" }
            require(maxBytes < 0 || frame.size <= maxBytes) { "Message $tag of ${frame.size} bytes exceeds the $maxBytes-byte limit" }
            val reader = FrameReader(frame)
            val actual = reader.readByte()
            if (actual != tag) throw PairingException("Expected pairing message $tag, got $actual")
            val message = read(reader)
            reader.expectEnd()
            return message
        } catch (e: PairingException) {
            throw e
        } catch (e: Exception) {
            throw PairingException("Malformed pairing message $tag")
        }
    }

    /** Exact-size gate for a fixed-width field; anything else fails the frame. */
    private fun sized(bytes: ByteArray, expected: Int): ByteArray {
        require(bytes.size == expected) { "Pairing field must be $expected bytes, was ${bytes.size}" }
        return bytes
    }
}

