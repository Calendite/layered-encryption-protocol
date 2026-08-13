package org.layeredencryption.pairing

import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLimits
import org.layeredencryption.XWing
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.membership.MembershipLog

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

    private const val TAG_BYTES = 1
    private const val LENGTH_PREFIX = 4
    private const val MAC_BYTES = 32
    private const val SAS_COMMITMENT_BYTES = 32
    private const val SAS_NONCE_BYTES = 32

    // Every ceremony message except InviterComplete has exactly one legal size (LEP-09 retest,
    // issue 9.2): all fields are fixed-width, so both the total and each field are checked, and
    // a frame that trades bytes between fields while keeping the total is still rejected.
    private const val INVITER_HELLO_BYTES = TAG_BYTES +
        LENGTH_PREFIX + XWing.PUBLIC_KEY_SIZE +
        LENGTH_PREFIX + DeviceIdentity.SERIALISED_SIZE +
        LENGTH_PREFIX + SAS_COMMITMENT_BYTES
    private const val JOINER_RESPONSE_BYTES = TAG_BYTES +
        LENGTH_PREFIX + XWing.CIPHERTEXT_SIZE +
        LENGTH_PREFIX + DeviceIdentity.SERIALISED_SIZE +
        LENGTH_PREFIX + MAC_BYTES
    private const val INVITER_CONFIRM_BYTES = TAG_BYTES +
        LENGTH_PREFIX + MAC_BYTES +
        LENGTH_PREFIX + SAS_NONCE_BYTES
    private const val SAS_CONFIRMED_BYTES = TAG_BYTES
    private const val INVITER_COMPLETE_MAX_BYTES = TAG_BYTES +
        LENGTH_PREFIX + ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES

    // ── Pairing messages ──────────────────────────────────────────────────────────────────────

    fun encode(message: InviterHello): ByteArray = FrameWriter()
        .putByte(TAG_INVITER_HELLO)
        .putBytes(message.xWingPublicKey)
        .putBytes(message.inviterDeviceIdentity.serialise())
        .putBytes(message.sasCommitment)
        .toByteArray()

    fun decodeInviterHello(frame: ByteArray): InviterHello = expect(frame, TAG_INVITER_HELLO, exactBytes = INVITER_HELLO_BYTES) { reader ->
        InviterHello(
            sized(reader.readBytes(XWing.PUBLIC_KEY_SIZE), XWing.PUBLIC_KEY_SIZE),
            DeviceIdentity.deserialise(reader.readBytes(DeviceIdentity.SERIALISED_SIZE)),
            sized(reader.readBytes(SAS_COMMITMENT_BYTES), SAS_COMMITMENT_BYTES),
        )
    }

    fun encode(message: JoinerResponse): ByteArray = FrameWriter()
        .putByte(TAG_JOINER_RESPONSE)
        .putBytes(message.kemCiphertext)
        .putBytes(message.joinerDeviceIdentity.serialise())
        .putBytes(message.joinerMac)
        .toByteArray()

    fun decodeJoinerResponse(frame: ByteArray): JoinerResponse = expect(frame, TAG_JOINER_RESPONSE, exactBytes = JOINER_RESPONSE_BYTES) { reader ->
        JoinerResponse(
            sized(reader.readBytes(XWing.CIPHERTEXT_SIZE), XWing.CIPHERTEXT_SIZE),
            DeviceIdentity.deserialise(reader.readBytes(DeviceIdentity.SERIALISED_SIZE)),
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

