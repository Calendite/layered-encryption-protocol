package org.layeredencryption.invite

import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLimits
import org.layeredencryption.XWing
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.suite.Suite1
import org.layeredencryption.pairing.PairingException

/**
 * Canonical wire encodings for the async invite's two transported messages — the framing that
 * was previously left to each transport, closing the gap the migration brief flagged: without a
 * canonical byte layout there is nothing to freeze, version, or fuzz.
 *
 * Every frame is `formatVersion(1) ‖ tag(1) ‖ length-framed fields`:
 *
 * ```
 * v1 tag 1  AsyncJoinerResponse: kemCiphertext(1120) ‖ deviceIdentityS(6621)
 *                                ‖ linkProofMac(32) ‖ joinerMac(32)
 * v1 tag 2  AsyncDelivery:       inviterMac(32) ‖ serialisedMembershipLog(≤ 4 MiB)
 * ```
 *
 * Format v1 freezes the currently-shipped Suite 1 flow — the fixed sizes above. The suited
 * (`A3`/bundle-v2) flow gets a format v2 with per-suite sizes when the async session adopts it;
 * a v2 frame fails closed here rather than misparse, exactly like an unknown tag. The version
 * byte leads so that dispatch is decided before a single field is believed.
 *
 * Authentication note: these frames are deliberately not self-authenticating — [AsyncJoinerResponse]'s
 * MACs and [AsyncDelivery]'s `inviterMac` are computed by the session over the async transcript
 * (Async_Invites_Spec.md §2.5–§2.6); the wire layer only guarantees canonical, fail-closed
 * parsing with [PairingException] as the single failure mode.
 */
object AsyncWire {

    const val FORMAT_VERSION = 1
    const val TAG_JOINER_RESPONSE = 1
    const val TAG_DELIVERY = 2

    private const val HEADER_BYTES = 2 // raw version + raw tag
    private const val LENGTH_PREFIX = 4
    private const val MAC_BYTES = 32

    // Every ceremony message has exactly one legal size except the delivery, whose log field is
    // bounded; a frame that trades bytes between fields while keeping the total is rejected by
    // the per-field exact-size checks.
    private val JOINER_RESPONSE_BYTES = HEADER_BYTES +
        LENGTH_PREFIX + XWing.CIPHERTEXT_SIZE +
        LENGTH_PREFIX + DeviceIdentity.serialisedSize(Suite1) +
        LENGTH_PREFIX + MAC_BYTES +
        LENGTH_PREFIX + MAC_BYTES
    private const val DELIVERY_MAX_BYTES = HEADER_BYTES +
        LENGTH_PREFIX + MAC_BYTES +
        LENGTH_PREFIX + ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES

    fun encode(message: AsyncJoinerResponse): ByteArray = FrameWriter()
        .putByte(FORMAT_VERSION)
        .putByte(TAG_JOINER_RESPONSE)
        .putBytes(message.kemCiphertext)
        .putBytes(message.deviceIdentityS.serialise())
        .putBytes(message.linkProofMac)
        .putBytes(message.joinerMac)
        .toByteArray()

    fun decodeJoinerResponse(frame: ByteArray): AsyncJoinerResponse =
        expect(frame, TAG_JOINER_RESPONSE, exactBytes = JOINER_RESPONSE_BYTES) { reader ->
            AsyncJoinerResponse(
                sized(reader.readBytes(XWing.CIPHERTEXT_SIZE), XWing.CIPHERTEXT_SIZE),
                DeviceIdentity.deserialise(reader.readBytes(DeviceIdentity.serialisedSize(Suite1))),
                sized(reader.readBytes(MAC_BYTES), MAC_BYTES),
                sized(reader.readBytes(MAC_BYTES), MAC_BYTES),
            )
        }

    fun encode(message: AsyncDelivery): ByteArray = FrameWriter()
        .putByte(FORMAT_VERSION)
        .putByte(TAG_DELIVERY)
        .putBytes(message.inviterMac)
        .putBytes(message.serialisedMembershipLog)
        .toByteArray()

    fun decodeDelivery(frame: ByteArray): AsyncDelivery =
        expect(frame, TAG_DELIVERY, maxBytes = DELIVERY_MAX_BYTES) { reader ->
            AsyncDelivery(
                sized(reader.readBytes(MAC_BYTES), MAC_BYTES),
                reader.readBytes(ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES),
            )
        }

    /**
     * The single decode boundary, mirroring `PairingWire.expect`: size budget before any copy,
     * version and tag gated before any field, full consumption, and every malformed-frame
     * failure collapsed to [PairingException].
     */
    private inline fun <T> expect(frame: ByteArray, tag: Int, exactBytes: Int = -1, maxBytes: Int = -1, read: (FrameReader) -> T): T {
        try {
            require(exactBytes < 0 || frame.size == exactBytes) { "Async message $tag must be exactly $exactBytes bytes, was ${frame.size}" }
            require(maxBytes < 0 || frame.size <= maxBytes) { "Async message $tag of ${frame.size} bytes exceeds the $maxBytes-byte limit" }
            val reader = FrameReader(frame)
            val version = reader.readByte()
            if (version != FORMAT_VERSION) throw PairingException("Unsupported async wire format version $version")
            val actual = reader.readByte()
            if (actual != tag) throw PairingException("Expected async message $tag, got $actual")
            val message = read(reader)
            reader.expectEnd()
            return message
        } catch (e: PairingException) {
            throw e
        } catch (e: Exception) {
            throw PairingException("Malformed async message $tag")
        }
    }

    /** Exact-size gate for a fixed-width field; anything else fails the frame. */
    private fun sized(bytes: ByteArray, expected: Int): ByteArray {
        require(bytes.size == expected) { "Async wire field must be $expected bytes, was ${bytes.size}" }
        return bytes
    }
}
