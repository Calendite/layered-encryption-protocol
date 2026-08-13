package org.layeredencryption.pairing

import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
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

    // ── Pairing messages ──────────────────────────────────────────────────────────────────────

    fun encode(message: InviterHello): ByteArray = FrameWriter()
        .putByte(TAG_INVITER_HELLO)
        .putBytes(message.xWingPublicKey)
        .putBytes(message.inviterDeviceIdentity.serialise())
        .putBytes(message.sasCommitment)
        .toByteArray()

    fun decodeInviterHello(frame: ByteArray): InviterHello = expect(frame, TAG_INVITER_HELLO) { reader ->
        InviterHello(reader.readBytes(), DeviceIdentity.deserialise(reader.readBytes()), reader.readBytes())
    }

    fun encode(message: JoinerResponse): ByteArray = FrameWriter()
        .putByte(TAG_JOINER_RESPONSE)
        .putBytes(message.kemCiphertext)
        .putBytes(message.joinerDeviceIdentity.serialise())
        .putBytes(message.joinerMac)
        .toByteArray()

    fun decodeJoinerResponse(frame: ByteArray): JoinerResponse = expect(frame, TAG_JOINER_RESPONSE) { reader ->
        JoinerResponse(reader.readBytes(), DeviceIdentity.deserialise(reader.readBytes()), reader.readBytes())
    }

    fun encode(message: InviterConfirm): ByteArray = FrameWriter()
        .putByte(TAG_INVITER_CONFIRM)
        .putBytes(message.inviterMac)
        .putBytes(message.sasNonce)
        .toByteArray()

    fun decodeInviterConfirm(frame: ByteArray): InviterConfirm = expect(frame, TAG_INVITER_CONFIRM) { reader ->
        InviterConfirm(reader.readBytes(), reader.readBytes())
    }

    fun encodeSasConfirmed(): ByteArray = FrameWriter().putByte(TAG_SAS_CONFIRMED).toByteArray()

    fun decodeSasConfirmed(frame: ByteArray) {
        expect(frame, TAG_SAS_CONFIRMED) { }
    }

    fun encode(message: InviterComplete): ByteArray = FrameWriter()
        .putByte(TAG_INVITER_COMPLETE)
        .putBytes(message.membershipLog)
        .toByteArray()

    fun decodeInviterComplete(frame: ByteArray): InviterComplete = expect(frame, TAG_INVITER_COMPLETE) { reader ->
        InviterComplete(reader.readBytes())
    }

    /**
     * The single decode boundary: the tag must match, the fields must consume the frame exactly
     * (trailing bytes rejected), and any malformed-frame failure surfaces as [PairingException] —
     * a hostile frame cannot pick which exception type escapes.
     */
    private inline fun <T> expect(frame: ByteArray, tag: Int, read: (FrameReader) -> T): T {
        try {
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
}

