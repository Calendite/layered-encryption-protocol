package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.invite.AsyncDelivery
import org.layeredencryption.invite.AsyncJoinerResponse
import org.layeredencryption.invite.AsyncWire
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.PairingWire
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The canonical async wire framing — previously each transport's own affair, now one frozen,
 * fail-closed byte layout for the response and delivery messages.
 */
class AsyncWireTest {

    private val provider = BouncyCastleCryptoProvider()
    private val joiner = DeviceKeys.generate(provider)

    private fun response() = AsyncJoinerResponse(
        kemCiphertext = provider.randomBytes(XWing.CIPHERTEXT_SIZE),
        deviceIdentityS = joiner.identity,
        linkProofMac = provider.randomBytes(32),
        joinerMac = provider.randomBytes(32),
    )

    private fun delivery() = AsyncDelivery(
        inviterMac = provider.randomBytes(32),
        serialisedMembershipLog = MembershipLog.found(provider, joiner.identity, joiner.signingKeyPair).serialise(),
    )

    @Test
    fun joinerResponse_roundTripsByteExactly() {
        val message = response()
        val frame = AsyncWire.encode(message)
        val decoded = AsyncWire.decodeJoinerResponse(frame)
        assertContentEquals(frame, AsyncWire.encode(decoded), "must re-encode byte-exactly")
        assertContentEquals(message.kemCiphertext, decoded.kemCiphertext)
        assertContentEquals(message.joinerMac, decoded.joinerMac)
        assertContentEquals(message.deviceIdentityS.serialise(), decoded.deviceIdentityS.serialise())
    }

    @Test
    fun delivery_roundTripsByteExactly() {
        val message = delivery()
        val frame = AsyncWire.encode(message)
        val decoded = AsyncWire.decodeDelivery(frame)
        assertContentEquals(frame, AsyncWire.encode(decoded), "must re-encode byte-exactly")
        assertContentEquals(message.inviterMac, decoded.inviterMac)
        assertContentEquals(message.serialisedMembershipLog, decoded.serialisedMembershipLog)
    }

    @Test
    fun formatVersionAndTags_areFrozenAndGatedFirst() {
        assertEquals(1, AsyncWire.FORMAT_VERSION)
        assertEquals(1, AsyncWire.TAG_JOINER_RESPONSE)
        assertEquals(2, AsyncWire.TAG_DELIVERY)

        val frame = AsyncWire.encode(response())
        assertEquals(1, frame[0].toInt(), "the version byte leads the frame")
        val versioned = frame.copyOf().also { it[0] = 2 }
        assertFailsWith<PairingException>("a future format version fails closed") {
            AsyncWire.decodeJoinerResponse(versioned)
        }
    }

    @Test
    fun frames_neverCrossDecode() {
        val responseFrame = AsyncWire.encode(response())
        val deliveryFrame = AsyncWire.encode(delivery())

        assertFailsWith<PairingException> { AsyncWire.decodeDelivery(responseFrame) }
        assertFailsWith<PairingException> { AsyncWire.decodeJoinerResponse(deliveryFrame) }
        assertFailsWith<PairingException>("trailing byte") { AsyncWire.decodeJoinerResponse(responseFrame + 0) }

        // The async and live-pairing wire families reject each other's frames outright.
        assertFailsWith<PairingException> { PairingWire.decodeInviterHello(responseFrame) }
        assertFailsWith<PairingException> { PairingWire.decodeJoinerResponse(responseFrame) }
        assertFailsWith<PairingException> {
            AsyncWire.decodeJoinerResponse(
                PairingWire.encode(
                    org.layeredencryption.pairing.InviterHello(
                        provider.randomBytes(XWing.PUBLIC_KEY_SIZE), joiner.identity, provider.randomBytes(32),
                    ),
                ),
            )
        }
    }
}
