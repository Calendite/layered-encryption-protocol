package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.pairing.InviterHello
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.PairingWire
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The input-size budgets (LEP-09 retest, issue 9.1) and exact pairing field sizes (issue 9.2):
 * oversize input is rejected before copies or cryptography, at the boundary values, and every
 * fixed-width pairing field rejects one byte short and one byte long — including a frame that
 * trades bytes between fields while keeping the correct total.
 */
class SizeBudgetTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    // ── FrameReader field ceiling ─────────────────────────────────────────────────────────────

    @Test
    fun boundedRead_rejectsAtLimitPlusOneBeforeCopying() {
        val atLimit = intToBytes(64) + ByteArray(64)
        assertEquals(64, FrameReader(atLimit).readBytes(64).size, "the limit itself is accepted")

        val overLimit = intToBytes(65) + ByteArray(65)
        val error = assertFailsWith<IllegalArgumentException> { FrameReader(overLimit).readBytes(64) }
        assertTrue(error.message!!.contains("exceeds"), "rejection must be the budget, not underflow")

        // A hostile length that lies beyond the buffer is rejected by the budget before the
        // underflow check ever needs to defend the copy.
        val hostile = intToBytes(Int.MAX_VALUE) + ByteArray(8)
        assertFailsWith<IllegalArgumentException> { FrameReader(hostile).readBytes(64) }
    }

    // ── Decoder totals ────────────────────────────────────────────────────────────────────────

    @Test
    fun membershipLog_rejectsOversizeInputBeforeParsing() {
        val error = assertFailsWith<IllegalArgumentException> {
            MembershipLog.deserialise(ByteArray(ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES + 1))
        }
        assertTrue(error.message!!.contains("exceeds"))
    }

    @Test
    fun laneEnvelope_rejectsOversizeInputBeforeParsing() {
        val error = assertFailsWith<IllegalArgumentException> {
            LaneEnvelope.deserialise(ByteArray(ProtocolLimits.MAX_ENVELOPE_BYTES + 1))
        }
        assertTrue(error.message!!.contains("exceeds"))
    }

    @Test
    fun epochKeys_rejectsOversizeInput() {
        assertNull(EpochKeys.deserialise(ByteArray(ProtocolLimits.MAX_EPOCH_KEYS_BYTES + 1)))
    }

    @Test
    fun membershipEntry_rejectsOversizeWrappedKeysField() {
        // An entry frame whose wrappedKeys field claims more than the per-entry budget: the
        // bounded read rejects it before the copy, regardless of the rest of the entry.
        val entry = FrameWriter()
            .putBytes(ByteArray(32)) // previousHash
            .putByte(1) // ADD
            .putBytes(DeviceKeys.generate(provider).identity.serialise())
            .putBytes(ByteArray(ProtocolLimits.MAX_WRAPPED_KEYS_BYTES + 1))
            .putByte(1)
            .putBytes(ByteArray(HybridSignature.PUBLIC_KEY_SIZE))
            .putBytes(ByteArray(HybridSignature.SIGNATURE_SIZE))
            .toByteArray()
        val log = FrameWriter().putBytes(entry).toByteArray()
        val error = assertFailsWith<IllegalArgumentException> { MembershipLog.deserialise(log) }
        assertTrue(error.message!!.contains("exceeds"))
    }

    // ── Exact pairing message and field sizes ─────────────────────────────────────────────────

    private val device = DeviceKeys.generate(provider)
    private val validHello = PairingWire.encode(
        InviterHello(provider.randomBytes(XWing.PUBLIC_KEY_SIZE), device.identity, provider.randomBytes(32)),
    )

    @Test
    fun pairingMessages_rejectOneByteShortAndOneByteLong() {
        PairingWire.decodeInviterHello(validHello) // the exact size parses
        assertFailsWith<PairingException> { PairingWire.decodeInviterHello(validHello.copyOf(validHello.size - 1)) }
        assertFailsWith<PairingException> { PairingWire.decodeInviterHello(validHello + 0) }
        assertFailsWith<PairingException> { PairingWire.decodeSasConfirmed(PairingWire.encodeSasConfirmed() + 0) }
    }

    @Test
    fun pairingFields_cannotTradeBytesWhileKeepingTheTotal() {
        // One byte moved from the X-Wing key to the SAS commitment: same total, wrong fields.
        val traded = FrameWriter()
            .putByte(PairingWire.TAG_INVITER_HELLO)
            .putBytes(ByteArray(XWing.PUBLIC_KEY_SIZE - 1))
            .putBytes(device.identity.serialise())
            .putBytes(ByteArray(32 + 1))
            .toByteArray()
        assertEquals(validHello.size, traded.size, "the attack premise: totals match")
        assertFailsWith<PairingException> { PairingWire.decodeInviterHello(traded) }
    }

    @Test
    fun everyFixedPairingFieldRejectsOneByteShortAndOneByteLong() {
        val identity = device.identity.serialise()
        class Message(val tag: Int, val fields: List<ByteArray>, val decode: (ByteArray) -> Any)
        val messages = listOf(
            Message(PairingWire.TAG_INVITER_HELLO, listOf(ByteArray(XWing.PUBLIC_KEY_SIZE), identity, ByteArray(32))) { PairingWire.decodeInviterHello(it) },
            Message(PairingWire.TAG_JOINER_RESPONSE, listOf(ByteArray(XWing.CIPHERTEXT_SIZE), identity, ByteArray(32))) { PairingWire.decodeJoinerResponse(it) },
            Message(PairingWire.TAG_INVITER_CONFIRM, listOf(ByteArray(32), ByteArray(32))) { PairingWire.decodeInviterConfirm(it) },
        )
        for (message in messages) {
            message.decode(frame(message.tag, message.fields)) // the exact sizes decode
            for (index in message.fields.indices) {
                for (delta in intArrayOf(-1, +1)) {
                    val mutated = message.fields.mapIndexed { i, field ->
                        if (i == index) ByteArray(field.size + delta) else field
                    }
                    assertFailsWith<PairingException>("tag ${message.tag}, field $index, delta $delta") {
                        message.decode(frame(message.tag, mutated))
                    }
                }
            }
        }
    }

    private fun frame(tag: Int, fields: List<ByteArray>): ByteArray {
        val writer = FrameWriter().putByte(tag)
        fields.forEach { writer.putBytes(it) }
        return writer.toByteArray()
    }

    @Test
    fun totalBudgetsBiteAtExactlyLimitPlusOne() {
        // At the limit: past the budget gate (the zeros then fail for content reasons).
        val atLimit = assertFailsWith<IllegalArgumentException> {
            MembershipLog.deserialise(ByteArray(ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES))
        }
        assertTrue(!atLimit.message!!.contains("exceeds the ${ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES}"), "the limit itself passes the gate")

        // One past the limit: the budget error, before any parsing.
        val overLimit = assertFailsWith<IllegalArgumentException> {
            MembershipLog.deserialise(ByteArray(ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES + 1))
        }
        assertTrue(overLimit.message!!.contains("exceeds"))
    }

    @Test
    fun inviterComplete_rejectsAnOversizeMembershipLog() {
        val oversize = FrameWriter()
            .putByte(PairingWire.TAG_INVITER_COMPLETE)
            .putBytes(ByteArray(ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES + 1))
            .toByteArray()
        assertFailsWith<PairingException> { PairingWire.decodeInviterComplete(oversize) }
    }
}
