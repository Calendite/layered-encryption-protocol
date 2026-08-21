package org.layeredencryption.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import org.layeredencryption.FrameReader
import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceIdentityV2
import org.layeredencryption.identity.KeyTransition
import org.layeredencryption.invite.InviteBundle
import org.layeredencryption.invite.InviteLink
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.SuiteUpgradePayload
import org.layeredencryption.membership.WrappedKeys
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.PairingWire

/**
 * Coverage-guided fuzz targets for every public decoder (LEP-08g).
 *
 * The invariant under test is each decoder's documented contract, the same one
 * `DecoderRobustnessTest` pins with its deterministic corpus: arbitrary bytes either parse, return
 * the documented null/empty, or throw the documented exception type — anything else (a stray
 * `IndexOutOfBounds`, an OOM from an unchecked length, an infinite loop) is a finding, and Jazzer
 * will minimise and report the input that caused it.
 *
 * Run modes: plain `:fuzz:test` replays the committed corpus as regression tests;
 * `JAZZER_FUZZ=1` runs real campaigns. Cryptographic verification (signatures, KEMs) is
 * deliberately outside these targets — fuzzing wants the parser hot loop, not ML-DSA.
 */
class DecoderFuzz {

    private fun allowIllegalArgument(block: () -> Any?) {
        try {
            block()
        } catch (expected: IllegalArgumentException) {
            // The documented failure mode for frame decoders (NumberFormatException included).
        }
    }

    @FuzzTest(maxDuration = "30s")
    fun frameReader(data: ByteArray) = allowIllegalArgument {
        val reader = FrameReader(data)
        while (reader.hasRemaining()) reader.readBytes(1 shl 20)
    }

    @FuzzTest(maxDuration = "30s")
    fun deviceIdentity(data: ByteArray) = allowIllegalArgument { DeviceIdentity.deserialise(data) }

    @FuzzTest(maxDuration = "30s")
    fun deviceIdentityV2(data: ByteArray) = allowIllegalArgument { DeviceIdentityV2.deserialise(data) }

    @FuzzTest(maxDuration = "30s")
    fun keyTransition(data: ByteArray) = allowIllegalArgument { KeyTransition.deserialise(data) }

    @FuzzTest(maxDuration = "30s")
    fun inviteBundle(data: ByteArray) = allowIllegalArgument { InviteBundle.deserialise(data) }

    @FuzzTest(maxDuration = "30s")
    fun membershipLog(data: ByteArray) = allowIllegalArgument { MembershipLog.deserialise(data) }

    @FuzzTest(maxDuration = "30s")
    fun laneEnvelope(data: ByteArray) = allowIllegalArgument { LaneEnvelope.deserialise(data) }

    /** Contract: null on malformed, never a throw. */
    @FuzzTest(maxDuration = "30s")
    fun epochKeys(data: ByteArray) {
        EpochKeys.deserialise(data)
    }

    /** Contract: empty list on malformed, never a throw. */
    @FuzzTest(maxDuration = "30s")
    fun wrappedKeysRecipients(data: ByteArray) {
        WrappedKeys.recipientsOf(data)
    }

    /** Contract: null on anything malformed, never a throw. */
    @FuzzTest(maxDuration = "30s")
    fun suiteUpgradePayload(data: ByteArray) {
        SuiteUpgradePayload.parse(data)
    }

    /** Contract: [PairingException] is the only exception the wire boundary lets out. */
    @FuzzTest(maxDuration = "30s")
    fun pairingWire(data: ByteArray) {
        for (decode in listOf<(ByteArray) -> Any?>(
            PairingWire::decodeInviterHello,
            PairingWire::decodeJoinerResponse,
            PairingWire::decodeInviterConfirm,
            PairingWire::decodeInviterComplete,
            { PairingWire.decodeSasConfirmed(it) },
            PairingWire::decodeSuiteOffer,
            PairingWire::decodeSuiteAccept,
        )) {
            try {
                decode(data)
            } catch (expected: PairingException) {
                // The single documented failure mode.
            }
        }
    }

    /** Contract: null on anything malformed, never a throw. */
    @FuzzTest(maxDuration = "30s")
    fun inviteLink(data: ByteArray) {
        val text = data.decodeToString() // lossy decode is fine: the parser takes a String
        InviteLink.parse(text)
        InviteLink.parseUrl(text)
    }

    /** Contract: null on anything that is not a code, never a throw. */
    @FuzzTest(maxDuration = "30s")
    fun pairingCode(data: ByteArray) {
        PairingCode.canonicalise(data.decodeToString())
    }
}
