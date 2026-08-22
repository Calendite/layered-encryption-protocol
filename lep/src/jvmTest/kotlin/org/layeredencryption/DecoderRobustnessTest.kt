package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.identity.KeyTransition
import org.layeredencryption.invite.InviteBundle
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.membership.WrappedKeys
import org.layeredencryption.pairing.InviterHello
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.PairingWire
import org.layeredencryption.pairing.SuiteAccept
import org.layeredencryption.pairing.SuiteOffer
import org.layeredencryption.suite.SuiteId
import kotlin.random.Random
import org.layeredencryption.suite.Suite1
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Every wire decoder, fed deterministic mutations of valid bytes: bit flips, truncations,
 * appended garbage, pure noise. The contract under test is that a decoder either succeeds,
 * returns its documented null, or throws its documented exception type — hostile bytes cannot
 * pick a different exception, and no failure path leaves the reader out of a controlled state.
 */
class DecoderRobustnessTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private val founder = DeviceKeys.generate(provider)
    private val member = DeviceKeys.generate(provider)

    private val identityBytes = founder.identity.serialise()
    private val logBytes = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
        .append(provider, MembershipOp.ADD, member.identity, provider.randomBytes(64), signer = founder.signingKeyPair)
        .serialise()
    private val envelopeBytes = LaneEnvelope.seal(
        provider, EpochKeys.founding(provider.randomBytes(32)), "ctx", "device-1", seq = 7, plaintext = "op".encodeToByteArray(),
    ).serialise()
    private val bundleBytes = InviteBundle.build(
        provider, XWing.generateKeyPair(provider).publicKey, founder,
        expiryEpochSeconds = 1_000_000L, ridAsync = provider.randomBytes(32),
    ).serialise()
    private val helloFrame = PairingWire.encode(
        InviterHello(provider.randomBytes(XWing.PUBLIC_KEY_SIZE), founder.identity, provider.randomBytes(32)),
    )
    private val epochKeysBytes = EpochKeys.founding(provider.randomBytes(32))
        .withNextEpoch(provider.randomBytes(32))
        .serialise()
    private val wrappedBlob = WrappedKeys.wrapFor(provider, Suite1, listOf(founder.identity, member.identity), provider.randomBytes(32))

    /** Deterministic corpus: same seed, same mutations, every run. */
    private fun mutations(bytes: ByteArray): List<ByteArray> {
        val random = Random(20_260_813)
        val out = mutableListOf(ByteArray(0))
        repeat(60) {
            val copy = bytes.copyOf()
            copy[random.nextInt(copy.size)] = random.nextInt(256).toByte()
            out += copy
        }
        repeat(30) { out += bytes.copyOf(random.nextInt(bytes.size)) }
        repeat(10) { out += bytes + ByteArray(random.nextInt(1, 16)) { random.nextInt(256).toByte() } }
        repeat(10) { out += ByteArray(random.nextInt(1, 64)) { random.nextInt(256).toByte() } }
        return out
    }

    private fun assertOnlyThrows(allowed: (Throwable) -> Boolean, corpus: List<ByteArray>, decode: (ByteArray) -> Any?) {
        for (input in corpus) {
            try {
                decode(input)
            } catch (e: Throwable) {
                if (!allowed(e)) fail("Uncontrolled ${e::class.simpleName} for ${input.size}-byte input: ${e.message}")
            }
        }
    }

    private val illegalArgumentOnly: (Throwable) -> Boolean = { it is IllegalArgumentException }
    private val pairingExceptionOnly: (Throwable) -> Boolean = { it is PairingException }
    private val nothing: (Throwable) -> Boolean = { false }

    // ── The mutation sweep, decoder by decoder ────────────────────────────────────────────────

    @Test
    fun deviceIdentity_throwsOnlyIllegalArgument() =
        assertOnlyThrows(illegalArgumentOnly, mutations(identityBytes)) { DeviceIdentity.deserialise(it) }

    @Test
    fun keyTransition_throwsOnlyIllegalArgument() {
        val transition = KeyTransition.create(
            provider, founder, DeviceKeys.generate(provider),
        ).serialise()
        assertOnlyThrows(illegalArgumentOnly, mutations(transition)) { KeyTransition.deserialise(it) }
    }

    @Test
    fun membershipLog_throwsOnlyIllegalArgument() =
        assertOnlyThrows(illegalArgumentOnly, mutations(logBytes)) { MembershipLog.deserialise(it) }

    @Test
    fun laneEnvelope_throwsOnlyIllegalArgument() =
        assertOnlyThrows(illegalArgumentOnly, mutations(envelopeBytes)) { LaneEnvelope.deserialise(it) }

    @Test
    fun inviteBundle_throwsOnlyIllegalArgument() =
        assertOnlyThrows(illegalArgumentOnly, mutations(bundleBytes)) { InviteBundle.deserialise(it) }

    @Test
    fun pairingWire_throwsOnlyPairingException() =
        assertOnlyThrows(pairingExceptionOnly, mutations(helloFrame)) { PairingWire.decodeInviterHello(it) }

    @Test
    fun asyncWireFrames_throwOnlyPairingException() {
        val response = org.layeredencryption.invite.AsyncWire.encode(
            org.layeredencryption.invite.AsyncJoinerResponse(
                provider.randomBytes(XWing.CIPHERTEXT_SIZE), founder.identity,
                provider.randomBytes(32), provider.randomBytes(32),
            ),
        )
        val delivery = org.layeredencryption.invite.AsyncWire.encode(
            org.layeredencryption.invite.AsyncDelivery(provider.randomBytes(32), logBytes),
        )
        assertOnlyThrows(pairingExceptionOnly, mutations(response)) {
            org.layeredencryption.invite.AsyncWire.decodeJoinerResponse(it)
        }
        assertOnlyThrows(pairingExceptionOnly, mutations(delivery)) {
            org.layeredencryption.invite.AsyncWire.decodeDelivery(it)
        }
    }

    @Test
    fun suiteNegotiationFrames_throwOnlyPairingException() {
        val offer = PairingWire.encode(
            SuiteOffer(provider.randomBytes(32), listOf(SuiteId.LEP_HYBRID_2026), SuiteId.LEP_HYBRID_2026),
        )
        val accept = PairingWire.encode(
            SuiteAccept(provider.randomBytes(32), listOf(SuiteId.LEP_HYBRID_2026), SuiteId.LEP_HYBRID_2026, SuiteId.LEP_HYBRID_2026),
        )
        assertOnlyThrows(pairingExceptionOnly, mutations(offer)) { PairingWire.decodeSuiteOffer(it) }
        assertOnlyThrows(pairingExceptionOnly, mutations(accept)) { PairingWire.decodeSuiteAccept(it) }
    }

    @Test
    fun epochKeys_neverThrows() =
        assertOnlyThrows(nothing, mutations(epochKeysBytes)) { EpochKeys.deserialise(it) }

    @Test
    fun wrappedKeys_neverThrows() =
        assertOnlyThrows(nothing, mutations(wrappedBlob)) {
            WrappedKeys.recipientsOf(Suite1, it)
            WrappedKeys.unwrapFor(provider, Suite1, it, member)
        }

    // ── Targeted canonical rejections ─────────────────────────────────────────────────────────

    @Test
    fun frameReader_hostileLengthIsCheckedSubtraction() {
        // A length of Int.MAX_VALUE would wrap `position + length` negative and slip past an
        // additive bounds check; the checked-subtraction guard must reject it cleanly.
        val hostile = intToBytes(Int.MAX_VALUE) + ByteArray(4)
        assertFailsWith<IllegalArgumentException> { FrameReader(hostile).readBytes() }
    }

    @Test
    fun decoders_rejectTrailingBytes() {
        assertFailsWith<IllegalArgumentException> { DeviceIdentity.deserialise(identityBytes + 0) }
        assertFailsWith<IllegalArgumentException> { LaneEnvelope.deserialise(envelopeBytes + 0) }
        assertFailsWith<IllegalArgumentException> { InviteBundle.deserialise(bundleBytes + 0) }
        assertFailsWith<PairingException> { PairingWire.decodeInviterHello(helloFrame + 0) }
    }

    @Test
    fun laneEnvelope_rejectsUnknownVersionsAndNonCanonicalNumbers() {
        fun envelope(version: String, seq: String) = FrameWriter()
            .putBytes(version.encodeToByteArray())
            .putBytes("1".encodeToByteArray()) // suite id
            .putBytes("ctx".encodeToByteArray())
            .putBytes("lane".encodeToByteArray())
            .putBytes(seq.encodeToByteArray())
            .putBytes("0".encodeToByteArray())
            .putBytes(ByteArray(48))
            .toByteArray()

        LaneEnvelope.deserialise(envelope("3", "7")) // the canonical form parses
        assertFailsWith<IllegalArgumentException>("retired version") { LaneEnvelope.deserialise(envelope("2", "7")) }
        assertFailsWith<IllegalArgumentException>("newer version") { LaneEnvelope.deserialise(envelope("4", "7")) }
        assertFailsWith<IllegalArgumentException>("negative seq") { LaneEnvelope.deserialise(envelope("3", "-1")) }
        assertFailsWith<IllegalArgumentException>("leading zero") { LaneEnvelope.deserialise(envelope("3", "07")) }
        assertFailsWith<IllegalArgumentException>("plus sign") { LaneEnvelope.deserialise(envelope("3", "+7")) }
        assertFailsWith<IllegalArgumentException>("overflow") { LaneEnvelope.deserialise(envelope("3", "9999999999")) }
    }

    @Test
    fun epochKeys_rejectsNonCanonicalStructures() {
        fun blob(build: FrameWriter.() -> Unit): ByteArray = FrameWriter().apply(build).toByteArray()
        val key = ByteArray(32)

        assertNull(EpochKeys.deserialise(blob { putBytes(ByteArray(3)); putBytes(key) }), "3-byte epoch")
        assertNull(EpochKeys.deserialise(blob { putBytes(intToBytes(0)); putBytes(ByteArray(31)) }), "31-byte key")
        assertNull(
            EpochKeys.deserialise(blob {
                putBytes(intToBytes(1)); putBytes(key)
                putBytes(intToBytes(1)); putBytes(key)
            }),
            "duplicate epoch",
        )
        assertNull(
            EpochKeys.deserialise(blob {
                putBytes(intToBytes(2)); putBytes(key)
                putBytes(intToBytes(1)); putBytes(key)
            }),
            "descending epochs",
        )
        assertNull(EpochKeys.deserialise(blob { putBytes(intToBytes(-1)); putBytes(key) }), "negative epoch")
    }

    @Test
    fun membershipLog_rejectsEmptyAndNonCanonicalEntries() {
        assertIs<MembershipVerification.Invalid>(
            MembershipLog.deserialise(ByteArray(0)).verify(provider),
            "an empty log must not verify as a valid zero-member context",
        )

        val entry = MembershipLog.found(provider, founder.identity, founder.signingKeyPair).entries.single()
        fun reserialised(flag: Int, wrapped: ByteArray) = FrameWriter().putBytes(
            FrameWriter()
                .putBytes(entry.previousHash)
                .putByte(entry.op.code)
                .putBytes(entry.deviceIdentity.serialise())
                .putBytes(wrapped)
                .putByte(flag)
                .putBytes(entry.signerPublicKey)
                .putBytes(entry.signature)
                .toByteArray(),
        ).toByteArray()

        MembershipLog.deserialise(reserialised(flag = 0, wrapped = ByteArray(0))) // canonical form parses
        assertFailsWith<IllegalArgumentException>("flag must be 0 or 1") {
            MembershipLog.deserialise(reserialised(flag = 7, wrapped = ByteArray(0)))
        }
        assertFailsWith<IllegalArgumentException>("absent wrappedKeys must be empty") {
            MembershipLog.deserialise(reserialised(flag = 0, wrapped = ByteArray(8)))
        }
    }

    @Test
    fun pairingCode_forgivesOnlySeparatorsAndWhitespace() {
        val code = "K7M4F2X94BQR1TZP9WVC3HND"
        assertTrue(PairingCode.canonicalise("K7M4-F2X9-4BQR 1TZP-9WVC-3HND") == code, "hyphens and spaces fold away")
        assertTrue(PairingCode.canonicalise("K7M4-F2X9-4BQR\n1TZP-9WVC-3HND") == code, "newlines fold away")

        // Anything else must reject the input, not be silently dropped: the old strip-everything
        // rule meant unboundedly many strings canonicalised to the same code.
        assertNull(PairingCode.canonicalise("K7M4*F2X9*4BQR*1TZP*9WVC*3HND"), "punctuation is not a separator")
        assertNull(PairingCode.canonicalise("K7M4.F2X9.4BQR.1TZP.9WVC.3HND"), "dots are not separators")
        assertNull(PairingCode.canonicalise("${code}!"), "trailing junk")
    }
}
