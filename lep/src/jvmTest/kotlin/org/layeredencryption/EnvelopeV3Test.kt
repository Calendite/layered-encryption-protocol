package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.InMemoryFreshnessStore
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.envelope.ReplayException
import org.layeredencryption.suite.FakeSuites
import org.layeredencryption.suite.Suite1
import org.layeredencryption.suite.SuiteId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Version 3 lane envelopes (the migration brief §6): the suite id joins the header and the
 * AEAD associated data, version 2 stays byte-frozen as the Suite 1 default, and an envelope
 * naming a suite this build does not know fails closed at parse.
 */
class EnvelopeV3Test {

    private val provider = BouncyCastleCryptoProvider()
    private val fake = FakeSuites.fakeSuite()
    private val resolver = FakeSuites.resolverWith(fake)

    private val masterKey = provider.randomBytes(32)
    private val keys = EpochKeys.founding(masterKey)
    private val plaintext = "suited envelope".encodeToByteArray()

    private fun sealedV3() = LaneEnvelope.sealSuited(
        provider, keys, fake, contextId = "ctx", lane = "device-1", seq = 7, plaintext = plaintext,
    )

    @Test
    fun v3_roundTripsAndOpensUnderItsSuite() {
        val envelope = sealedV3()
        assertEquals(LaneEnvelope.VERSION_SUITED, envelope.version)
        assertEquals(FakeSuites.FAKE_ID, envelope.suiteId)

        val bytes = envelope.serialise()
        val decoded = LaneEnvelope.deserialise(bytes, resolver)
        assertEquals(FakeSuites.FAKE_ID, decoded.suiteId)
        assertEquals(7, decoded.seq)
        assertContentEquals(bytes, decoded.serialise(), "v3 must re-serialise byte-exactly")
        assertContentEquals(plaintext, decoded.openWithoutReplayProtection(provider, keys, resolver = resolver))
    }

    @Test
    fun suiteId_isBoundIntoTheAssociatedData() {
        // Same ciphertext, same everything, re-labelled to a different (registered, and even
        // cryptographically identical) suite: the AAD differs, so decryption must fail.
        val twin = FakeSuites.fakeSuite(id = SuiteId(0xFF01u), name = "TEST_TWIN")
        val twinResolver = FakeSuites.resolverWith(fake, twin)
        val envelope = sealedV3()
        val relabelled = LaneEnvelope(
            LaneEnvelope.VERSION_SUITED, envelope.contextId, envelope.lane, envelope.seq, envelope.epoch,
            envelope.ciphertext, twin.id,
        )
        assertFailsWith<CryptoException> {
            relabelled.openWithoutReplayProtection(provider, keys, resolver = twinResolver)
        }
    }

    @Test
    fun unknownSuite_failsClosedAtParse() {
        val bytes = sealedV3().serialise()
        // The production registry does not know the test suite: rejected before any field is believed.
        val failure = assertFailsWith<IllegalArgumentException> { LaneEnvelope.deserialise(bytes) }
        assertTrue("Unknown suite" in failure.message.orEmpty(), failure.message.orEmpty())
    }

    @Test
    fun hostileVersionAndSuiteFields_areRejected() {
        fun frame(version: String, suite: String?) = FrameWriter()
            .putBytes(version.encodeToByteArray())
            .apply { suite?.let { putBytes(it.encodeToByteArray()) } }
            .putBytes("ctx".encodeToByteArray())
            .putBytes("lane".encodeToByteArray())
            .putBytes("7".encodeToByteArray())
            .putBytes("0".encodeToByteArray())
            .putBytes(ByteArray(48))
            .toByteArray()

        LaneEnvelope.deserialise(frame("3", "1")) // canonical v3 naming Suite 1 parses
        assertFailsWith<IllegalArgumentException>("newer version") { LaneEnvelope.deserialise(frame("4", "1")) }
        assertFailsWith<IllegalArgumentException>("leading zero") { LaneEnvelope.deserialise(frame("3", "01")) }
        assertFailsWith<IllegalArgumentException>("out of range") { LaneEnvelope.deserialise(frame("3", "65536")) }
        assertFailsWith<IllegalArgumentException>("unknown suite") { LaneEnvelope.deserialise(frame("3", "9")) }
        assertFailsWith<IllegalArgumentException>("v3 without a suite") { LaneEnvelope.deserialise(frame("3", null)) }
        assertFailsWith<IllegalArgumentException>("v2 with a suite field") { LaneEnvelope.deserialise(frame("2", "1")) }
    }

    @Test
    fun constructor_refusesMismatchedVersionAndSuite() {
        assertFailsWith<IllegalArgumentException> {
            LaneEnvelope(LaneEnvelope.VERSION, "ctx", "lane", 1, 0, ByteArray(48), FakeSuites.FAKE_ID)
        }
        assertFailsWith<IllegalArgumentException> {
            LaneEnvelope(LaneEnvelope.VERSION_SUITED, "ctx", "lane", 1, 0, ByteArray(48), suiteId = null)
        }
    }

    @Test
    fun v3_flowsThroughReplayProtectedDelivery() {
        val envelope = sealedV3()
        val freshness = InMemoryFreshnessStore()
        val delivered = envelope.openAndValidate(
            provider, keys, expectedContextId = "ctx", expectedLane = "device-1",
            freshness = freshness, resolver = resolver,
        ) { it.decodeToString() }
        assertEquals("suited envelope", delivered)
        assertFailsWith<ReplayException>("the same sequence must not deliver twice") {
            envelope.openAndValidate(
                provider, keys, expectedContextId = "ctx", expectedLane = "device-1",
                freshness = freshness, resolver = resolver,
            ) { it.decodeToString() }
        }
    }

    @Test
    fun v2_remainsTheDefaultAndOpensAsBefore() {
        val v2 = LaneEnvelope.seal(provider, keys, "ctx", "device-1", seq = 1, plaintext = plaintext)
        assertEquals(LaneEnvelope.VERSION, v2.version)
        assertEquals(null, v2.suiteId)
        assertContentEquals(plaintext, LaneEnvelope.deserialise(v2.serialise()).openWithoutReplayProtection(provider, keys))
    }

    @Test
    fun v3UnderSuite1_isLegalAndSelfDescribing() {
        // A context that has not upgraded may still emit self-describing v3 envelopes.
        val envelope = LaneEnvelope.sealSuited(provider, keys, Suite1, "ctx", "device-1", 1, plaintext)
        val decoded = LaneEnvelope.deserialise(envelope.serialise())
        assertEquals(SuiteId.LEP_HYBRID_2026, decoded.suiteId)
        assertContentEquals(plaintext, decoded.openWithoutReplayProtection(provider, keys))
    }
}
