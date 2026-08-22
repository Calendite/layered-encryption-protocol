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
 * The lane envelope (version 3, the only version): the suite id is named in the header and
 * bound into the AEAD associated data alongside every other routing field, and an envelope
 * naming a suite this build does not know fails closed at parse.
 */
class LaneEnvelopeTest {

    private val provider = BouncyCastleCryptoProvider()
    private val fake = FakeSuites.fakeSuite()
    private val resolver = FakeSuites.resolverWith(fake)

    private val masterKey = provider.randomBytes(32)
    private val keys = EpochKeys.founding(masterKey)
    private val plaintext = "suited envelope".encodeToByteArray()

    private fun sealed(suite: org.layeredencryption.suite.ProtocolSuite = Suite1) = LaneEnvelope.seal(
        provider, keys, contextId = "ctx", lane = "device-1", seq = 7, plaintext = plaintext, suite = suite,
    )

    @Test
    fun envelope_roundTripsAndOpensUnderItsSuite() {
        val envelope = sealed(fake)
        assertEquals(LaneEnvelope.VERSION, envelope.version)
        assertEquals(FakeSuites.FAKE_ID, envelope.suiteId)

        val bytes = envelope.serialise()
        val decoded = LaneEnvelope.deserialise(bytes, resolver)
        assertEquals(FakeSuites.FAKE_ID, decoded.suiteId)
        assertEquals(7, decoded.seq)
        assertContentEquals(bytes, decoded.serialise(), "must re-serialise byte-exactly")
        assertContentEquals(plaintext, decoded.openWithoutReplayProtection(provider, keys, resolver = resolver))
    }

    @Test
    fun suiteId_isBoundIntoTheAssociatedData() {
        // Same ciphertext, same everything, re-labelled to a different (registered, and even
        // cryptographically identical) suite: the AAD differs, so decryption must fail.
        val twin = FakeSuites.fakeSuite(id = SuiteId(0xFF01u), name = "TEST_TWIN")
        val twinResolver = FakeSuites.resolverWith(fake, twin)
        val envelope = sealed(fake)
        val relabelled = LaneEnvelope(
            LaneEnvelope.VERSION, envelope.contextId, envelope.lane, envelope.seq, envelope.epoch,
            envelope.ciphertext, twin.id,
        )
        assertFailsWith<CryptoException> {
            relabelled.openWithoutReplayProtection(provider, keys, resolver = twinResolver)
        }
    }

    @Test
    fun unknownSuite_failsClosedAtParse() {
        val bytes = sealed(fake).serialise()
        // The production registry does not know the test suite: rejected before any field is believed.
        val failure = assertFailsWith<IllegalArgumentException> { LaneEnvelope.deserialise(bytes) }
        assertTrue("Unknown suite" in failure.message.orEmpty(), failure.message.orEmpty())
    }

    @Test
    fun hostileVersionAndSuiteFields_areRejected() {
        fun frame(version: String, suite: String) = FrameWriter()
            .putBytes(version.encodeToByteArray())
            .putBytes(suite.encodeToByteArray())
            .putBytes("ctx".encodeToByteArray())
            .putBytes("lane".encodeToByteArray())
            .putBytes("7".encodeToByteArray())
            .putBytes("0".encodeToByteArray())
            .putBytes(ByteArray(48))
            .toByteArray()

        LaneEnvelope.deserialise(frame("3", "1")) // the canonical form parses
        assertFailsWith<IllegalArgumentException>("retired version 2") { LaneEnvelope.deserialise(frame("2", "1")) }
        assertFailsWith<IllegalArgumentException>("newer version") { LaneEnvelope.deserialise(frame("4", "1")) }
        assertFailsWith<IllegalArgumentException>("leading zero") { LaneEnvelope.deserialise(frame("3", "01")) }
        assertFailsWith<IllegalArgumentException>("out of range") { LaneEnvelope.deserialise(frame("3", "65536")) }
        assertFailsWith<IllegalArgumentException>("unknown suite") { LaneEnvelope.deserialise(frame("3", "9")) }
    }

    @Test
    fun envelope_flowsThroughReplayProtectedDelivery() {
        val envelope = sealed(fake)
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
    fun suite1IsTheDefaultSeal_andIsSelfDescribing() {
        val envelope = sealed()
        assertEquals(SuiteId.LEP_HYBRID_2026, envelope.suiteId)
        val decoded = LaneEnvelope.deserialise(envelope.serialise())
        assertContentEquals(plaintext, decoded.openWithoutReplayProtection(provider, keys))
    }
}
