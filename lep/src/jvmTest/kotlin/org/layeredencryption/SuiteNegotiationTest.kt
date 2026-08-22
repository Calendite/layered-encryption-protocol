package org.layeredencryption

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.PairingFerry
import org.layeredencryption.pairing.PairingSuitePolicy
import org.layeredencryption.pairing.PairingWire
import org.layeredencryption.pairing.SuiteAccept
import org.layeredencryption.pairing.SuiteNegotiator
import org.layeredencryption.pairing.SuiteOffer
import org.layeredencryption.suite.FakeSuites
import org.layeredencryption.suite.Suite1
import org.layeredencryption.suite.SuiteId
import org.layeredencryption.suite.SuiteRegistry
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The migration brief's required negotiation security tests (§3, "Required security tests"):
 * offers and selections are authenticated; stripping or reordering a suite list breaks
 * transcript verification on both ends; unknown or rule-breaking selections fail closed; and
 * there is no silent fallback — not to a weaker suite, and not to the legacy flow.
 */
class SuiteNegotiationTest {

    private val provider = BouncyCastleCryptoProvider()
    private val fake = FakeSuites.fakeSuite()
    private val resolver = FakeSuites.resolverWith(fake)

    // ── The selection rule ────────────────────────────────────────────────────────────────────

    @Test
    fun selection_picksTheStrongestMutualSuite() {
        val both = listOf(SuiteId.LEP_HYBRID_2026, FakeSuites.FAKE_ID)
        val selected = SuiteNegotiator.select(resolver, both, SuiteId.LEP_HYBRID_2026, both, SuiteId.LEP_HYBRID_2026)
        assertEquals(FakeSuites.FAKE_ID, selected?.id, "the stronger suite must always win")

        // Ids unknown to the resolver never become candidates.
        val withUnknown = listOf(SuiteId.LEP_HYBRID_2026, SuiteId(0x7777u))
        assertEquals(
            SuiteId.LEP_HYBRID_2026,
            SuiteNegotiator.select(resolver, withUnknown, SuiteId.LEP_HYBRID_2026, withUnknown, SuiteId.LEP_HYBRID_2026)?.id,
        )

        // A strength tie breaks to the higher id, deterministically on both ends.
        val twin = FakeSuites.fakeSuite(id = SuiteId(0xFF01u), strength = 2, name = "TEST_TWIN")
        val tieResolver = FakeSuites.resolverWith(fake, twin)
        val all = listOf(SuiteId.LEP_HYBRID_2026, FakeSuites.FAKE_ID, twin.id)
        assertEquals(
            FakeSuites.FAKE_ID,
            SuiteNegotiator.select(tieResolver, all, SuiteId.LEP_HYBRID_2026, all, SuiteId.LEP_HYBRID_2026)?.id,
        )
    }

    @Test
    fun selection_policyFloorsAbortRatherThanRedirect() {
        // The only mutual suite is Suite 1, but a floor demands the fake's strength: the answer
        // is "no suite", never "the next weaker one".
        val ours = listOf(SuiteId.LEP_HYBRID_2026)
        assertNull(SuiteNegotiator.select(resolver, ours, FakeSuites.FAKE_ID, ours, SuiteId.LEP_HYBRID_2026))
        assertNull(SuiteNegotiator.select(resolver, ours, SuiteId.LEP_HYBRID_2026, ours, FakeSuites.FAKE_ID))
    }

    // ── Provisional accept validation (pre-MAC, fail closed) ─────────────────────────────────

    @Test
    fun acceptSelectingUnknownSuite_failsClosed() {
        val negotiation = SuiteNegotiator.beginInviter(provider, resolver)
        val accept = SuiteAccept(
            provider.randomBytes(32),
            listOf(FakeSuites.FAKE_ID, SuiteId.LEP_HYBRID_2026),
            SuiteId.LEP_HYBRID_2026,
            selectedSuite = SuiteId(0x7777u),
        )
        assertFailsWith<PairingException> { negotiation.onAccept(PairingWire.encode(accept)) }
    }

    @Test
    fun acceptSelectingAgainstTheRule_rejectedBeforeTheCeremony() {
        // The responder advertises the fake suite yet selects Suite 1: the inviter's own
        // recomputation of the rule disagrees, so this dies before a single ceremony frame.
        val negotiation = SuiteNegotiator.beginInviter(provider, resolver)
        val accept = SuiteAccept(
            provider.randomBytes(32),
            listOf(FakeSuites.FAKE_ID, SuiteId.LEP_HYBRID_2026),
            SuiteId.LEP_HYBRID_2026,
            selectedSuite = SuiteId.LEP_HYBRID_2026,
        )
        assertFailsWith<PairingException> { negotiation.onAccept(PairingWire.encode(accept)) }
    }

    @Test
    fun offerCodec_rejectsMalformedFrames() {
        val good = PairingWire.encode(SuiteOffer(provider.randomBytes(32), listOf(SuiteId.LEP_HYBRID_2026), SuiteId.LEP_HYBRID_2026))
        // Round-trips byte-exactly; then every structural mutation is refused.
        assertContentEquals(good, PairingWire.encode(PairingWire.decodeSuiteOffer(good)))
        assertFailsWith<PairingException>("trailing byte") { PairingWire.decodeSuiteOffer(good + 0) }
        assertFailsWith<PairingException>("wrong tag") { PairingWire.decodeSuiteAccept(good) }

        val versioned = good.copyOf().also { it[5] = 2 } // the framed formatVersion byte
        assertFailsWith<PairingException>("unknown negotiation version") { PairingWire.decodeSuiteOffer(versioned) }

        // A duplicated id in the list: splice the 2-byte id in over the wire, since the message
        // constructor refuses to build one. The list field starts after tag(1) + framed
        // version(4+1) + framed nonce(4+32): its length prefix is at offset 42.
        val duplicated = FrameWriter()
            .putByte(PairingWire.TAG_SUITE_OFFER)
            .putBytes(byteArrayOf(1))
            .putBytes(ByteArray(32))
            .putBytes(byteArrayOf(0, 1, 0, 1)) // Suite 1 twice
            .putBytes(byteArrayOf(0, 1))
            .toByteArray()
        assertFailsWith<PairingException>("duplicate id") { PairingWire.decodeSuiteOffer(duplicated) }

        val oddLength = FrameWriter()
            .putByte(PairingWire.TAG_SUITE_OFFER)
            .putBytes(byteArrayOf(1))
            .putBytes(ByteArray(32))
            .putBytes(byteArrayOf(0, 1, 0)) // one and a half ids
            .putBytes(byteArrayOf(0, 1))
            .toByteArray()
        assertFailsWith<PairingException>("odd-length list") { PairingWire.decodeSuiteOffer(oddLength) }

        val emptyList = FrameWriter()
            .putByte(PairingWire.TAG_SUITE_OFFER)
            .putBytes(byteArrayOf(1))
            .putBytes(ByteArray(32))
            .putBytes(ByteArray(0))
            .putBytes(byteArrayOf(0, 1))
            .toByteArray()
        assertFailsWith<PairingException>("empty list") { PairingWire.decodeSuiteOffer(emptyList) }

        // Constructor-level rules mirror the decoder's, so a hostile list cannot be built either.
        assertFailsWith<IllegalArgumentException> {
            SuiteOffer(provider.randomBytes(32), listOf(SuiteId.LEP_HYBRID_2026, SuiteId.LEP_HYBRID_2026), SuiteId.LEP_HYBRID_2026)
        }
        assertFailsWith<IllegalArgumentException> {
            SuiteOffer(provider.randomBytes(32), emptyList(), SuiteId.LEP_HYBRID_2026)
        }
    }

    @Test
    fun legacyDecoders_rejectNegotiationFrames() {
        val offer = SuiteNegotiator.beginInviter(provider, resolver).offerFrame
        assertFailsWith<PairingException> { PairingWire.decodeInviterHello(offer) }
        assertFailsWith<PairingException> { PairingWire.decodeJoinerResponse(offer) }
        assertFailsWith<PairingException> { PairingWire.decodeInviterConfirm(offer) }
        assertFailsWith<PairingException> { PairingWire.decodeSasConfirmed(offer) }
        assertFailsWith<PairingException> { PairingWire.decodeInviterComplete(offer) }
    }

    // ── Full negotiated ceremonies ────────────────────────────────────────────────────────────

    private class Pipe(
        private val incoming: Channel<ByteArray>,
        private val outgoing: Channel<ByteArray>,
        private val sent: MutableList<ByteArray>,
        private val transformSend: (ByteArray) -> ByteArray = { it },
    ) : FrameChannel {
        override suspend fun send(frame: ByteArray) {
            val transformed = transformSend(frame)
            sent += transformed.copyOf()
            outgoing.send(transformed)
        }
        override suspend fun receive(): ByteArray = incoming.receive()
        override fun close() { outgoing.close() }
    }

    private class Wire(
        val inviterChannel: FrameChannel,
        val joinerChannel: FrameChannel,
        val frames: MutableList<ByteArray>,
    )

    /** A pipe pair recording every frame that crosses, with optional in-flight tampering. */
    private fun wire(
        tamperInviterSend: (ByteArray) -> ByteArray = { it },
        tamperJoinerSend: (ByteArray) -> ByteArray = { it },
    ): Wire {
        val toJoiner = Channel<ByteArray>(Channel.UNLIMITED)
        val toInviter = Channel<ByteArray>(Channel.UNLIMITED)
        val frames = mutableListOf<ByteArray>()
        return Wire(
            Pipe(toInviter, toJoiner, frames, tamperInviterSend),
            Pipe(toJoiner, toInviter, frames, tamperJoinerSend),
            frames,
        )
    }

    private fun ceremonyDevices(suite: org.layeredencryption.suite.ProtocolSuite = Suite1) =
        DeviceKeys.generate(provider, suite) to DeviceKeys.generate(provider, suite)

    private fun CoroutineScope.launchJoiner(
        wire: Wire,
        joinerKeys: DeviceKeys,
        code: PairingCode,
        resolver: org.layeredencryption.suite.SuiteResolver = this@SuiteNegotiationTest.resolver,
        policy: PairingSuitePolicy = PairingSuitePolicy(),
    ): Deferred<Result<ByteArray>> = async {
        runCatching {
            PairingFerry.runJoiner(wire.joinerChannel, provider, joinerKeys, code, resolver = resolver, policy = policy) { true }.masterKey
        }
    }

    @Test
    fun negotiatedCeremony_runsEndToEndUnderANonDefaultSuite() = runTest {
        // Devices whose identities live under the fake suite pair under it: the whole ceremony —
        // KEM, transcript, MACs, wrapped keys, membership log — routes through the negotiated
        // suite, and the offer advertises exactly the suites the device holds identities for.
        val (inviterKeys, joinerKeys) = ceremonyDevices(fake)
        val code = PairingCode.generate(provider)
        val wire = wire()

        val joiner = CoroutineScope(EmptyCoroutineContext).launchJoiner(wire, joinerKeys, code)
        val inviterKey = PairingFerry.runInviter(
            wire.inviterChannel, provider, inviterKeys, code, resolver = resolver,
        ) { true }.masterKey
        val joinerKey = joiner.await().getOrThrow()

        assertContentEquals(inviterKey, joinerKey, "both sides must end with the same master key")
        val offer = PairingWire.decodeSuiteOffer(wire.frames.first())
        assertEquals(listOf(FakeSuites.FAKE_ID), offer.supportedSuites)
        val accept = PairingWire.decodeSuiteAccept(wire.frames[1])
        assertEquals(FakeSuites.FAKE_ID, accept.selectedSuite)
    }

    @Test
    fun mismatchedIdentityAndSelection_isRejectedAtSessionConstruction() {
        // A device whose identity belongs to a different suite than the negotiation selected can
        // never run the ceremony — the identity rides the MAC'd transcript, so this equality is
        // load-bearing, not cosmetic.
        val context = org.layeredencryption.pairing.TestNegotiation.single(provider) // selects Suite 1
        val fakeDevice = DeviceKeys.generate(provider, fake)
        assertFailsWith<PairingException> {
            org.layeredencryption.pairing.Inviter(
                provider, fakeDevice, PairingCode.generate(provider), negotiated = context,
            )
        }
    }

    @Test
    fun negotiatedCeremony_worksWithOnlySuite1Registered() = runTest {
        val (inviterKeys, joinerKeys) = ceremonyDevices()
        val code = PairingCode.generate(provider)
        val wire = wire()

        val joiner = CoroutineScope(EmptyCoroutineContext).launchJoiner(wire, joinerKeys, code, resolver = SuiteRegistry)
        val inviterKey = PairingFerry.runInviter(
            wire.inviterChannel, provider, inviterKeys, code, resolver = SuiteRegistry,
        ) { true }.masterKey
        assertContentEquals(inviterKey, joiner.await().getOrThrow())
    }

    @Test
    fun strippingTheOfferedSuite_abortsBeforeAnyCeremonyFrame() = runTest {
        // A MITM replaces the fake-suite offer with a Suite-1-only one. The joiner's own identity
        // lives under the fake suite, so the intersection is empty and it refuses outright: the
        // downgrade dies at selection, with zero ceremony frames — never a quieter suite.
        val (inviterKeys, joinerKeys) = ceremonyDevices(fake)
        val code = PairingCode.generate(provider)
        val wire = wire(
            tamperInviterSend = { frame ->
                if (frame.isNotEmpty() && frame[0].toInt() == PairingWire.TAG_SUITE_OFFER) {
                    val offer = PairingWire.decodeSuiteOffer(frame)
                    PairingWire.encode(SuiteOffer(offer.nonce, listOf(SuiteId.LEP_HYBRID_2026), offer.minimumSuite))
                } else frame
            },
        )

        val joiner = CoroutineScope(EmptyCoroutineContext).launchJoiner(wire, joinerKeys, code)
        val inviter = runCatching {
            PairingFerry.runInviter(wire.inviterChannel, provider, inviterKeys, code, resolver = resolver) { true }
        }
        assertTrue(joiner.await().isFailure, "the joiner must refuse the downgraded offer")
        assertTrue(inviter.isFailure)
        for (frame in wire.frames) {
            val tag = frame.firstOrNull()?.toInt() ?: fail("empty frame recorded")
            assertTrue(tag == PairingWire.TAG_SUITE_OFFER, "no later frame may ever cross; saw tag $tag")
        }
    }

    @Test
    fun tamperedNegotiationFrames_failAtTheCeremonyMacs() {
        // The transcript binds the RAW offer/accept bytes: two sessions holding contexts that
        // differ by a single reordered-list re-encoding of the offer (same logical content, same
        // selection — every provisional check passes) must fail each other's code-keyed MACs.
        // This is the doc's "removal or reordering of supported suites causes transcript
        // verification to fail", exercised at the binding itself.
        val inviterNegotiation = SuiteNegotiator.beginInviter(
            provider, resolver, supported = listOf(FakeSuites.FAKE_ID, SuiteId.LEP_HYBRID_2026),
        )
        val offer = PairingWire.decodeSuiteOffer(inviterNegotiation.offerFrame)
        val reordered = PairingWire.encode(
            SuiteOffer(offer.nonce, offer.supportedSuites.reversed(), offer.minimumSuite),
        )
        // The joiner saw the reordered offer; the inviter bound the original.
        val joinerNegotiation = SuiteNegotiator.respond(
            reordered, provider, resolver, supported = listOf(FakeSuites.FAKE_ID, SuiteId.LEP_HYBRID_2026),
        )
        val inviterContext = inviterNegotiation.onAccept(joinerNegotiation.acceptFrame)
        assertEquals(joinerNegotiation.context.suite.id, inviterContext.suite.id, "same selection on both ends")

        val code = PairingCode.generate(provider)
        val inviterKeys = DeviceKeys.generate(provider, fake)
        val joinerKeys = DeviceKeys.generate(provider, fake)
        val inviter = org.layeredencryption.pairing.Inviter(provider, inviterKeys, code, negotiated = inviterContext)
        val joiner = org.layeredencryption.pairing.Joiner(provider, joinerKeys, code, negotiated = joinerNegotiation.context)

        val response = joiner.onInviterHello(inviter.hello())
        val failure = assertFailsWith<PairingException> { inviter.onJoinerResponse(response) }
        assertTrue("MAC" in failure.message.orEmpty(), "must die at authentication, was: ${failure.message}")
    }

    @Test
    fun noMutuallyAcceptableSuite_abortsWithoutASingleCeremonyFrame() = runTest {
        // The joiner's policy floor demands the fake suite; the inviter only has Suite 1. The
        // outcome must be a refusal — never a quiet legacy ceremony.
        val (inviterKeys, joinerKeys) = ceremonyDevices()
        val code = PairingCode.generate(provider)
        val wire = wire()

        val joiner = CoroutineScope(EmptyCoroutineContext).launchJoiner(
            wire, joinerKeys, code, resolver = resolver, policy = PairingSuitePolicy(minimumSuite = FakeSuites.FAKE_ID),
        )
        val inviter = runCatching {
            PairingFerry.runInviter(wire.inviterChannel, provider, inviterKeys, code, resolver = SuiteRegistry) { true }
        }
        val joinerOutcome = joiner.await()

        assertTrue(joinerOutcome.isFailure, "the joiner must refuse")
        assertTrue(joinerOutcome.exceptionOrNull() is PairingException)
        assertTrue(inviter.isFailure, "the inviter cannot complete against a refusal")
        for (frame in wire.frames) {
            val tag = frame.firstOrNull()?.toInt() ?: fail("empty frame recorded")
            assertTrue(
                tag == PairingWire.TAG_SUITE_OFFER || tag == PairingWire.TAG_SUITE_ACCEPT,
                "no ceremony frame may ever cross after a failed negotiation; saw tag $tag",
            )
        }
    }

    @Test
    fun distinctNegotiations_deriveDistinctTranscriptsAndKeys() {
        // Identical classic fields, identical shared secret: two different negotiation runs must
        // still yield different transcripts and handshake keys, because the raw offer/accept
        // frames (fresh nonces included) are bound into both — a transcript from one ceremony
        // can never authenticate another.
        fun context(): org.layeredencryption.pairing.NegotiatedSuiteContext {
            val negotiation = SuiteNegotiator.beginInviter(provider, SuiteRegistry)
            val accepted = SuiteNegotiator.respond(negotiation.offerFrame, provider, SuiteRegistry)
            return negotiation.onAccept(accepted.acceptFrame)
        }

        val kemKeyPair = Suite1.kem.generateKeyPair(provider)
        val identity = DeviceKeys.generate(provider).identity.serialise()
        val ciphertext = Suite1.kem.encapsulate(provider, kemKeyPair.publicKey)
        val commitment = provider.randomBytes(32)

        val first = org.layeredencryption.pairing.PairingTranscript(
            kemKeyPair.publicKey, identity, ciphertext.ciphertext, identity, commitment,
            negotiated = context(),
        )
        val second = org.layeredencryption.pairing.PairingTranscript(
            kemKeyPair.publicKey, identity, ciphertext.ciphertext, identity, commitment,
            negotiated = context(),
        )
        assertTrue(!first.bytes().contentEquals(second.bytes()), "transcripts must differ")

        val secret = ciphertext.sharedSecret
        val firstKey = org.layeredencryption.pairing.Handshake.handshakeKey(provider, secret, first)
        val secondKey = org.layeredencryption.pairing.Handshake.handshakeKey(provider, secret, second)
        assertTrue(!firstKey.contentEquals(secondKey), "handshake keys must differ")
    }
}
