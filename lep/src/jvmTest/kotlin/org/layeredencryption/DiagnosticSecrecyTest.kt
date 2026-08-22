package org.layeredencryption

import dev.diagnostics.DiagnosticSink
import dev.diagnostics.Diagnostics
import dev.diagnostics.LogEvent
import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.InMemoryFreshnessStore
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.envelope.ReplayException
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.invite.AsyncDelivery
import org.layeredencryption.invite.AsyncInviter
import org.layeredencryption.invite.AsyncJoiner
import org.layeredencryption.invite.ResponseOutcome
import org.layeredencryption.membership.ForkResolution
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.TestNegotiation
import org.layeredencryption.pairing.PairingException
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The rule the diagnostics carry on their face: **no key material, ever** — enforced the way the
 * recorder's rule is enforced, by holding the real secrets from real runs and asserting none of
 * them appears in anything emitted. Alongside it, the inverse guarantee: the ceremonies are no
 * longer a black box — the subsystems that used to go dark provably emit.
 *
 * The library never installs a sink itself, so everything here also documents the default:
 * uninstalled, nothing is built and nothing leaves.
 */
class DiagnosticSecrecyTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private val negotiation = TestNegotiation.pair(provider)

    private class RecordingSink : DiagnosticSink {
        val events = mutableListOf<LogEvent>()
        override fun emit(event: LogEvent) {
            events += event
        }

        /** Every string an emission could carry anywhere. */
        fun allText(): List<String> = events.flatMap {
            listOfNotNull(it.message, it.data, it.filterTag, it.throwable?.stackTraceToString())
        }
    }

    private val sink = RecordingSink()

    @AfterTest
    fun cleanUp() = Diagnostics.uninstall()

    /** Hex both ways plus a 16-char prefix, so even a truncated leak is caught. */
    private fun forbiddenForms(secret: ByteArray): List<String> {
        val hex = secret.toHexString()
        return listOf(hex, hex.uppercase(), hex.take(16))
    }

    private fun assertNothingLeaked(secrets: Map<String, ByteArray>) {
        val emitted = sink.allText()
        assertTrue(emitted.isNotEmpty(), "the ceremonies must emit — a black box would pass a leak test trivially")
        for ((name, secret) in secrets) {
            for (form in forbiddenForms(secret)) {
                for (text in emitted) {
                    assertTrue(!text.contains(form), "$name leaked into a diagnostic emission: $text")
                }
            }
        }
    }

    @Test
    fun theFullCeremoniesEmitAndLeakNothing() {
        Diagnostics.install(sink)

        // ── A complete synchronous pairing, including a wrong-code rejection ──────────────
        val code = PairingCode.generate(provider)
        val inviterDevice = DeviceKeys.generate(provider)
        val joinerDevice = DeviceKeys.generate(provider)
        val inviter = Inviter(provider, inviterDevice, code, negotiated = negotiation.first)
        val joiner = Joiner(provider, joinerDevice, code, negotiated = negotiation.second)
        val response = joiner.onInviterHello(inviter.hello())
        joiner.onInviterConfirm(inviter.onJoinerResponse(response))
        joiner.onInviterComplete(inviter.complete(inviter.confirmSas()), joiner.confirmSas())
        val masterKey = inviter.masterKey()

        val wrongCodeJoiner = Joiner(provider, DeviceKeys.generate(provider), PairingCode.generate(provider), negotiated = negotiation.second)
        val hostileInviter = Inviter(provider, DeviceKeys.generate(provider), PairingCode.generate(provider), negotiated = negotiation.first)
        val hostileResponse = wrongCodeJoiner.onInviterHello(hostileInviter.hello())
        runCatching { hostileInviter.onJoinerResponse(hostileResponse) }

        // ── A complete async invite ───────────────────────────────────────────────────────
        val asyncInviter = AsyncInviter.create(provider, DeviceKeys.generate(provider), nowEpochSeconds = 1_000, expiryEpochSeconds = 1_000 + 604_800)
        val asyncJoiner = AsyncJoiner(provider, DeviceKeys.generate(provider))
        val asyncResponse = asyncJoiner.onBundle(asyncInviter.link, asyncInviter.bundle, 1_000)
        assertIs<ResponseOutcome.Claimed>(asyncInviter.onResponse(asyncResponse, 1_000))
        asyncJoiner.onDelivery(asyncInviter.approve())
        val asyncMasterKey = asyncJoiner.masterKey()

        // ── A fork resolved with a rotation ───────────────────────────────────────────────
        val a = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)
        val c = DeviceKeys.generate(provider)
        val base = MembershipLog.found(provider, a.identity, a.signingKeyPair)
            .append(provider, MembershipOp.ADD, b.identity, null, a.signingKeyPair)
            .append(provider, MembershipOp.ADD, c.identity, null, a.signingKeyPair)
        val rotationKey = provider.randomBytes(32)
        // Two divergent owner-signed branches: the shape a real fork takes now that membership
        // is the founding device's prerogative.
        val honest = base.revoke(provider, b.identity, rotationKey, a.signingKeyPair)
        val other = base.revoke(provider, c.identity, provider.randomBytes(32), a.signingKeyPair)
        val resolved = assertIs<ForkResolution.Resolved>(honest.resolveFork(provider, other, resolver = a))

        // ── Envelopes: delivery, replay refusal, cross-context refusal ────────────────────
        val keys = EpochKeys.founding(masterKey)
        val freshness = InMemoryFreshnessStore()
        val envelope = LaneEnvelope.seal(provider, keys, "ctx", "device-1", 1, "an op".encodeToByteArray())
        envelope.openAndValidate(provider, keys, "ctx", "device-1", freshness) { it }
        assertFailsWith<ReplayException> { envelope.openAndValidate(provider, keys, "ctx", "device-1", freshness) { it } }
        assertFailsWith<ReplayException> { envelope.openAndValidate(provider, keys, "other", "device-1", freshness) { it } }

        // ── Nothing secret in any of it ───────────────────────────────────────────────────
        assertNothingLeaked(
            mapOf(
                "pairing master key" to masterKey,
                "pairing code" to code.canonical.encodeToByteArray(),
                "inviter signing key" to inviterDevice.signingPrivateKey,
                "inviter x25519 key" to inviterDevice.x25519IdentityPrivateKey,
                "inviter x-wing seed" to inviterDevice.xWingPrivateKey,
                "joiner signing key" to joinerDevice.signingPrivateKey,
                "async master key" to asyncMasterKey,
                "async link secret" to asyncInviter.link.secret,
                "fork rotation key" to rotationKey,
                "resolution master key" to (resolved.newMasterKey ?: ByteArray(32)),
            )
        )

        // And the black box is provably open: each dark subsystem spoke at least once.
        val tags = sink.events.map { it.tag }.toSet()
        for (expected in listOf("LepPairing", "LepInvite", "LepEnvelope", "LepMembership")) {
            assertTrue(expected in tags, "expected an emission from $expected, saw only $tags")
        }
    }

    /**
     * The catch-all in `onDelivery` passes its raw parser exception through the *unsafe* slot:
     * a default install drops it (the trace of a third-party exception can embed the bytes it
     * choked on), while an install with `captureUnsafeThrowables = true` — a local debugging
     * session — gets the full trace. Same code path, the installer chooses.
     */
    @Test
    fun aRawParserExceptionSurfacesOnlyWhenTheInstallOptedIn() {
        // A real ceremony up to the delivery, run silently so only the deliveries are recorded.
        val asyncInviter = AsyncInviter.create(provider, DeviceKeys.generate(provider), nowEpochSeconds = 1_000, expiryEpochSeconds = 1_000 + 604_800)
        val asyncJoiner = AsyncJoiner(provider, DeviceKeys.generate(provider))
        val response = asyncJoiner.onBundle(asyncInviter.link, asyncInviter.bundle, 1_000)
        assertIs<ResponseOutcome.Claimed>(asyncInviter.onResponse(response, 1_000))
        val genuine = asyncInviter.approve()
        // The right MAC over a garbage log: past the gate, into the parser.
        val tampered = AsyncDelivery(genuine.inviterMac, byteArrayOf(1, 2, 3))

        Diagnostics.install(sink, captureUnsafeThrowables = true)
        assertFailsWith<PairingException> { asyncJoiner.onDelivery(tampered) }
        val flagged = sink.events.single { it.message == "delivery rejected: malformed" }
        assertNotNull(flagged.throwable, "the opted-in install should carry the raw cause")
        assertTrue(flagged.throwable !is PairingException, "and it is the parser's own exception, not a sanitised wrapper")

        Diagnostics.uninstall()
        val plainSink = RecordingSink()
        Diagnostics.install(plainSink)
        assertFailsWith<PairingException> { asyncJoiner.onDelivery(tampered) }
        val plain = plainSink.events.single { it.message == "delivery rejected: malformed" }
        assertNull(plain.throwable, "a default install must drop the raw exception entirely")
    }

    @Test
    fun withNoSinkTheCeremoniesStaySilentAndUnchanged() {
        Diagnostics.uninstall()

        val code = PairingCode.generate(provider)
        val inviter = Inviter(provider, DeviceKeys.generate(provider), code, negotiated = negotiation.first)
        val joiner = Joiner(provider, DeviceKeys.generate(provider), code, negotiated = negotiation.second)
        val response = joiner.onInviterHello(inviter.hello())
        joiner.onInviterConfirm(inviter.onJoinerResponse(response))
        joiner.onInviterComplete(inviter.complete(inviter.confirmSas()), joiner.confirmSas())

        assertTrue(sink.events.isEmpty(), "an uninstalled library emits nothing at all")
        assertTrue(inviter.masterKey().contentEquals(joiner.masterKey()), "and the ceremony is unaffected")
    }
}
