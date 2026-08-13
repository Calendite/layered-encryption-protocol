package org.layeredencryption

import org.layeredencryption.BouncyCastleCryptoProvider
import org.layeredencryption.CryptoProvider
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.FrameChannel
import org.layeredencryption.pairing.PairingFerry
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.pairing.ContextId
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The two things a pairing must produce beyond the master key, without which two phones can complete
 * the ceremony and then never sync: an agreed context id, and a membership log on both sides.
 */
class ContextIdTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private class PipeChannel(
        private val incoming: Channel<ByteArray>,
        private val outgoing: Channel<ByteArray>,
    ) : FrameChannel {
        override suspend fun send(frame: ByteArray) = outgoing.send(frame)
        override suspend fun receive(): ByteArray = incoming.receive()
        override fun close() = Unit
    }

    private fun pipePair(): Pair<FrameChannel, FrameChannel> {
        val aToB = Channel<ByteArray>(Channel.UNLIMITED)
        val bToA = Channel<ByteArray>(Channel.UNLIMITED)
        return PipeChannel(bToA, aToB) to PipeChannel(aToB, bToA)
    }

    // ── The derivation ────────────────────────────────────────────────────────────────────────

    private fun foundedLog() = DeviceKeys.generate(provider).let { owner ->
        MembershipLog.found(provider, owner.identity, owner.signingKeyPair) to owner
    }

    @Test
    fun sameLogGivesTheSameId() {
        val (log, _) = foundedLog()

        assertEquals(
            ContextId.forCalendar(provider, log),
            ContextId.forCalendar(provider, MembershipLog.deserialise(log.serialise())),
            "every device must land on the same id without ever exchanging it",
        )
    }

    @Test
    fun differentCalendarsNeverCollide() {
        assertNotEquals(
            ContextId.forCalendar(provider, foundedLog().first),
            ContextId.forCalendar(provider, foundedLog().first),
        )
    }

    /**
     * The whole reason the derivation moved off the master key. Removing a member rotates that key,
     * and if the calendar were named after it the rename would orphan every lane and every chain at
     * the moment the user least wants surprises.
     */
    @Test
    fun theIdSurvivesGrowingAndRekeyingTheCalendar() {
        val (log, owner) = foundedLog()
        val idAtFounding = ContextId.forCalendar(provider, log)

        val grown = log.append(
            provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity,
            wrappedKeys = provider.randomBytes(32), signer = owner.signingKeyPair,
        ).append(
            provider, MembershipOp.REVOKE, DeviceKeys.generate(provider).identity,
            wrappedKeys = null, signer = owner.signingKeyPair,
        )

        assertEquals(idAtFounding, ContextId.forCalendar(provider, grown), "the calendar keeps its name")
    }

    @Test
    fun theIdIsAFullHashInHex() {
        val id = ContextId.forCalendar(provider, foundedLog().first)

        assertEquals(64, id.length, "a full SHA-256 rendered as hex")
        assertTrue(id.all { it in "0123456789abcdef" })
    }

    // ── End to end, which is where it actually matters ────────────────────────────────────────

    @Test
    fun bothSidesOfARealPairingAgreeOnTheIdAndKeepTheLog() = runTest {
        val code = PairingCode.generate(provider)
        val (inviterChannel, joinerChannel) = pipePair()
        val inviter = Inviter(provider, DeviceKeys.generate(provider), code)
        val joiner = Joiner(provider, DeviceKeys.generate(provider), code)

        val inviterKey = async { PairingFerry.runInviter(inviterChannel, inviter) { true } }
        val joinerKey = async { PairingFerry.runJoiner(joinerChannel, joiner) { true } }

        inviterKey.await()
        joinerKey.await()
        val idOnInviter = ContextId.forCalendar(provider, assertNotNull(inviter.membershipLog()))
        val idOnJoiner = ContextId.forCalendar(provider, assertNotNull(joiner.membershipLog()))

        // Without this, the two phones pair, show matching numbers, and then refuse every sync
        // because the context id is bound into the signed sync transcript.
        assertEquals(idOnInviter, idOnJoiner, "a real pairing must agree on the context id")

        // And both must retain the log, or neither can persist the pairing.
        assertNotNull(inviter.membershipLog(), "the inviter founded the log")
        assertNotNull(joiner.membershipLog(), "the joiner verified and kept it")
    }

    @Test
    fun theLogIsNotAvailableBeforeTheCeremonyFinishes() {
        val inviter = Inviter(provider, DeviceKeys.generate(provider), PairingCode.generate(provider))

        assertTrue(inviter.membershipLog() == null, "nothing to persist until complete() has run")
    }
}
