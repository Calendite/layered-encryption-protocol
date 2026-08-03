package org.layeredencryption

import org.layeredencryption.BouncyCastleCryptoProvider
import org.layeredencryption.CryptoProvider
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.FrameChannel
import org.layeredencryption.pairing.PairingFerry
import org.layeredencryption.pairing.CalendarId
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
 * the ceremony and then never sync: an agreed calendar id, and a membership log on both sides.
 */
class CalendarIdTest {

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

    @Test
    fun sameMasterKeyGivesTheSameId() {
        val masterKey = provider.randomBytes(32)

        assertEquals(
            CalendarId.derive(provider, masterKey),
            CalendarId.derive(provider, masterKey.copyOf()),
            "both devices must land on the same id without ever exchanging it",
        )
    }

    @Test
    fun differentPairingsNeverCollide() {
        val first = CalendarId.derive(provider, provider.randomBytes(32))
        val second = CalendarId.derive(provider, provider.randomBytes(32))

        assertNotEquals(first, second)
    }

    @Test
    fun theIdRevealsNothingAboutTheKey() {
        val masterKey = provider.randomBytes(32)
        val id = CalendarId.derive(provider, masterKey)

        assertEquals(64, id.length, "a full SHA-256 rendered as hex")
        assertTrue(id.all { it in "0123456789abcdef" })
        assertTrue(masterKey.joinToString("") { b -> (b.toInt() and 0xFF).toString(16).padStart(2, '0') } != id)
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

        val idOnInviter = CalendarId.derive(provider, inviterKey.await())
        val idOnJoiner = CalendarId.derive(provider, joinerKey.await())

        // Without this, the two phones pair, show matching numbers, and then refuse every sync
        // because the calendar id is bound into the signed sync transcript.
        assertEquals(idOnInviter, idOnJoiner, "a real pairing must agree on the calendar id")

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
