package org.layeredencryption

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.pairing.ExistingCalendar
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.PairingFerry
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A ceremony whose log is too big to send whole: the inviter publishes the log and sends only the
 * joiner's ADD entry, and the joiner fetches the log and accepts it only if it holds that entry.
 * Measured on 11 November 2026: at 24 members the log is 338 KB, more than the relay channel the
 * ceremony runs over can carry, so the 25th person could not join.
 */
class PairingAnchorTest {

    private val provider = BouncyCastleCryptoProvider()
    private val founder = DeviceKeys.generate(provider)
    private val joiner = DeviceKeys.generate(provider)
    private val keys = EpochKeys.founding(provider.randomBytes(32))

    private class Pipe(private val incoming: Channel<ByteArray>, private val outgoing: Channel<ByteArray>) : FrameChannel {
        val sent = mutableListOf<ByteArray>()
        override suspend fun send(frame: ByteArray) { sent += frame; outgoing.send(frame) }
        override suspend fun receive(): ByteArray = incoming.receive()
        override fun close() { outgoing.close() }
    }

    private fun pipes(): Pair<Pipe, Pipe> {
        val toJoiner = Channel<ByteArray>(Channel.UNLIMITED)
        val toInviter = Channel<ByteArray>(Channel.UNLIMITED)
        return Pipe(toInviter, toJoiner) to Pipe(toJoiner, toInviter)
    }

    /** A group the founder made, with [others] already in it. */
    private fun group(others: Int): MembershipLog =
        (1..others).fold(MembershipLog.found(provider, founder.identity, founder.signingKeyPair)) { log, _ ->
            log.append(provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity, wrappedKeys = null, signer = founder.signingKeyPair)
        }

    /** The mailbox: what the inviter published, and what the joiner fetches, possibly altered. */
    private var mailbox: ByteArray? = null

    private suspend fun pair(
        log: MembershipLog,
        anchorAbove: Int,
        fetch: PairingFerry.LogFetcher? = PairingFerry.LogFetcher { mailbox },
    ): Triple<PairingFerry.PairingResult, PairingFerry.PairingResult, Pipe> {
        val (inviterSide, joinerSide) = pipes()
        val code = PairingCode.generate(provider)
        val joining = CoroutineScope(EmptyCoroutineContext).async {
            PairingFerry.runJoiner(joinerSide, provider, joiner, code, fetchLog = fetch, confirmSas = { true })
        }
        val invited = PairingFerry.runInviter(
            inviterSide, provider, founder, code, ExistingCalendar(keys, log),
            anchorAboveBytes = anchorAbove,
            publishLog = { published, _ -> mailbox = published.serialise() },
            confirmSas = { true },
        )
        return Triple(invited, joining.await(), inviterSide)
    }

    @Test
    fun aBigGroupsLogIsFetched_andTheJoinerEndsWithTheSameLogAndKeys() = runTest {
        val (invited, joined, sent) = pair(group(others = 5), anchorAbove = 0)
        assertContentEquals(invited.masterKey, joined.masterKey)
        assertContentEquals(invited.membershipLog.serialise(), joined.membershipLog.serialise())
        val last = sent.sent.last()
        assertTrue(last.size < 64 * 1024, "the last message is the joiner's entry alone, ${last.size} bytes")
        assertTrue(last.size < invited.membershipLog.serialise().size)
    }

    @Test
    fun aSmallGroupStillSendsTheWholeLog_soAnOlderJoinerIsUnaffected() = runTest {
        val (invited, _, sent) = pair(group(others = 2), anchorAbove = Int.MAX_VALUE)
        assertEquals(null, mailbox, "nothing was published")
        assertTrue(sent.sent.last().size >= invited.membershipLog.serialise().size)
    }

    @Test
    fun aLogThatGrewSinceIsAccepted() = runTest {
        val grown = PairingFerry.LogFetcher {
            val published = MembershipLog.deserialise(mailbox!!)
            published.append(provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity, wrappedKeys = null, signer = founder.signingKeyPair).serialise()
        }
        val (invited, joined, _) = pair(group(others = 3), anchorAbove = 0, fetch = grown)
        assertEquals(invited.membershipLog.entries.size + 1, joined.membershipLog.entries.size)
    }

    @Test
    fun aLogFromBeforeTheJoinerWasAddedIsRefused() = runTest {
        val before = group(others = 3)
        val stale = PairingFerry.LogFetcher { before.serialise() }
        assertFailsWith<PairingException> { pair(before, anchorAbove = 0, fetch = stale) }
    }

    @Test
    fun anotherGroupsLogIsRefused() = runTest {
        val elsewhere = DeviceKeys.generate(provider)
        val foreign = PairingFerry.LogFetcher {
            MembershipLog.found(provider, elsewhere.identity, elsewhere.signingKeyPair)
                .append(provider, MembershipOp.ADD, joiner.identity, wrappedKeys = null, signer = elsewhere.signingKeyPair)
                .serialise()
        }
        assertFailsWith<PairingException> { pair(group(others = 3), anchorAbove = 0, fetch = foreign) }
    }

    @Test
    fun aJoinerWithNowhereToFetchFromFailsPlainly() = runTest {
        val failure = assertFailsWith<PairingException> { pair(group(others = 3), anchorAbove = 0, fetch = null) }
        assertTrue("nowhere to fetch" in failure.message.orEmpty())
    }

    @Test
    fun aLogThatNeverArrivesFailsPlainly() = runTest {
        val failure = assertFailsWith<PairingException> { pair(group(others = 3), anchorAbove = 0, fetch = { null }) }
        assertTrue("never reached" in failure.message.orEmpty())
    }
}
