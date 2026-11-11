package org.layeredencryption

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.CHECKPOINT_EVERY
import org.layeredencryption.membership.CheckpointPayload
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipRules
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.membership.VerifiedPrefixes
import org.layeredencryption.membership.WrappedKeys
import org.layeredencryption.pairing.ExistingCalendar
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.PairingFerry
import org.layeredencryption.pairing.PairingWire
import org.layeredencryption.pairing.InviterComplete
import org.layeredencryption.suite.SuiteRegistry
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Who a joiner trusts a checkpoint from. The log a big group's joiner fetches comes from the relay
 * mailbox, which nothing authenticates; only the joiner's own ADD reaches it over the ceremony, from
 * the inviter it compared a SAS with. So only a checkpoint that ADD's hash chain pins (one before it)
 * may be taken on its word, everything after the ADD is walked, and nothing taken on a checkpoint's
 * word may reach the cache that a strict [MembershipLog.verify] resumes from.
 */
class CheckpointTrustTest {

    private class Counting(private val inner: CryptoProvider = BouncyCastleCryptoProvider()) : CryptoProvider by inner {
        var mlDsaChecks = 0
        override fun mlDsa65Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
            mlDsaChecks++
            return inner.mlDsa65Verify(publicKey, message, signature)
        }
    }

    private val provider = BouncyCastleCryptoProvider()
    /** The joiner's own provider, so its signature checks can be counted apart from the inviter's. */
    private val joinerProvider = Counting()
    private val founder = DeviceKeys.generate(provider)
    private val joiner = DeviceKeys.generate(provider)
    /** The relay's own key, which is in no genuine version of the group. */
    private val relay = DeviceKeys.generate(provider)
    private val keys = EpochKeys.founding(provider.randomBytes(32))
    private val suite = SuiteRegistry.require(founder.identity.suiteId)

    @BeforeTest
    fun forget() = VerifiedPrefixes.clear()

    private fun MembershipLog.add(who: DeviceKeys = DeviceKeys.generate(provider)): MembershipLog =
        append(provider, MembershipOp.ADD, who.identity, wrappedKeys = null, signer = founder.signingKeyPair)

    private fun anyMemberGroup(adds: Int) =
        (1..adds).fold(MembershipLog.found(provider, founder.identity, founder.signingKeyPair).raiseRules(provider, MembershipRules.ANY_MEMBER, founder)) { log, _ -> log.add() }

    // ── The relay's forgeries ─────────────────────────────────────────────────────────────────

    /** A checkpoint signed by the relay, at the right position of the right group, listing [listed]. */
    private fun MembershipLog.withForgedCheckpoint(listed: List<DeviceKeys>): MembershipLog {
        val payload = CheckpointPayload(
            genesisHash = entries.first().hash(provider),
            founderKey = entries.first().deviceIdentity.signingPublicKey,
            entryCount = entries.size,
            epoch = 0,
            rules = MembershipRules.ANY_MEMBER,
            suiteId = suite.id.value.toInt(),
            members = listed.sortedBy { it.identity.signingPublicKey.toHexString() }.map { it.identity.serialise() },
        )
        return append(provider, MembershipOp.CHECKPOINT, relay.identity, payload.serialise(), relay.signingKeyPair)
    }

    /** Then a rotation from the relay to a key it chose, wrapped for itself and the joiner. */
    private fun MembershipLog.withForgedRotation(): MembershipLog = append(
        provider, MembershipOp.ROTATE, relay.identity,
        WrappedKeys.wrapFor(provider, suite, listOf(relay.identity, joiner.identity), provider.randomBytes(32)),
        relay.signingKeyPair,
    )

    // ── Pairing over pipes, with a mailbox the relay controls ─────────────────────────────────

    private var mailbox: ByteArray? = null

    private class Pipe(
        private val incoming: Channel<ByteArray>,
        private val outgoing: Channel<ByteArray>,
        private val alter: (ByteArray) -> ByteArray = { it },
    ) : FrameChannel {
        override suspend fun send(frame: ByteArray) = outgoing.send(alter(frame))
        override suspend fun receive(): ByteArray = incoming.receive()
        override fun close() { outgoing.close() }
    }

    private suspend fun pair(
        log: MembershipLog,
        anchorAbove: Int,
        fetch: PairingFerry.LogFetcher = PairingFerry.LogFetcher { mailbox },
        alterInviterFrames: (ByteArray) -> ByteArray = { it },
    ): Pair<PairingFerry.PairingResult, PairingFerry.PairingResult> {
        val toJoiner = Channel<ByteArray>(Channel.UNLIMITED)
        val toInviter = Channel<ByteArray>(Channel.UNLIMITED)
        val inviterSide = Pipe(toInviter, toJoiner, alterInviterFrames)
        val joinerSide = Pipe(toJoiner, toInviter)
        val code = PairingCode.generate(provider)
        val joining = CoroutineScope(EmptyCoroutineContext).async {
            PairingFerry.runJoiner(joinerSide, joinerProvider, joiner, code, fetchLog = fetch, confirmSas = { true })
        }
        val invited = PairingFerry.runInviter(
            inviterSide, provider, founder, code, ExistingCalendar(keys, log),
            anchorAboveBytes = anchorAbove,
            publishLog = { published, _ -> mailbox = published.serialise() },
            confirmSas = { true },
        )
        return invited to joining.await()
    }

    /**
     * The relay's fetch: the published log with [forge] applied. The cache is cleared first because
     * the joiner is another device: in this test both run in one process, and the inviter's own
     * checks would otherwise hand the joiner the genuine state.
     */
    private fun forgingRelay(forge: (MembershipLog) -> MembershipLog) = PairingFerry.LogFetcher {
        VerifiedPrefixes.clear()
        forge(MembershipLog.deserialise(mailbox!!)).serialise()
    }

    // ── Bug 1: a checkpoint after the joiner's ADD is not taken on trust ──────────────────────

    @Test
    fun aRelayCannotAppendItsOwnCheckpointAfterTheJoinersAdd() = runTest {
        val forgeries = listOf<(MembershipLog) -> MembershipLog>(
            { it.withForgedCheckpoint(listOf(relay, joiner)) },
            { it.withForgedCheckpoint(listOf(relay, joiner)).withForgedRotation() },
        )
        for (forge in forgeries) {
            assertFailsWith<PairingException> { pair(anyMemberGroup(3), anchorAbove = 0, fetch = forgingRelay(forge)) }
        }
    }

    @Test
    fun aRelayCannotDoItToALogSentWholeEither() = runTest {
        val forging: (ByteArray) -> ByteArray = { frame ->
            runCatching { PairingWire.decodeInviterComplete(frame) }.getOrNull()?.let { complete ->
                VerifiedPrefixes.clear()
                val forged = MembershipLog.deserialise(complete.membershipLog).withForgedCheckpoint(listOf(relay, joiner)).withForgedRotation()
                PairingWire.encode(InviterComplete(forged.serialise()))
            } ?: frame
        }
        assertFailsWith<PairingException> { pair(anyMemberGroup(3), anchorAbove = Int.MAX_VALUE, alterInviterFrames = forging) }
    }

    @Test
    fun aGenuineCheckpointBeforeTheJoinersAddIsStillCheckedFrom_cheaply() = runTest {
        val log = anyMemberGroup(CHECKPOINT_EVERY).checkpointIfDue(provider, founder).add()
        assertEquals(MembershipOp.CHECKPOINT, log.entries[log.entries.size - 2].op)
        val counting = PairingFerry.LogFetcher {
            VerifiedPrefixes.clear()
            joinerProvider.mlDsaChecks = 0
            mailbox
        }
        val (invited, joined) = pair(log, anchorAbove = 0, fetch = counting)
        val checks = joinerProvider.mlDsaChecks
        assertContentEquals(invited.membershipLog.serialise(), joined.membershipLog.serialise())
        assertTrue(checks in 1..8, "the checkpoint and the entries after it, not the history ($checks checks)")
    }

    @Test
    fun aGenuineCheckpointAfterTheJoinersAddIsWalked_andAccepted() = runTest {
        // The inviter's own checkpoint follows the joiner's ADD; the joiner recomputes it.
        val (invited, joined) = pair(anyMemberGroup(CHECKPOINT_EVERY - 1), anchorAbove = 0, fetch = forgingRelay { it })
        assertEquals(MembershipOp.CHECKPOINT, invited.membershipLog.entries.last().op)
        assertContentEquals(invited.membershipLog.serialise(), joined.membershipLog.serialise())
    }

    // ── Bug 2: nothing taken on a checkpoint's word reaches the strict cache ──────────────────

    @Test
    fun aRefusedForgeryLeavesNothingAStrictVerifyWouldResumeFrom() = runTest {
        var forged: MembershipLog? = null
        // Listing only the relay, so even the old code refuses it (the joiner is not a member).
        val relayOnly = forgingRelay { log -> log.withForgedCheckpoint(listOf(relay)).also { forged = it } }
        assertFailsWith<PairingException> { pair(anyMemberGroup(3), anchorAbove = 0, fetch = relayOnly) }

        // A longer log on the forged one: the relay rotating to a key of its choosing.
        val extended = forged!!.append(
            provider, MembershipOp.ROTATE, relay.identity,
            WrappedKeys.wrapFor(provider, suite, listOf(relay.identity), provider.randomBytes(32)),
            relay.signingKeyPair,
        )
        assertIs<MembershipVerification.Invalid>(extended.verify(provider), "warm cache")
        VerifiedPrefixes.clear()
        assertIs<MembershipVerification.Invalid>(extended.verify(provider), "cold cache")
    }

    // ── checkpoint() needs no cache ───────────────────────────────────────────────────────────

    @Test
    fun aCheckpointCanBeWrittenAfterTheCacheIsCleared() {
        val log = anyMemberGroup(4)
        assertIs<MembershipVerification.Valid>(log.verify(provider))
        VerifiedPrefixes.clear()
        val checkpointed = log.checkpoint(provider, founder)
        assertEquals(MembershipOp.CHECKPOINT, checkpointed.entries.last().op)
        VerifiedPrefixes.clear()
        assertIs<MembershipVerification.Valid>(checkpointed.verify(provider))
    }
}
