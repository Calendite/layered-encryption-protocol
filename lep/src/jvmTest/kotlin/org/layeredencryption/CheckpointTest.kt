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
import org.layeredencryption.pairing.ExistingCalendar
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingFerry
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Checkpoint entries (Membership_Log_Checkpoints.md, stage 2) and a newcomer starting from one. */
class CheckpointTest {

    private class Counting(private val inner: CryptoProvider = BouncyCastleCryptoProvider()) : CryptoProvider by inner {
        var mlDsaChecks = 0
        override fun mlDsa65Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
            mlDsaChecks++
            return inner.mlDsa65Verify(publicKey, message, signature)
        }
    }

    private val provider = Counting()
    private val founder = DeviceKeys.generate(provider)

    @BeforeTest
    fun forget() = VerifiedPrefixes.clear()

    private fun MembershipLog.add(by: DeviceKeys = founder, who: DeviceKeys = DeviceKeys.generate(provider)): MembershipLog =
        append(provider, MembershipOp.ADD, who.identity, wrappedKeys = null, signer = by.signingKeyPair)

    private fun founded() = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)

    /** A group on the any-member rules with [adds] members added after them. */
    private fun anyMemberGroup(adds: Int) =
        (1..adds).fold(founded().raiseRules(provider, MembershipRules.ANY_MEMBER, founder)) { log, _ -> log.add() }

    private fun valid(log: MembershipLog) = assertIs<MembershipVerification.Valid>(log.verify(provider)).activeMembers

    // ── Writing them ──────────────────────────────────────────────────────────────────────────

    @Test
    fun aCheckpointIsWrittenOnceSixteenEntriesHaveGoneBy() {
        val early = anyMemberGroup(CHECKPOINT_EVERY - 2).checkpointIfDue(provider, founder)
        assertTrue(early.entries.none { it.op == MembershipOp.CHECKPOINT }, "not due yet")
        val due = anyMemberGroup(CHECKPOINT_EVERY).checkpointIfDue(provider, founder)
        assertEquals(MembershipOp.CHECKPOINT, due.entries.last().op)
        valid(due)
        assertEquals(due, due.checkpointIfDue(provider, founder), "and not again straight after")
    }

    @Test
    fun noCheckpointUnderTheFounderOnlyRules_whereAnOlderBuildCouldNotReadOne() {
        val log = (1..CHECKPOINT_EVERY + 4).fold(founded()) { log, _ -> log.add() }
        assertEquals(log, log.checkpointIfDue(provider, founder))
    }

    @Test
    fun aCheckpointChangesNoMembersAndNoEpoch() {
        val log = anyMemberGroup(CHECKPOINT_EVERY)
        val members = valid(log)
        val checkpointed = log.checkpointIfDue(provider, founder)
        assertEquals(members, valid(checkpointed))
        assertEquals(log.rotatedKeysByEpoch(provider, founder), checkpointed.rotatedKeysByEpoch(provider, founder))
    }

    // ── Checking them ─────────────────────────────────────────────────────────────────────────

    @Test
    fun aCheckpointThatLeavesSomeoneOutIsRefused() {
        val log = anyMemberGroup(4)
        valid(log)
        val honest = assertTrueParse(log.checkpoint(provider, founder))
        val lying = CheckpointPayload(honest.genesisHash, honest.founderKey, honest.entryCount, honest.epoch, honest.rules, honest.suiteId, honest.members.drop(1))
        val forged = log.append(provider, MembershipOp.CHECKPOINT, founder.identity, lying.serialise(), founder.signingKeyPair)
        VerifiedPrefixes.clear()
        val verdict = assertIs<MembershipVerification.Invalid>(forged.verify(provider))
        assertEquals(log.entries.size, verdict.entryIndex)
    }

    @Test
    fun aCheckpointWithTheWrongEpochIsRefused() {
        val log = anyMemberGroup(4)
        val honest = assertTrueParse(log.checkpoint(provider, founder))
        val lying = CheckpointPayload(honest.genesisHash, honest.founderKey, honest.entryCount, honest.epoch + 1, honest.rules, honest.suiteId, honest.members)
        val forged = log.append(provider, MembershipOp.CHECKPOINT, founder.identity, lying.serialise(), founder.signingKeyPair)
        assertIs<MembershipVerification.Invalid>(forged.verify(provider))
    }

    @Test
    fun aCheckpointFromSomeoneOutsideTheGroupIsRefused() {
        val stranger = DeviceKeys.generate(provider)
        val log = anyMemberGroup(4)
        val honest = assertTrueParse(log.checkpoint(provider, founder))
        val forged = log.append(provider, MembershipOp.CHECKPOINT, stranger.identity, honest.serialise(), stranger.signingKeyPair)
        assertIs<MembershipVerification.Invalid>(forged.verify(provider))
    }

    @Test
    fun anyMemberMayWriteOne_notOnlyTheFounder() {
        val bob = DeviceKeys.generate(provider)
        val log = anyMemberGroup(3).add(who = bob)
        valid(log.checkpoint(provider, bob))
    }

    private fun assertTrueParse(checkpointed: MembershipLog): CheckpointPayload =
        assertIs<CheckpointPayload>(CheckpointPayload.parse(checkpointed.entries.last().wrappedKeys))

    // ── A newcomer starting from one ──────────────────────────────────────────────────────────

    @Test
    fun aNewcomerChecksFromTheLatestCheckpoint_andGetsTheSameMembers() {
        val log = anyMemberGroup(CHECKPOINT_EVERY).checkpointIfDue(provider, founder).add().add()
        val full = valid(log)
        VerifiedPrefixes.clear()
        provider.mlDsaChecks = 0
        val fromCheckpoint = assertIs<MembershipVerification.Valid>(log.verifyFromLatestCheckpoint(provider)).activeMembers
        assertEquals(full, fromCheckpoint)
        assertTrue(provider.mlDsaChecks <= 6, "the checkpoint and the entries after it, not the history (${provider.mlDsaChecks} checks)")
    }

    @Test
    fun aNewcomerStillRefusesAHistoryThatDoesNotHashUpToTheCheckpoint() {
        val log = anyMemberGroup(CHECKPOINT_EVERY).checkpointIfDue(provider, founder)
        val entries = log.entries.toMutableList()
        // Swap two entries before the checkpoint: every signature is genuine, the chain is not.
        entries[3] = entries[4].also { entries[4] = entries[3] }
        val shuffled = MembershipLog.deserialise(entries.fold(FrameWriter()) { w, e -> w.putBytes(e.serialise()) }.toByteArray())
        assertIs<MembershipVerification.Invalid>(shuffled.verifyFromLatestCheckpoint(provider))
    }

    @Test
    fun aRemovalAfterTheCheckpointIsSeenByTheNewcomer() {
        val leaving = DeviceKeys.generate(provider)
        val log = anyMemberGroup(CHECKPOINT_EVERY).add(who = leaving).checkpointIfDue(provider, founder)
        val after = log.revoke(provider, leaving.identity, provider.randomBytes(32), founder.signingKeyPair)
        val members = assertIs<MembershipVerification.Valid>(after.verifyFromLatestCheckpoint(provider)).activeMembers
        assertTrue(leaving.identity.signingPublicKey.toHexString() !in members)
    }

    // ── Pairing into a group whose log gains a checkpoint as the newcomer is added ────────────

    @Test
    fun pairingAddsTheCheckpointThatIsDue_andTheJoinerAcceptsIt() = runTest {
        val joiner = DeviceKeys.generate(provider)
        val log = anyMemberGroup(CHECKPOINT_EVERY - 1)
        val keys = EpochKeys.founding(provider.randomBytes(32))
        for (anchorAbove in listOf(Int.MAX_VALUE, 0)) {
            VerifiedPrefixes.clear()
            var mailbox: ByteArray? = null
            val toJoiner = Channel<ByteArray>(Channel.UNLIMITED)
            val toInviter = Channel<ByteArray>(Channel.UNLIMITED)
            val inviterSide = object : FrameChannel {
                override suspend fun send(frame: ByteArray) = toJoiner.send(frame)
                override suspend fun receive(): ByteArray = toInviter.receive()
                override fun close() { toJoiner.close() }
            }
            val joinerSide = object : FrameChannel {
                override suspend fun send(frame: ByteArray) = toInviter.send(frame)
                override suspend fun receive(): ByteArray = toJoiner.receive()
                override fun close() { toInviter.close() }
            }
            val code = PairingCode.generate(provider)
            val joining = CoroutineScope(EmptyCoroutineContext).async {
                PairingFerry.runJoiner(joinerSide, provider, joiner, code, fetchLog = { mailbox }, confirmSas = { true })
            }
            val invited = PairingFerry.runInviter(
                inviterSide, provider, founder, code, ExistingCalendar(keys, log),
                anchorAboveBytes = anchorAbove, publishLog = { published, _ -> mailbox = published.serialise() },
                confirmSas = { true },
            )
            val joined = joining.await()
            assertEquals(MembershipOp.CHECKPOINT, invited.membershipLog.entries.last().op, "the checkpoint follows the joiner's ADD")
            assertContentEquals(invited.membershipLog.serialise(), joined.membershipLog.serialise())
        }
    }
}
