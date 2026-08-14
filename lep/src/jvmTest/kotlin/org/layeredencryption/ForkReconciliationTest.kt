package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.Reconciliation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Two devices changing membership at the same moment.
 *
 * Rare, because membership changes are human-initiated, but the old behaviour on hitting one was
 * to refuse both logs forever, leaving two phones permanently disagreeing about who is in the
 * calendar. That is worse than any merge.
 *
 * The rule only has to be deterministic and identical everywhere: both devices hold the same two
 * branches and must pick the same winner without exchanging a word about it.
 */
class ForkReconciliationTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private fun founded(): Pair<MembershipLog, DeviceKeys> {
        val owner = DeviceKeys.generate(provider)
        return MembershipLog.found(provider, owner.identity, owner.signingKeyPair) to owner
    }

    private fun MembershipLog.plusAdd(owner: DeviceKeys) = append(
        provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity,
        wrappedKeys = null, signer = owner.signingKeyPair,
    )

    @Test
    fun `identical logs are the same`() {
        val (log, _) = founded()

        assertIs<Reconciliation.Same>(log.reconcile(provider, MembershipLog.deserialise(log.serialise())))
    }

    @Test
    fun `a pure extension is recognised in both directions`() {
        val (base, owner) = founded()
        val longer = base.plusAdd(owner)

        assertIs<Reconciliation.TheyExtendUs>(base.reconcile(provider, longer))
        assertIs<Reconciliation.WeExtendThem>(longer.reconcile(provider, base))
    }

    @Test
    fun `two concurrent appends are a fork, and say where they parted`() {
        val (base, owner) = founded()
        val ours = base.plusAdd(owner)
        val theirs = base.plusAdd(owner)

        val fork = assertIs<Reconciliation.Forked>(ours.reconcile(provider, theirs))
        assertEquals(1, fork.sharedPrefix, "they agree on genesis and nothing after it")
        assertEquals(1, ours.entriesAfter(fork.sharedPrefix).size)
    }

    /**
     * The property the whole scheme rests on. Both devices hold the same pair of branches and must
     * independently choose the same one, or they build on different histories and fork again.
     */
    @Test
    fun `both sides of a fork choose the same winner`() {
        repeat(20) {
            val (base, owner) = founded()
            val ours = base.plusAdd(owner)
            val theirs = base.plusAdd(owner)

            val fromOurSide = assertIs<Reconciliation.Forked>(ours.reconcile(provider, theirs))
            val fromTheirSide = assertIs<Reconciliation.Forked>(theirs.reconcile(provider, ours))

            // One says "theirs wins", the other must say "mine wins": the same log, either way.
            assertTrue(
                fromOurSide.theirsWins != fromTheirSide.theirsWins,
                "the two devices disagreed about which branch to build on",
            )
        }
    }

    @Test
    fun `with equal revocations the longer branch wins`() {
        // No revocations on either side, so removal-precedence is a tie and length decides.
        val (base, owner) = founded()
        val short = base.plusAdd(owner)
        val long = base.plusAdd(owner).plusAdd(owner)

        assertTrue(assertIs<Reconciliation.Forked>(short.reconcile(provider, long)).theirsWins)
        assertTrue(!assertIs<Reconciliation.Forked>(long.reconcile(provider, short)).theirsWins)
    }

    @Test
    fun `a fork deeper in the chain keeps the whole shared history`() {
        val (base, owner) = founded()
        val shared = base.plusAdd(owner).plusAdd(owner)
        val ours = shared.plusAdd(owner)
        val theirs = shared.plusAdd(owner)

        val fork = assertIs<Reconciliation.Forked>(ours.reconcile(provider, theirs))

        assertEquals(3, fork.sharedPrefix, "genesis plus the two agreed additions")
        assertEquals(1, ours.entriesAfter(fork.sharedPrefix).size, "only the divergent tail is in question")
    }

    /**
     * Not a fork at all. Two logs that share nothing were never the same calendar, and calling that
     * a fork would let a stranger's log replace this one wholesale on the longest-branch rule.
     */
    @Test
    fun `an unrelated log is not a fork`() {
        val (ours, _) = founded()
        val (theirs, theirOwner) = founded()

        assertIs<Reconciliation.Unrelated>(ours.reconcile(provider, theirs))
        // A valid unrelated log (their own owner signs the addition) is still Unrelated, not a fork.
        assertIs<Reconciliation.Unrelated>(ours.reconcile(provider, theirs.plusAdd(theirOwner)))
    }
}
