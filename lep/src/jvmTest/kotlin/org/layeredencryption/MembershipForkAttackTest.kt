package org.layeredencryption

import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.membership.Reconciliation
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The LEP-03 attack: a member about to be revoked forks and pads its branch to defeat the
 * revocation. Removal-precedence reconciliation and invalid-transition rejection must close every
 * vector — a padded branch either fails verification or loses to the branch carrying the revoke,
 * and the revocation is always surfaced.
 */
class MembershipForkAttackTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private class Calendar {
        val provider: CryptoProvider = BouncyCastleCryptoProvider()
        val owner = DeviceKeys.generate(provider)
        val malloryB = DeviceKeys.generate(provider)

        /** genesis(owner) → ADD(B, by owner): a two-member calendar with B active. */
        val base: MembershipLog = MembershipLog.found(provider, owner.identity, owner.signingKeyPair)
            .append(provider, MembershipOp.ADD, malloryB.identity, wrappedKeys = null, signer = owner.signingKeyPair)
    }

    private fun MembershipLog.add(subject: DeviceIdentity, signer: DeviceKeys) =
        append(provider, MembershipOp.ADD, subject, wrappedKeys = null, signer = signer.signingKeyPair)

    private fun MembershipLog.revoke(subject: DeviceIdentity, signer: DeviceKeys) =
        revoke(provider, subject, provider.randomBytes(32), signer.signingKeyPair)

    private fun MembershipLog.isValid() = verify(provider) is MembershipVerification.Valid
    private fun MembershipLog.activeMembers() =
        (verify(provider) as MembershipVerification.Valid).activeMembers

    // ── Padding fails verification ────────────────────────────────────────────────────────────

    @Test
    fun paddingWithDuplicateSelfAddsFailsVerification() {
        val c = Calendar()
        // B, still active, forks and pads with signed ADD(B) — the exact LEP-03 primitive.
        var padded = c.base
        repeat(5) { padded = padded.add(c.malloryB.identity, c.malloryB) }

        assertFalse(padded.isValid(), "a branch padded with re-ADDs of an active member must not verify")
        // And a consumer cannot reconcile against it: it is InvalidBranch, never adopted.
        val ownerRevoke = c.base.revoke(c.malloryB.identity, c.owner)
        assertIs<Reconciliation.InvalidBranch>(ownerRevoke.reconcile(provider, padded))
    }

    @Test
    fun aRevokedDeviceCannotKeepAppending() {
        val c = Calendar()
        val revoked = c.base.revoke(c.malloryB.identity, c.owner) // owner removes B
        // B, now a non-member, tries to append anything at all.
        val bKeepsGoing = revoked.add(DeviceKeys.generate(provider).identity, c.malloryB)
        assertFalse(bKeepsGoing.isValid(), "an entry signed by a revoked device must not verify")
    }

    // ── Padding with valid junk loses to the revocation ───────────────────────────────────────

    @Test
    fun aLongJunkPaddedBranchLosesToTheRevokeBranch() {
        val c = Calendar()
        // A (owner) revokes B on a short branch.
        val ownerBranch = c.base.revoke(c.malloryB.identity, c.owner)
        // B forks before the revoke and pads with many distinct junk-device ADDs, trying to
        // out-grow the owner's branch. Length was never the defence — but now the padding is
        // not even well-formed history: membership belongs to the founding device, so a guest's
        // ADD is unauthorised and the whole branch fails verification.
        var bBranch = c.base
        repeat(20) { bBranch = bBranch.add(DeviceKeys.generate(provider).identity, c.malloryB) }
        assertFalse(bBranch.isValid(), "a guest cannot pad a branch with additions it may not make")
        assertTrue(bBranch.entries.size > ownerBranch.entries.size, "B's branch is longer")

        // Length was never the defence, and now the race never happens: an unauthorised branch
        // is refused from both sides rather than out-voted. B cannot bury its own revocation
        // under padding it has no authority to create.
        assertIs<Reconciliation.InvalidBranch>(ownerBranch.reconcile(provider, bBranch))
        assertIs<Reconciliation.InvalidBranch>(bBranch.reconcile(provider, ownerBranch))

        // The owner's branch stands, carrying the revocation a consumer must honour.
        assertTrue(ownerBranch.isValid())
        assertTrue(
            c.malloryB.identity.signingPublicKey.toHexString() !in
                (ownerBranch.verify(provider) as MembershipVerification.Valid).activeMembers,
        )
    }

    @Test
    fun revokeBeatsAddOnAOneEntryFork() {
        val c = Calendar()
        val revokeBranch = c.base.revoke(c.malloryB.identity, c.owner)
        val addBranch = c.base.add(DeviceKeys.generate(provider).identity, c.owner)

        assertFalse(assertIs<Reconciliation.Forked>(revokeBranch.reconcile(provider, addBranch)).theirsWins)
        assertTrue(assertIs<Reconciliation.Forked>(addBranch.reconcile(provider, revokeBranch)).theirsWins)
    }

    // ── Both branches revoke: the union is honoured ───────────────────────────────────────────

    @Test
    fun bothBranchesRevocationsAreUnionedNeverDropped() {
        val provider = BouncyCastleCryptoProvider()
        val owner = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)
        val cc = DeviceKeys.generate(provider)
        val base = MembershipLog.found(provider, owner.identity, owner.signingKeyPair)
            .append(provider, MembershipOp.ADD, b.identity, null, signer = owner.signingKeyPair)
            .append(provider, MembershipOp.ADD, cc.identity, null, signer = owner.signingKeyPair)

        val branchRevokesB = base.revoke(provider, b.identity, provider.randomBytes(32), owner.signingKeyPair)
        val branchRevokesC = base.revoke(provider, cc.identity, provider.randomBytes(32), owner.signingKeyPair)

        val fork = assertIs<Reconciliation.Forked>(branchRevokesB.reconcile(provider, branchRevokesC))
        assertTrue(b.identity.signingPublicKey.toHexString() in fork.revokedMembers, "B's revoke survives")
        assertTrue(cc.identity.signingPublicKey.toHexString() in fork.revokedMembers, "C's revoke survives")
    }

    // ── Determinism under grinding ────────────────────────────────────────────────────────────

    @Test
    fun equalRevokeAndLengthForksResolveDeterministicallyBothSides() {
        repeat(20) {
            val c = Calendar()
            // Two equal-length, zero-revoke branches: resolution falls to the true hash tie-break.
            val ours = c.base.add(DeviceKeys.generate(provider).identity, c.owner)
            val theirs = c.base.add(DeviceKeys.generate(provider).identity, c.owner)

            val a = assertIs<Reconciliation.Forked>(ours.reconcile(provider, theirs))
            val b = assertIs<Reconciliation.Forked>(theirs.reconcile(provider, ours))
            assertTrue(a.theirsWins != b.theirsWins, "the two sides must pick the same winning branch")
        }
    }

    @Test
    fun reconcilingAgainstAForgedBranchRefuses() {
        val c = Calendar()
        val good = c.base.revoke(c.malloryB.identity, c.owner)
        // Tamper the serialised bytes of a valid branch: the signature/chain no longer verifies.
        val tamperedBytes = c.base.serialise().copyOf().also { it[it.lastIndex] = (it[it.lastIndex] + 1).toByte() }
        val forged = runCatching { MembershipLog.deserialise(tamperedBytes) }.getOrNull()
        if (forged != null) {
            assertIs<Reconciliation.InvalidBranch>(good.reconcile(provider, forged))
        }
    }
}
