package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.ForkResolution
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.membership.Reconciliation
import org.layeredencryption.membership.WrappedKeys
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * RT-01: fork resolution must *enforce* what reconciliation only reports. The revocation union
 * becomes real revocations on the winning branch, a condemned member's smuggled additions fall
 * with their sponsor, and resolution rotates the context key so that nobody outside the resolved
 * membership — revoked, tainted, or dropped with the losing branch — can read anything sealed
 * after the fork.
 */
class MembershipForkResolutionTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private fun newKey() = provider.randomBytes(WrappedKeys.CONTEXT_KEY_BYTES)

    private fun MembershipLog.add(subject: DeviceKeys, signer: DeviceKeys) =
        append(provider, MembershipOp.ADD, subject.identity, wrappedKeys = null, signer = signer.signingKeyPair)

    private fun MembershipLog.revokeBy(subject: DeviceKeys, signer: DeviceKeys) =
        revoke(provider, subject.identity, newKey(), signer.signingKeyPair)

    private fun MembershipLog.actives(): Set<String> =
        (verify(provider) as MembershipVerification.Valid).activeMembers

    private fun hex(device: DeviceKeys) = device.identity.signingPublicKey.toHexString()

    /** Whether [device] can read [key] from any rotation this log addressed to it. */
    private fun MembershipLog.handsKeyTo(device: DeviceKeys, key: ByteArray): Boolean =
        rotatedKeysFor(provider, device).any { it.contentEquals(key) }

    // ── The padding attack, end to end ───────────────────────────────────────────────────────

    @Test
    fun paddedBranchLosesItsAuthorAndItsPuppets() {
        val a = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)
        val c = DeviceKeys.generate(provider)
        val p1 = DeviceKeys.generate(provider)
        val p2 = DeviceKeys.generate(provider)
        val base = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(b, a).add(c, a)

        // A revokes B; B races it with a spurious revocation of C plus sock-puppet additions,
        // winning the tie-break on length. Exactly the retest's example attack.
        val honest = base.revokeBy(b, a)
        val padded = base.revokeBy(c, b).add(p1, b).add(p2, b)

        val resolution = honest.resolveFork(provider, padded, resolver = a)
        val resolved = assertIs<ForkResolution.Resolved>(resolution)

        // B wins the branch race and still loses everything: itself, and both puppets.
        assertEquals(setOf(hex(b), hex(p1), hex(p2)), resolved.revoked)
        assertEquals(setOf(hex(a)), resolved.log.actives())
        assertTrue(resolved.lostAdditions.isEmpty())

        // The rotation excludes every condemned identity; the survivor reads the new key.
        val key = assertNotNull(resolved.newMasterKey)
        assertTrue(resolved.log.handsKeyTo(a, key))
        for (outsider in listOf(b, c, p1, p2)) {
            assertFalse(resolved.log.handsKeyTo(outsider, key), "an excluded device must not read the new key")
        }
    }

    @Test
    fun outRevokingTheHonestBranchStillEndsInRevocation() {
        val a = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)
        val c = DeviceKeys.generate(provider)
        val d = DeviceKeys.generate(provider)
        val base = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(b, a).add(c, a).add(d, a)

        // B outguns the honest branch with two spurious revocations. Its branch wins outright —
        // and resolution then revokes B on it.
        val honest = base.revokeBy(b, a)
        val malicious = base.revokeBy(c, b).revokeBy(d, b)

        val resolved = assertIs<ForkResolution.Resolved>(honest.resolveFork(provider, malicious, resolver = a))

        assertEquals(setOf(hex(b)), resolved.revoked)
        assertEquals(setOf(hex(a)), resolved.log.actives())
        val key = assertNotNull(resolved.newMasterKey)
        assertTrue(resolved.log.handsKeyTo(a, key))
        for (outsider in listOf(b, c, d)) {
            assertFalse(resolved.log.handsKeyTo(outsider, key))
        }
    }

    @Test
    fun twoHonestBranchesRevokingDifferentMembersRemoveBoth() {
        val a = DeviceKeys.generate(provider)
        val c = DeviceKeys.generate(provider)
        val x = DeviceKeys.generate(provider)
        val y = DeviceKeys.generate(provider)
        val base = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(c, a).add(x, a).add(y, a)

        val branchA = base.revokeBy(x, a)
        val branchC = base.revokeBy(y, c)

        val resolved = assertIs<ForkResolution.Resolved>(branchA.resolveFork(provider, branchC, resolver = a))

        assertEquals(setOf(hex(a), hex(c)), resolved.log.actives())
        val key = assertNotNull(resolved.newMasterKey)
        assertTrue(resolved.log.handsKeyTo(a, key))
        assertTrue(resolved.log.handsKeyTo(c, key))
        assertFalse(resolved.log.handsKeyTo(x, key))
        assertFalse(resolved.log.handsKeyTo(y, key))
    }

    @Test
    fun taintIsTransitive() {
        val a = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)
        val b2 = DeviceKeys.generate(provider)
        val b3 = DeviceKeys.generate(provider)
        val c = DeviceKeys.generate(provider)
        val base = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(b, a).add(c, a)

        // B sponsors B2, who sponsors B3: a puppet chain. All of it falls with B.
        val honest = base.revokeBy(b, a)
        val chained = base.revokeBy(c, b).add(b2, b).add(b3, b2)

        val resolved = assertIs<ForkResolution.Resolved>(honest.resolveFork(provider, chained, resolver = a))

        assertEquals(setOf(hex(b), hex(b2), hex(b3)), resolved.revoked)
        assertEquals(setOf(hex(a)), resolved.log.actives())
        val key = assertNotNull(resolved.newMasterKey)
        for (outsider in listOf(b, b2, b3)) {
            assertFalse(resolved.log.handsKeyTo(outsider, key))
        }
    }

    // ── Losing-branch additions ──────────────────────────────────────────────────────────────

    @Test
    fun honestLosingAdditionIsDroppedReportedAndKeyExcluded() {
        val a = DeviceKeys.generate(provider)
        val c = DeviceKeys.generate(provider)
        val e = DeviceKeys.generate(provider)
        val d = DeviceKeys.generate(provider)
        val base = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(c, a).add(e, a)

        // A honestly adds D while C honestly revokes E. Removal precedence picks C's branch, so
        // D's addition is dropped — but D was handed key material when added, so resolution must
        // rotate even though there is nobody left to revoke.
        val withAdd = base.add(d, a)
        val withRevoke = base.revokeBy(e, c)

        val resolved = assertIs<ForkResolution.Resolved>(withAdd.resolveFork(provider, withRevoke, resolver = a))

        assertTrue(resolved.revoked.isEmpty(), "nobody was left to revoke on the winner")
        assertEquals(setOf(hex(d)), resolved.lostAdditions)
        assertEquals(setOf(hex(a), hex(c)), resolved.log.actives())

        val key = assertNotNull(resolved.newMasterKey, "a dropped key-holder must force a rotation")
        assertTrue(resolved.log.handsKeyTo(a, key))
        assertTrue(resolved.log.handsKeyTo(c, key))
        assertFalse(resolved.log.handsKeyTo(d, key))
        assertFalse(resolved.log.handsKeyTo(e, key))
    }

    // ── Resolver authority ───────────────────────────────────────────────────────────────────

    @Test
    fun aCondemnedResolverIsExcluded() {
        val a = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)
        val c = DeviceKeys.generate(provider)
        val base = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(b, a).add(c, a)

        val honest = base.revokeBy(b, a)
        val padded = base.revokeBy(c, b)

        // B resolving its own fork: condemned by the union, no authority.
        assertIs<ForkResolution.ResolverExcluded>(padded.resolveFork(provider, honest, resolver = b))
    }

    @Test
    fun aResolverAddedOnlyOnTheLosingBranchIsExcluded() {
        val a = DeviceKeys.generate(provider)
        val c = DeviceKeys.generate(provider)
        val e = DeviceKeys.generate(provider)
        val d = DeviceKeys.generate(provider)
        val base = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(c, a).add(e, a)

        val withAdd = base.add(d, a)
        val withRevoke = base.revokeBy(e, c)

        // D exists only on the losing branch: it cannot sign entries the winner would verify.
        assertIs<ForkResolution.ResolverExcluded>(withAdd.resolveFork(provider, withRevoke, resolver = d))
    }

    // ── Convergence ──────────────────────────────────────────────────────────────────────────

    @Test
    fun concurrentResolutionsConvergeWithoutASecondRotation() {
        val a = DeviceKeys.generate(provider)
        val c = DeviceKeys.generate(provider)
        val x = DeviceKeys.generate(provider)
        val y = DeviceKeys.generate(provider)
        val base = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(c, a).add(x, a).add(y, a)

        val branchA = base.revokeBy(x, a)
        val branchC = base.revokeBy(y, c)

        // A and C resolve the same fork independently, without exchanging a word.
        val byA = assertIs<ForkResolution.Resolved>(branchA.resolveFork(provider, branchC, resolver = a))
        val byC = assertIs<ForkResolution.Resolved>(branchC.resolveFork(provider, branchA, resolver = c))
        assertEquals(byA.revoked, byC.revoked, "concurrent resolvers must agree on who is revoked")
        assertEquals(byA.log.actives(), byC.log.actives())

        // Their resolutions differ only in signer and key bytes, so they fork again — and that
        // fork resolves as pure convergence: adopt the deterministic winner, rotate nothing.
        val convergence = assertIs<ForkResolution.Resolved>(byA.log.resolveFork(provider, byC.log, resolver = a))
        assertNull(convergence.newMasterKey, "converging on an already-resolved fork must not rotate again")
        assertTrue(convergence.revoked.isEmpty())
        assertTrue(convergence.lostAdditions.isEmpty())
        assertEquals(convergence.log.actives(), byA.log.actives())
    }

    // ── The ROTATE op itself ─────────────────────────────────────────────────────────────────

    @Test
    fun rotateHandsEveryActiveMemberTheNewKeyAndSurvivesSerialisation() {
        val a = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)
        val log = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(b, a)

        val key = newKey()
        val rotated = log.rotate(provider, key, signer = a)

        assertIs<MembershipVerification.Valid>(rotated.verify(provider))
        assertEquals(setOf(hex(a), hex(b)), rotated.actives(), "a rotation changes no membership")
        assertTrue(rotated.handsKeyTo(a, key))
        assertTrue(rotated.handsKeyTo(b, key))

        val roundTripped = MembershipLog.deserialise(rotated.serialise())
        assertIs<MembershipVerification.Valid>(roundTripped.verify(provider))
        assertTrue(roundTripped.handsKeyTo(b, key))
    }

    @Test
    fun rotationEpochsInterleaveWithRevocationsInLogOrder() {
        val a = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)
        val c = DeviceKeys.generate(provider)
        val log = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(b, a).add(c, a)

        val rotateKey = newKey()
        val revokeKey = newKey()
        val history = log.rotate(provider, rotateKey, signer = a)
            .revoke(provider, c.identity, revokeKey, a.signingKeyPair)

        // B sees both epochs, oldest first; C saw only the rotation that predated its removal.
        assertEquals(listOf(true, true), history.rotatedKeysFor(provider, b).map { it.contentEquals(rotateKey) || it.contentEquals(revokeKey) })
        assertTrue(history.rotatedKeysFor(provider, b)[0].contentEquals(rotateKey))
        assertTrue(history.rotatedKeysFor(provider, b)[1].contentEquals(revokeKey))
        assertEquals(1, history.rotatedKeysFor(provider, c).size)
    }

    @Test
    fun rotateAuthorisationIsStrict() {
        val a = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)
        val outsider = DeviceKeys.generate(provider)
        val log = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(b, a)
        val wrapped = WrappedKeys.wrapFor(provider, listOf(a.identity, b.identity), newKey())

        // A rotation about somebody else is not a rotation.
        val impersonating = log.append(provider, MembershipOp.ROTATE, b.identity, wrapped, a.signingKeyPair)
        assertIs<MembershipVerification.Invalid>(impersonating.verify(provider))

        // A rotation carrying no keys rotates to nobody.
        val empty = log.append(provider, MembershipOp.ROTATE, a.identity, wrappedKeys = null, signer = a.signingKeyPair)
        assertIs<MembershipVerification.Invalid>(empty.verify(provider))

        // A non-member cannot rotate.
        val foreign = log.append(provider, MembershipOp.ROTATE, outsider.identity, wrapped, outsider.signingKeyPair)
        assertIs<MembershipVerification.Invalid>(foreign.verify(provider))
    }

    // ── Non-fork pass-through ────────────────────────────────────────────────────────────────

    @Test
    fun nonForkOutcomesPassThroughUnresolved() {
        val a = DeviceKeys.generate(provider)
        val b = DeviceKeys.generate(provider)
        val log = MembershipLog.found(provider, a.identity, a.signingKeyPair).add(b, a)

        val same = assertIs<ForkResolution.NotForked>(log.resolveFork(provider, log, resolver = a))
        assertIs<Reconciliation.Same>(same.reconciliation)

        val extended = log.revokeBy(b, a)
        val theyExtend = assertIs<ForkResolution.NotForked>(log.resolveFork(provider, extended, resolver = a))
        assertIs<Reconciliation.TheyExtendUs>(theyExtend.reconciliation)

        val stranger = MembershipLog.found(provider, b.identity, b.signingKeyPair)
        val unrelated = assertIs<ForkResolution.NotForked>(log.resolveFork(provider, stranger, resolver = a))
        assertIs<Reconciliation.Unrelated>(unrelated.reconciliation)

        // A branch padded with re-ADDs of an active member (the LEP-03 primitive) never verifies,
        // so it can never reach resolution either.
        val padded = log.add(b, b)
        val invalid = assertIs<ForkResolution.NotForked>(log.resolveFork(provider, padded, resolver = a))
        assertIs<Reconciliation.InvalidBranch>(invalid.reconciliation)
    }
}
