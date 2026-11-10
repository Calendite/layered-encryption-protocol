package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.ForkResolution
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipRules
import org.layeredencryption.membership.MembershipVerification
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Membership rules version 2, any member (Calendite's Calendar_Keys_And_Consent.md).
 *
 * Under the founder-only rules ([MembershipAuthorityTest]) a group whose founder's phone is lost can
 * never admit or remove anyone, and only the founder can invite. Once each owner's calendar has a key
 * of its own, joining grants nothing, so the founder can give that privilege up: one RULES entry, and
 * from then on any member may add, and any member may remove the founder. A log without the entry
 * verifies exactly as before.
 */
class MembershipRulesTest {

    private val provider = BouncyCastleCryptoProvider()

    private val founder = DeviceKeys.generate(provider)
    private val bob = DeviceKeys.generate(provider)
    private val dana = DeviceKeys.generate(provider)
    private val charlie = DeviceKeys.generate(provider)

    private fun hex(device: DeviceKeys) = device.identity.signingPublicKey.toHexString()

    /** The founder with Bob and Dana, under the founder-only rules every log starts with. */
    private fun group() = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
        .append(provider, MembershipOp.ADD, bob.identity, wrappedKeys = null, signer = founder.signingKeyPair)
        .append(provider, MembershipOp.ADD, dana.identity, wrappedKeys = null, signer = founder.signingKeyPair)

    private fun anyMember() = group().raiseRules(provider, MembershipRules.ANY_MEMBER, founder)

    private fun MembershipLog.add(device: DeviceKeys, by: DeviceKeys) =
        append(provider, MembershipOp.ADD, device.identity, wrappedKeys = null, signer = by.signingKeyPair)

    // ── Which rules a log is under ────────────────────────────────────────────────────────────

    @Test
    fun aLogStartsUnderTheFounderOnlyRules() {
        assertEquals(MembershipRules.FOUNDER_ONLY, group().rulesVersion())
        assertEquals(MembershipRules.ANY_MEMBER, anyMember().rulesVersion())
    }

    @Test
    fun raisingTheRulesChangesNoMembers() {
        val before = assertIs<MembershipVerification.Valid>(group().verify(provider)).activeMembers
        val after = assertIs<MembershipVerification.Valid>(anyMember().verify(provider)).activeMembers
        assertEquals(before, after)
    }

    // ── Adding ────────────────────────────────────────────────────────────────────────────────

    @Test
    fun underAnyMemberRules_aMemberMayAddSomeone() {
        val verification = anyMember().add(charlie, by = bob).verify(provider)
        val active = assertIs<MembershipVerification.Valid>(verification).activeMembers
        assertTrue(hex(charlie) in active)
    }

    @Test
    fun underFounderOnlyRules_aMemberStillMayNot() {
        val verification = group().add(charlie, by = bob).verify(provider)
        assertEquals("Only the founding device may add members", assertIs<MembershipVerification.Invalid>(verification).reason)
    }

    @Test
    fun anAdditionMadeBeforeTheRulesChangedIsStillRefused() {
        // Rules apply from their entry onwards, never backwards: an unauthorised ADD earlier in the
        // chain does not become valid because the founder relaxed the rules after it.
        val log = group().add(charlie, by = bob).raiseRules(provider, MembershipRules.ANY_MEMBER, founder)
        assertIs<MembershipVerification.Invalid>(log.verify(provider))
    }

    @Test
    fun someoneAddedByAMemberMayAddSomeoneToo() {
        val eve = DeviceKeys.generate(provider)
        val verification = anyMember().add(charlie, by = bob).add(eve, by = charlie).verify(provider)
        assertTrue(hex(eve) in assertIs<MembershipVerification.Valid>(verification).activeMembers)
    }

    // ── Removing the founder ──────────────────────────────────────────────────────────────────

    @Test
    fun underAnyMemberRules_aMemberMayRemoveTheFounder() {
        val log = anyMember().revoke(provider, founder.identity, provider.randomBytes(32), bob.signingKeyPair)
        val active = assertIs<MembershipVerification.Valid>(log.verify(provider)).activeMembers
        assertEquals(setOf(hex(bob), hex(dana)), active)
    }

    @Test
    fun underFounderOnlyRules_aMemberStillMayNotRemoveTheFounder() {
        val log = group().revoke(provider, founder.identity, provider.randomBytes(32), bob.signingKeyPair)
        assertEquals(
            "Only the founding device may revoke itself",
            assertIs<MembershipVerification.Invalid>(log.verify(provider)).reason,
        )
    }

    @Test
    fun withTheFounderGone_theOthersCanStillAddSomeone() {
        // The case the founder-only rules could not survive: the founder's phone is lost.
        val log = anyMember()
            .revoke(provider, founder.identity, provider.randomBytes(32), bob.signingKeyPair)
            .add(charlie, by = dana)
        assertTrue(hex(charlie) in assertIs<MembershipVerification.Valid>(log.verify(provider)).activeMembers)
    }

    // ── Who may change the rules ──────────────────────────────────────────────────────────────

    @Test
    fun onlyTheFounderMayChangeTheRules() {
        val log = group().append(
            provider, MembershipOp.RULES, bob.identity, wrappedKeys = byteArrayOf(MembershipRules.ANY_MEMBER.toByte()),
            signer = bob.signingKeyPair,
        )
        assertEquals("Only the founding device may change the rules", assertIs<MembershipVerification.Invalid>(log.verify(provider)).reason)
    }

    @Test
    fun rulesOnlyMoveForward() {
        val again = anyMember().raiseRules(provider, MembershipRules.ANY_MEMBER, founder)
        assertEquals("Rules may only move forward", assertIs<MembershipVerification.Invalid>(again.verify(provider)).reason)
        val back = anyMember().raiseRules(provider, MembershipRules.FOUNDER_ONLY, founder)
        assertEquals("Rules may only move forward", assertIs<MembershipVerification.Invalid>(back.verify(provider)).reason)
    }

    @Test
    fun aRulesVersionThisLibraryDoesNotKnowFailsTheLog() {
        val log = group().raiseRules(provider, MembershipRules.CURRENT + 1, founder)
        assertEquals("Unknown rules version ${MembershipRules.CURRENT + 1}", assertIs<MembershipVerification.Invalid>(log.verify(provider)).reason)
    }

    @Test
    fun aRulesEntryMustNameExactlyOneVersion() {
        val log = group().append(
            provider, MembershipOp.RULES, founder.identity, wrappedKeys = byteArrayOf(2, 0), signer = founder.signingKeyPair,
        )
        assertEquals("Rules entry must name one version", assertIs<MembershipVerification.Invalid>(log.verify(provider)).reason)
    }

    @Test
    fun aRulesEntryRoundTripsThroughTheWire() {
        val log = MembershipLog.deserialise(anyMember().serialise())
        assertEquals(MembershipRules.ANY_MEMBER, log.rulesVersion())
        assertIs<MembershipVerification.Valid>(log.verify(provider))
    }

    // ── Forks ─────────────────────────────────────────────────────────────────────────────────

    @Test
    fun aForkStillTakesARevokedMembersAdditionsWithThem() {
        // Bob adds Charlie on one branch; Dana revokes Bob on the other. Removals win, and what Bob
        // added goes with him: the guarantee founder-only rules gave by forbidding it, kept by fork
        // resolution once members may add.
        val base = anyMember()
        val bobBranch = base.add(charlie, by = bob)
        val danaBranch = base.revoke(provider, bob.identity, provider.randomBytes(32), dana.signingKeyPair)

        val resolved = assertIs<ForkResolution.Resolved>(danaBranch.resolveFork(provider, bobBranch, dana))
        val active = assertIs<MembershipVerification.Valid>(resolved.log.verify(provider)).activeMembers
        assertFalse(hex(bob) in active)
        assertFalse(hex(charlie) in active, "Bob's addition must not outlive Bob")
    }
}
