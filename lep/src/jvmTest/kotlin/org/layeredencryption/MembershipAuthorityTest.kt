package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A calendar belongs to the device that founded it, and membership is that device's prerogative
 * (LEP-R3).
 *
 * The product rule is simply stated: *User A can add anyone they like to User A's calendar; no
 * one else can add anyone to it.* The security consequence is what makes it worth enforcing in
 * the verifier rather than the UI — a compromised guest device cannot mint attacker-controlled
 * identities that would outlive its own revocation, because it could never add anyone in the
 * first place.
 *
 * Revocation is deliberately *not* restricted the same way. It removes access rather than
 * granting it, so a guest ejecting a stolen device promptly is worth more than the griefing it
 * permits — which the owner can undo by re-adding. The one exception is the founder itself:
 * since it alone can admit members, letting a guest revoke it would leave the calendar
 * permanently unable to admit anyone.
 */
class MembershipAuthorityTest {

    private val provider = BouncyCastleCryptoProvider()

    private val owner = DeviceKeys.generate(provider)
    private val sarah = DeviceKeys.generate(provider)
    private val mum = DeviceKeys.generate(provider)

    /** The owner's calendar with two guests on it. */
    private fun calendar() = MembershipLog.found(provider, owner.identity, owner.signingKeyPair)
        .append(provider, MembershipOp.ADD, sarah.identity, wrappedKeys = null, signer = owner.signingKeyPair)
        .append(provider, MembershipOp.ADD, mum.identity, wrappedKeys = null, signer = owner.signingKeyPair)

    private fun hex(device: DeviceKeys) = device.identity.signingPublicKey.toHexString()

    // ── Adding ────────────────────────────────────────────────────────────────────────────────

    @Test
    fun theOwnerMayAddAnyone() {
        val verification = calendar().verify(provider)
        assertIs<MembershipVerification.Valid>(verification)
        assertEquals(setOf(hex(owner), hex(sarah), hex(mum)), verification.activeMembers)
    }

    @Test
    fun aGuestMayNotAddAnyone() {
        val stranger = DeviceKeys.generate(provider)
        val grown = calendar().append(
            provider, MembershipOp.ADD, stranger.identity, wrappedKeys = null, signer = sarah.signingKeyPair,
        )

        val verification = grown.verify(provider)
        assertIs<MembershipVerification.Invalid>(verification)
        assertEquals("Only the founding device may add members", verification.reason)
        // Genesis, Sarah, Mum, then the guest's unauthorised addition.
        assertEquals(3, verification.entryIndex, "the guest's entry is the one refused")
    }

    @Test
    fun aCompromisedGuestCannotLeaveBehindIdentitiesThatSurviveItsRevocation() {
        // The attack the rule exists to prevent: a compromised device sponsors identities it
        // controls, so that revoking the device it was noticed on changes nothing. Every step of
        // it is now unauthorised rather than merely undone afterwards.
        val puppet = DeviceKeys.generate(provider)
        val sponsored = calendar().append(
            provider, MembershipOp.ADD, puppet.identity, wrappedKeys = null, signer = sarah.signingKeyPair,
        )
        assertIs<MembershipVerification.Invalid>(sponsored.verify(provider))

        // And with the guest gone, the puppet was never a member to begin with — so the rotation
        // that ejects the guest cannot hand it the new key.
        val afterRevoke = calendar().revoke(provider, sarah.identity, provider.randomBytes(32), owner.signingKeyPair)
        val active = assertIs<MembershipVerification.Valid>(afterRevoke.verify(provider)).activeMembers
        assertEquals(setOf(hex(owner), hex(mum)), active)
        assertTrue(hex(puppet) !in active)
    }

    // ── Revoking ──────────────────────────────────────────────────────────────────────────────

    @Test
    fun aGuestMayStillRevokeAnotherGuest() {
        // Removal is not escalation: prompt ejection of a stolen device is worth more than the
        // griefing this allows, and the owner can re-add anyone removed in bad faith.
        val after = calendar().revoke(provider, mum.identity, provider.randomBytes(32), sarah.signingKeyPair)
        assertIs<MembershipVerification.Valid>(after.verify(provider))
    }

    @Test
    fun aGuestMayNotRevokeTheOwner() {
        // Otherwise a single malicious guest could freeze the calendar forever: with the founder
        // gone, nobody would be able to admit anyone again.
        val after = calendar().revoke(provider, owner.identity, provider.randomBytes(32), sarah.signingKeyPair)

        val verification = after.verify(provider)
        assertIs<MembershipVerification.Invalid>(verification)
        assertEquals("Only the founding device may revoke itself", verification.reason)
    }

    @Test
    fun theOwnerMayStandDown() {
        // Leaving is always allowed, including for the founder — it is the one revocation of the
        // owner that is not somebody else seizing the calendar.
        val after = calendar().revoke(provider, owner.identity, provider.randomBytes(32), owner.signingKeyPair)
        val verification = after.verify(provider)
        assertIs<MembershipVerification.Valid>(verification)
        assertTrue(hex(owner) !in verification.activeMembers)
    }
}
