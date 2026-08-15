package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.membership.WrappedKeys
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Retest §4: a rotation-carrying entry must wrap the key for exactly the members it leaves
 * behind. A signed rotation that quietly omits an active member creates a silent membership/key
 * partition — the log vouches for them, the keys never reach them — and one that includes the
 * revoked subject or a stranger hands the new key to precisely who it exists to exclude.
 */
class MembershipRecipientValidationTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private val a = DeviceKeys.generate(provider)
    private val b = DeviceKeys.generate(provider)
    private val c = DeviceKeys.generate(provider)
    private val outsider = DeviceKeys.generate(provider)

    /** genesis(a) → ADD(b) → ADD(c): a three-member calendar. */
    private val log = MembershipLog.found(provider, a.identity, a.signingKeyPair)
        .append(provider, MembershipOp.ADD, b.identity, null, a.signingKeyPair)
        .append(provider, MembershipOp.ADD, c.identity, null, a.signingKeyPair)

    private fun wrapFor(vararg recipients: DeviceKeys): ByteArray =
        WrappedKeys.wrapFor(provider, recipients.map { it.identity }, provider.randomBytes(32))

    private fun assertInvalid(entry: MembershipLog, reason: String) {
        val verification = assertIs<MembershipVerification.Invalid>(entry.verify(provider))
        assertTrue(verification.reason.isNotEmpty(), reason)
    }

    // ── ROTATE ───────────────────────────────────────────────────────────────────────────────

    @Test
    fun aRotationForExactlyTheActiveMembersVerifies() {
        val rotated = log.append(provider, MembershipOp.ROTATE, a.identity, wrapFor(a, b, c), a.signingKeyPair)
        assertIs<MembershipVerification.Valid>(rotated.verify(provider))
    }

    @Test
    fun aRotationOmittingAnActiveMemberIsInvalid() {
        val partitioning = log.append(provider, MembershipOp.ROTATE, a.identity, wrapFor(a, b), a.signingKeyPair)
        assertInvalid(partitioning, "omitting c would leave them a member who can never read another epoch")
    }

    @Test
    fun aRotationIncludingAStrangerIsInvalid() {
        val leaking = log.append(provider, MembershipOp.ROTATE, a.identity, wrapFor(a, b, c, outsider), a.signingKeyPair)
        assertInvalid(leaking, "a non-member must never receive the context key")
    }

    @Test
    fun aRotationWithADuplicateRecipientIsInvalid() {
        // wrapFor itself refuses duplicates, so splice two bundles together.
        val duplicated = wrapFor(a, b, c) + wrapFor(a, b, c)
        val spliced = log.append(provider, MembershipOp.ROTATE, a.identity, duplicated, a.signingKeyPair)
        assertInvalid(spliced, "a duplicated recipient list must not verify")
    }

    @Test
    fun aRotationWithMalformedWrappedKeysIsInvalid() {
        val garbage = log.append(provider, MembershipOp.ROTATE, a.identity, ByteArray(37) { 0x42 }, a.signingKeyPair)
        assertInvalid(garbage, "an unparseable bundle must not verify")
    }

    // ── REVOKE ───────────────────────────────────────────────────────────────────────────────

    @Test
    fun aKeyedRevocationForExactlyTheSurvivorsVerifies() {
        val revoked = log.revoke(provider, c.identity, provider.randomBytes(32), a.signingKeyPair)
        assertIs<MembershipVerification.Valid>(revoked.verify(provider))
    }

    @Test
    fun aKeyedRevocationIncludingTheRevokedSubjectIsInvalid() {
        val selfDefeating = log.append(provider, MembershipOp.REVOKE, c.identity, wrapFor(a, b, c), a.signingKeyPair)
        assertInvalid(selfDefeating, "wrapping the new key for the ejected member defeats the entry")
    }

    @Test
    fun aKeyedRevocationOmittingASurvivorIsInvalid() {
        val partitioning = log.append(provider, MembershipOp.REVOKE, c.identity, wrapFor(a), a.signingKeyPair)
        assertInvalid(partitioning, "omitting b would silently cut them off from every later epoch")
    }

    @Test
    fun aKeylessRevocationIsLegalOnlyInsideATerminatedBatch() {
        // Fork resolution batches its removals under one final rotation. The batch as a whole is
        // valid; its prefix — where somebody reads as revoked while the old key stays current —
        // must not be presentable as a state of its own (6ddd7e4 retest, finding 1).
        val keyless = log.append(provider, MembershipOp.REVOKE, c.identity, null, a.signingKeyPair)
        assertIs<MembershipVerification.Invalid>(keyless.verify(provider))
        assertIs<MembershipVerification.Valid>(keyless.rotate(provider, provider.randomBytes(32), signer = a).verify(provider))
    }
}
