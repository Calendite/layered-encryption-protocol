package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.membership.VerifiedPrefixes
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Verifying a log that extends one already verified checks only the new entries
 * (Membership_Log_Checkpoints.md, stage 1), and gives exactly the verdict a full check gives.
 */
class IncrementalVerifyTest {

    /** Counts the post-quantum signature checks, the expensive part of verifying a log. */
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

    private fun MembershipLog.add(): MembershipLog =
        append(provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity, wrappedKeys = null, signer = founder.signingKeyPair)

    private fun groupOf(size: Int) =
        (2..size).fold(MembershipLog.found(provider, founder.identity, founder.signingKeyPair)) { log, _ -> log.add() }

    private fun checksFor(block: () -> Unit): Int {
        provider.mlDsaChecks = 0
        block()
        return provider.mlDsaChecks
    }

    @Test
    fun extendingAVerifiedLogChecksOnlyTheNewEntries() {
        val log = groupOf(20)
        val full = checksFor { assertIs<MembershipVerification.Valid>(log.verify(provider)) }
        val grown = log.add()
        val incremental = checksFor { assertIs<MembershipVerification.Valid>(grown.verify(provider)) }
        assertTrue(full >= 20, "a first check walks every entry ($full checks)")
        assertTrue(incremental in 1..3, "the next checks only the new entry ($incremental checks)")
    }

    @Test
    fun checkingTheSameLogAgainCostsNoSignatureChecks() {
        val log = groupOf(10)
        log.verify(provider)
        assertEquals(0, checksFor { log.verify(provider) })
    }

    @Test
    fun theVerdictIsTheSameAsAFullCheck() {
        val log = groupOf(8).add().add()
        val cached = log.verify(provider)
        VerifiedPrefixes.clear()
        assertEquals(log.verify(provider), cached)
    }

    @Test
    fun alteredEarlierEntriesBehindAVerifiedTailAreCaught() {
        val log = groupOf(8)
        log.verify(provider)
        val entries = log.entries.toMutableList()
        // Every entry genuine and the last one the same, but two earlier ones swapped: the chain
        // breaks, and the cached state for that last entry is another history's.
        entries[2] = entries[3].also { entries[3] = entries[2] }
        val swapped = MembershipLog.deserialise(entries.fold(FrameWriter()) { w, e -> w.putBytes(e.serialise()) }.toByteArray())
        assertIs<MembershipVerification.Invalid>(swapped.verify(provider))
    }

    @Test
    fun aForgedEntryAfterAVerifiedPrefixIsStillCaught() {
        val log = groupOf(6)
        log.verify(provider)
        val stranger = DeviceKeys.generate(provider)
        // Signed by someone who is not a member: invalid however much of the log was checked before.
        val forged = log.append(provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity, wrappedKeys = null, signer = stranger.signingKeyPair)
        val verdict = assertIs<MembershipVerification.Invalid>(forged.verify(provider))
        assertEquals(6, verdict.entryIndex)
        VerifiedPrefixes.clear()
        assertEquals(verdict, forged.verify(provider), "the same verdict a full check gives")
    }

    @Test
    fun aDifferentHistoryOfTheSameLengthIsCheckedInFull() {
        val one = groupOf(5)
        one.verify(provider)
        val other = MembershipLog.found(provider, DeviceKeys.generate(provider).identity, founder.signingKeyPair)
        val checks = checksFor { other.verify(provider) }
        assertTrue(checks >= 1, "nothing of the first log's walk applies to another history")
    }

    @Test
    fun aRemovalAfterAVerifiedPrefixLeavesTheRightMembers() {
        val log = groupOf(5)
        log.verify(provider)
        val leaving = log.entries[3].deviceIdentity
        val after = log.revoke(provider, leaving, provider.randomBytes(32), founder.signingKeyPair)
        val members = assertIs<MembershipVerification.Valid>(after.verify(provider)).activeMembers
        assertEquals(4, members.size)
        VerifiedPrefixes.clear()
        assertEquals(members, assertIs<MembershipVerification.Valid>(after.verify(provider)).activeMembers)
    }
}
