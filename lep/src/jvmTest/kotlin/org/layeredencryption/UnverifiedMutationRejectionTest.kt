package org.layeredencryption

import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.suite.Suite1
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A parsed-but-unverified membership log can never drive a key wrap (LEP-R2).
 *
 * Deserialising proves a log is well-formed, not authentic. A relay or a restored backup can
 * hand over a structurally perfect log carrying an unauthorised `ADD` that names an attacker's
 * KEM key; if a rotation then wrapped the fresh context key to "every active member", it would
 * encapsulate it straight to the attacker. These tests pin that the refusal happens **before any
 * cryptographic work**, not merely that the resulting log would later fail verification.
 */
class UnverifiedMutationRejectionTest {

    /** Counts the operations a wrap would perform, so "rejected early" is measurable. */
    private class CountingProvider(private val delegate: CryptoProvider) : CryptoProvider by delegate {
        var encapsulations = 0
            private set

        override fun mlKem768Encapsulate(publicKey: ByteArray): KemEncapsulation {
            encapsulations++
            return delegate.mlKem768Encapsulate(publicKey)
        }
    }

    private val provider = BouncyCastleCryptoProvider()
    private val founder = DeviceKeys.generate(provider)
    private val member = DeviceKeys.generate(provider)
    private val attacker = DeviceKeys.generate(provider)

    /**
     * A log whose bytes parse cleanly but whose final `ADD` was signed by a non-member: exactly
     * what a hostile relay would serve.
     */
    private fun forgedLog(): MembershipLog {
        val honest = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
            .append(provider, MembershipOp.ADD, member.identity, wrappedKeys = null, signer = founder.signingKeyPair)
        val head = honest.head(provider)
        val unsigned = org.layeredencryption.membership.MembershipEntry(
            head, MembershipOp.ADD, attacker.identity, null, attacker.identity.signingPublicKey, ByteArray(0),
        )
        val injected = org.layeredencryption.membership.MembershipEntry(
            head, MembershipOp.ADD, attacker.identity, null, attacker.identity.signingPublicKey,
            // Self-signed by the attacker, who is not a member — structurally valid, unauthorised.
            HybridSignature.sign(provider, attacker.signingPrivateKey, unsigned.unsignedBytes()),
        )
        return MembershipLog.deserialise(
            honest.serialise() + FrameWriter().putBytes(injected.serialise()).toByteArray(),
        )
    }

    @Test
    fun theForgedLogIsStructurallyValidButUnauthorised() {
        val log = forgedLog()
        // It parses — that is the whole hazard. Verification is what catches it.
        assertEquals(3, log.entries.size)
        val verification = log.verify(provider)
        assertIs<MembershipVerification.Invalid>(verification)
        assertEquals("Signer is not an active member", verification.reason)
    }

    @Test
    fun rotateOnAnUnverifiedLogRefusesBeforeAnyKemWork() {
        val counting = CountingProvider(provider)
        val log = MembershipLog.deserialise(forgedLog().serialise())

        val failure = assertFailsWith<IllegalArgumentException> {
            log.rotate(counting, provider.randomBytes(32), founder)
        }
        assertTrue("unverified" in failure.message.orEmpty(), failure.message.orEmpty())
        assertEquals(0, counting.encapsulations, "the attacker's KEM key must never be encapsulated to")
    }

    @Test
    fun revokeOnAnUnverifiedLogRefusesBeforeAnyKemWork() {
        val counting = CountingProvider(provider)
        val log = MembershipLog.deserialise(forgedLog().serialise())

        assertFailsWith<IllegalArgumentException> {
            log.revoke(counting, member.identity, provider.randomBytes(32), founder.signingKeyPair)
        }
        assertEquals(0, counting.encapsulations)
    }

    @Test
    fun suiteUpgradeOnAnUnverifiedLogRefusesBeforeAnyKemWork() {
        val counting = CountingProvider(provider)
        val fake = org.layeredencryption.suite.FakeSuites.fakeSuite()
        val resolver = org.layeredencryption.suite.FakeSuites.resolverWith(fake)
        val log = MembershipLog.deserialise(forgedLog().serialise(), resolver)

        assertFailsWith<IllegalArgumentException> {
            log.upgradeSuite(counting, fake, provider.randomBytes(32), founder, resolver = resolver)
        }
        assertEquals(0, counting.encapsulations)
    }

    @Test
    fun theAttackerNeverAppearsAmongTheRecipientsOfAnHonestRotation() {
        // The same honest prefix, mutated legitimately: only the real members are wrapped for.
        val honest = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
            .append(provider, MembershipOp.ADD, member.identity, wrappedKeys = null, signer = founder.signingKeyPair)
        val rotated = honest.rotate(provider, provider.randomBytes(32), founder)

        val recipients = org.layeredencryption.membership.WrappedKeys.recipientsOf(
            Suite1, rotated.entries.last().wrappedKeys!!,
        )
        assertEquals(
            setOf(founder.identity, member.identity).map { it.signingPublicKey.toHexString() }.toSet(),
            recipients.toSet(),
        )
        assertTrue(attacker.identity.signingPublicKey.toHexString() !in recipients)
    }

    @Test
    fun aVerifiedLogStillMutatesNormally() {
        // The gate must not cost honest callers anything: a log parsed from trusted storage
        // verifies and then rotates, and the result verifies again.
        val honest = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
            .append(provider, MembershipOp.ADD, member.identity, wrappedKeys = null, signer = founder.signingKeyPair)
        val reparsed = MembershipLog.deserialise(honest.serialise())
        assertIs<MembershipVerification.Valid>(reparsed.verify(provider))

        val rotated = reparsed.rotate(provider, provider.randomBytes(32), founder)
        assertIs<MembershipVerification.Valid>(rotated.verify(provider))
    }
}
