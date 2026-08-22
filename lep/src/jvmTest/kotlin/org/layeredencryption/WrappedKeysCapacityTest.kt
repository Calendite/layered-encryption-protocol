package org.layeredencryption

import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.membership.WrappedKeys
import org.layeredencryption.suite.FakeSuites
import org.layeredencryption.suite.ProtocolSuite
import org.layeredencryption.suite.Suite1
import org.layeredencryption.suite.SuiteAead
import org.layeredencryption.suite.SuiteId
import org.layeredencryption.suite.SuiteKem
import org.layeredencryption.suite.SuiteSignature
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Capacity is bounded on both sides (LEP-R4): a wrapped-keys blob can never be built larger than
 * its own parser accepts, and a context can never grow past the point where one rotation could
 * wrap for everyone left.
 *
 * The failure this prevents is an availability trap with security consequences: at 204 members a
 * single revocation would need 203 recipient copies — 1,053,164 bytes against a 1,048,576-byte
 * budget — so the group could no longer eject a compromised device.
 */
class WrappedKeysCapacityTest {

    private val provider = BouncyCastleCryptoProvider()

    /** Counts encapsulations, so "rejected before cryptography" is measurable rather than asserted. */
    private class CountingProvider(private val delegate: CryptoProvider) : CryptoProvider by delegate {
        var encapsulations = 0
            private set

        override fun mlKem768Encapsulate(publicKey: ByteArray): KemEncapsulation {
            encapsulations++
            return delegate.mlKem768Encapsulate(publicKey)
        }
    }

    // ── The arithmetic ────────────────────────────────────────────────────────────────────────

    @Test
    fun suite1CapacityIsTheDocumentedBoundary() {
        // 4+3968 (member id hex) + 4+1120 (KEM ciphertext) + 4+88 (sealed copy) = 5188.
        assertEquals(5188, WrappedKeys.copyBytes(Suite1))
        assertEquals(202, WrappedKeys.maxRecipients(Suite1))
        // The membership cap must leave a wide margin under it, or revocation could be blocked.
        assertTrue(
            ProtocolLimits.MAX_ACTIVE_MEMBERS < WrappedKeys.maxRecipients(Suite1),
            "the member cap must fit inside one wrapped blob for every supported suite",
        )
    }

    @Test
    fun capacityFollowsTheSuitesOwnSizes() {
        // A suite with larger fields must yield a smaller capacity — the number is derived, not
        // copied from Suite 1.
        val wide = suiteWith(signaturePublicKeySize = 4096, kemCiphertextSize = 4096, sealedOverhead = 64)
        assertTrue(WrappedKeys.maxRecipients(wide) < WrappedKeys.maxRecipients(Suite1))
        assertEquals(ProtocolLimits.MAX_WRAPPED_KEYS_BYTES / WrappedKeys.copyBytes(wide), WrappedKeys.maxRecipients(wide))
    }

    @Test
    fun pathologicalSuiteSizesCannotOverflowOrDivideByZero() {
        assertFailsWith<IllegalArgumentException>("zero-size signature key") {
            WrappedKeys.copyBytes(suiteWith(signaturePublicKeySize = 0))
        }
        assertFailsWith<IllegalArgumentException>("negative ciphertext") {
            WrappedKeys.copyBytes(suiteWith(kemCiphertextSize = -1))
        }
        assertFailsWith<IllegalArgumentException>("overflowing total") {
            WrappedKeys.copyBytes(suiteWith(signaturePublicKeySize = Int.MAX_VALUE, kemCiphertextSize = Int.MAX_VALUE))
        }
    }

    // ── The encoder's preflight ───────────────────────────────────────────────────────────────

    @Test
    fun theMaximumNumberOfRecipientsRoundTrips() {
        // Building 202 real identities is far too slow; the boundary is exercised with synthetic
        // identities, which is enough because wrapFor's limit is structural, not cryptographic.
        val recipients = List(WrappedKeys.maxRecipients(Suite1)) { syntheticIdentity(it) }
        val blob = WrappedKeys.wrapFor(provider, Suite1, recipients, provider.randomBytes(32))

        assertTrue(blob.size <= ProtocolLimits.MAX_WRAPPED_KEYS_BYTES, "the maximum must fit its own budget")
        assertEquals(recipients.size, WrappedKeys.recipientsOf(Suite1, blob).size, "and parse back")
    }

    @Test
    fun oneRecipientTooManyIsRefusedBeforeAnyKemWork() {
        val counting = CountingProvider(provider)
        val recipients = List(WrappedKeys.maxRecipients(Suite1) + 1) { syntheticIdentity(it) }

        val failure = assertFailsWith<IllegalArgumentException> {
            WrappedKeys.wrapFor(counting, Suite1, recipients, provider.randomBytes(32))
        }
        assertTrue("at most 202" in failure.message.orEmpty(), failure.message.orEmpty())
        assertEquals(0, counting.encapsulations, "an impossible output must cost no cryptography")
    }

    // ── The membership cap ────────────────────────────────────────────────────────────────────

    @Test
    fun aContextCannotGrowPastTheMemberCap() {
        // Real identities: the cap is checked during authorisation, which runs *after* the
        // identity binding, so synthetic keys would be rejected for the wrong reason.
        val founder = DeviceKeys.generate(provider)
        var log = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
        repeat(ProtocolLimits.MAX_ACTIVE_MEMBERS - 1) {
            log = log.append(
                provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity, wrappedKeys = null,
                signer = founder.signingKeyPair,
            )
        }
        assertIs<MembershipVerification.Valid>(log.verify(provider), "a context exactly at the cap is legal")

        val overfull = log.append(
            provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity, wrappedKeys = null,
            signer = founder.signingKeyPair,
        )
        val verification = overfull.verify(provider)
        assertIs<MembershipVerification.Invalid>(verification)
        assertTrue("at most ${ProtocolLimits.MAX_ACTIVE_MEMBERS}" in verification.reason, verification.reason)
    }

    @Test
    fun aHostileIdentityMakesVerificationReturnInvalidRatherThanThrow() {
        // A relay-supplied log can carry correctly-sized but cryptographically invalid identity
        // bytes. Verification is documented to *return* Invalid; a provider that raises on a
        // bad public key must not turn that into an exception in the caller's handler.
        val founder = DeviceKeys.generate(provider)
        val log = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
            .append(provider, MembershipOp.ADD, syntheticIdentity(1), wrappedKeys = null, signer = founder.signingKeyPair)

        val verification = MembershipLog.deserialise(log.serialise()).verify(provider)
        assertIs<MembershipVerification.Invalid>(verification)
        assertEquals("Invalid device-identity binding", verification.reason)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────

    /**
     * A structurally valid identity with distinct keys. Its binding does not verify, which is
     * irrelevant here: every rule under test is a size/count rule enforced before any signature
     * is checked, and generating hundreds of real hybrid identities would dominate the runtime.
     */
    private fun syntheticIdentity(index: Int): DeviceIdentity {
        fun filled(size: Int, seed: Int) = ByteArray(size) { ((it + seed) % 251).toByte() }
        return DeviceIdentity(
            suiteId = SuiteId.LEP_HYBRID_2026,
            signingPublicKey = filled(HybridSignature.PUBLIC_KEY_SIZE, index + 1),
            x25519IdentityPublicKey = filled(32, index + 2),
            xWingPublicKey = XWing.generateKeyPair(provider).publicKey,
            bindingSignature = filled(HybridSignature.SIGNATURE_SIZE, index + 3),
        )
    }

    private fun suiteWith(
        signaturePublicKeySize: Int = HybridSignature.PUBLIC_KEY_SIZE,
        kemCiphertextSize: Int = XWing.CIPHERTEXT_SIZE,
        sealedOverhead: Int = 56,
    ): ProtocolSuite = object : ProtocolSuite {
        override val id = SuiteId(0xFF02u)
        override val name = "TEST_SIZES"
        override val strength = 1
        override val kem: SuiteKem = object : SuiteKem by Suite1.kem {
            override val ciphertextSize get() = kemCiphertextSize
        }
        override val signature: SuiteSignature = object : SuiteSignature by Suite1.signature {
            override val publicKeySize get() = signaturePublicKeySize
        }
        override val aead: SuiteAead = object : SuiteAead by Suite1.aead {
            override fun sealedSize(plaintextSize: Int) = plaintextSize + sealedOverhead
        }
    }
}
