package org.layeredencryption.suite

import org.layeredencryption.Cascade
import org.layeredencryption.CryptoProvider
import org.layeredencryption.HybridSignature
import org.layeredencryption.XWing
import org.layeredencryption.platformCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The suite layer's own freeze and fail-closed contracts: Suite 1 is registered under id 1 and
 * behaves byte-identically to the facades it delegates to; every other id is refused loudly.
 */
class SuiteRegistryTest {

    private val provider: CryptoProvider? = runCatching { platformCryptoProvider() }.getOrNull()

    @Test
    fun suite1_isRegisteredUnderItsFrozenIdentity() {
        val suite = SuiteRegistry.require(SuiteId.LEP_HYBRID_2026)
        assertSame(Suite1, suite)
        assertEquals(1u.toUShort(), suite.id.value, "Suite 1's id is frozen; renumbering is a protocol break")
        assertEquals("LEP_HYBRID_2026", suite.name)
        assertTrue(SuiteRegistry.contains(SuiteId.LEP_HYBRID_2026))
        assertEquals(setOf(SuiteId.LEP_HYBRID_2026), SuiteRegistry.known)
    }

    @Test
    fun unknownSuiteIds_failClosed() {
        for (value in listOf<UShort>(0u, 2u, 3u, 255u, 0xFFFFu)) {
            val exception = assertFailsWith<UnsupportedSuiteException>("id $value must be refused") {
                SuiteRegistry.require(SuiteId(value))
            }
            assertEquals(SuiteId(value), exception.id)
            assertFalse(SuiteRegistry.contains(SuiteId(value)))
        }
    }

    @Test
    fun suite1Sizes_equalTheFacadeConstants() {
        assertEquals(XWing.PUBLIC_KEY_SIZE, Suite1.kem.publicKeySize)
        assertEquals(XWing.CIPHERTEXT_SIZE, Suite1.kem.ciphertextSize)
        assertEquals(XWing.SECRET_KEY_SIZE, Suite1.kem.secretKeySize)
        assertEquals(HybridSignature.PUBLIC_KEY_SIZE, Suite1.signature.publicKeySize)
        assertEquals(HybridSignature.SIGNATURE_SIZE, Suite1.signature.signatureSize)
    }

    @Test
    fun suite1KeyAndSigningOperations_matchTheFacades() {
        val provider = provider ?: return
        val seed = ByteArray(32) { it.toByte() }

        val fromSuite = Suite1.kem.keyPairFromSeed(provider, seed)
        val fromFacade = XWing.keyPairFromSeed(provider, seed)
        assertContentEquals(fromFacade.publicKey, fromSuite.publicKey)
        assertContentEquals(fromFacade.privateKey, fromSuite.privateKey)
        assertContentEquals(
            XWing.x25519PublicComponent(fromFacade.publicKey),
            Suite1.kem.x25519PublicComponent(fromSuite.publicKey),
        )
        assertContentEquals(
            XWing.x25519SecretComponent(provider, seed),
            Suite1.kem.x25519SecretComponent(provider, seed),
        )

        val signing = Suite1.signature.generateKeyPair(provider)
        val message = "suite equivalence".encodeToByteArray()
        // Cross-verified rather than byte-compared: ML-DSA-65 signing is hedged (randomised) on
        // some providers (Noble) and deterministic on others (Bouncy Castle), so two signings of
        // the same message need not match. Byte-exact reproduction is pinned on the JVM reference
        // provider by Suite1ReproductionTest; here the contract is interchangeability.
        val suiteSignature = Suite1.signature.sign(provider, signing.privateKey, message)
        assertTrue(HybridSignature.verify(provider, signing.publicKey, message, suiteSignature))
        val facadeSignature = HybridSignature.sign(provider, signing.privateKey, message)
        assertTrue(Suite1.signature.verify(provider, signing.publicKey, message, facadeSignature))
        assertContentEquals(
            HybridSignature.classicalPublic(signing.publicKey),
            Suite1.signature.classicalPublic(signing.publicKey),
        )
        assertContentEquals(
            HybridSignature.postQuantumPublic(signing.publicKey),
            Suite1.signature.postQuantumPublic(signing.publicKey),
        )
    }

    @Test
    fun suite1RandomisedOperations_interoperateWithTheFacades() {
        val provider = provider ?: return

        // KEM: what the suite encapsulates, the facade decapsulates — and vice versa.
        val keyPair = XWing.generateKeyPair(provider)
        val fromSuite = Suite1.kem.encapsulate(provider, keyPair.publicKey)
        assertContentEquals(
            fromSuite.sharedSecret,
            XWing.decapsulate(provider, keyPair.privateKey, fromSuite.ciphertext),
        )
        val fromFacade = XWing.encapsulate(provider, keyPair.publicKey)
        assertContentEquals(
            fromFacade.sharedSecret,
            Suite1.kem.decapsulate(provider, keyPair.privateKey, fromFacade.ciphertext),
        )

        // AEAD: what the suite seals, the facade opens — and vice versa, AAD included.
        val masterKey = provider.randomBytes(32)
        val aad = "suite aad".encodeToByteArray()
        val plaintext = "cascade equivalence".encodeToByteArray()
        assertContentEquals(
            plaintext,
            Cascade.open(provider, masterKey, Suite1.aead.seal(provider, masterKey, plaintext, aad), aad),
        )
        assertContentEquals(
            plaintext,
            Suite1.aead.open(provider, masterKey, Cascade.seal(provider, masterKey, plaintext, aad), aad),
        )
    }
}
