package org.layeredencryption

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The hybrid signature's whole value rests on one property: **both** legs must verify. A version
 * that checked only the classical leg, or that fell back to it when the post-quantum leg was
 * missing, would pass a naive round-trip test while offering nothing against a quantum adversary.
 * Most of what follows therefore attacks one leg at a time.
 */
class HybridSignatureTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()
    private val message = "the bytes that get signed".encodeToByteArray()

    @Test
    fun `sizes match FIPS 204 for ML-DSA-65`() {
        val keys = HybridSignature.generateKeyPair(provider)
        val signature = HybridSignature.sign(provider, keys.privateKey, message)

        assertEquals(1984, keys.publicKey.size, "32 B Ed25519 + 1952 B ML-DSA-65")
        assertEquals(3373, signature.size, "64 B Ed25519 + 3309 B ML-DSA-65")
        assertEquals(HybridSignature.PUBLIC_KEY_SIZE, keys.publicKey.size)
        assertEquals(HybridSignature.SIGNATURE_SIZE, signature.size)
    }

    @Test
    fun `a genuine signature verifies`() {
        val keys = HybridSignature.generateKeyPair(provider)
        val signature = HybridSignature.sign(provider, keys.privateKey, message)

        assertTrue(HybridSignature.verify(provider, keys.publicKey, message, signature))
    }

    @Test
    fun `breaking only the classical leg is still rejected`() {
        val keys = HybridSignature.generateKeyPair(provider)
        val signature = HybridSignature.sign(provider, keys.privateKey, message)

        val tampered = signature.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()

        assertFalse(
            HybridSignature.verify(provider, keys.publicKey, message, tampered),
            "an intact ML-DSA leg must not rescue a broken Ed25519 leg",
        )
    }

    @Test
    fun `breaking only the post-quantum leg is still rejected`() {
        val keys = HybridSignature.generateKeyPair(provider)
        val signature = HybridSignature.sign(provider, keys.privateKey, message)

        val tampered = signature.copyOf()
        val postQuantumStart = HybridSignature.ED25519_SIGNATURE_SIZE
        tampered[postQuantumStart] = (tampered[postQuantumStart].toInt() xor 0x01).toByte()

        assertFalse(
            HybridSignature.verify(provider, keys.publicKey, message, tampered),
            "an intact Ed25519 leg must not rescue a broken ML-DSA leg",
        )
    }

    /**
     * The attack a quantum adversary would actually mount: forge the classical leg (assume it is
     * broken) and keep a post-quantum leg from a signature it once saw. Verification must fail
     * because the two legs come from different keys.
     */
    @Test
    fun `legs from different keys cannot be mixed`() {
        val honest = HybridSignature.generateKeyPair(provider)
        val attacker = HybridSignature.generateKeyPair(provider)

        val honestSignature = HybridSignature.sign(provider, honest.privateKey, message)
        val attackerSignature = HybridSignature.sign(provider, attacker.privateKey, message)

        val spliced = attackerSignature.copyOfRange(0, HybridSignature.ED25519_SIGNATURE_SIZE) +
            honestSignature.copyOfRange(HybridSignature.ED25519_SIGNATURE_SIZE, honestSignature.size)

        assertFalse(HybridSignature.verify(provider, attacker.publicKey, message, spliced))
        assertFalse(HybridSignature.verify(provider, honest.publicKey, message, spliced))
    }

    @Test
    fun `a different message is rejected`() {
        val keys = HybridSignature.generateKeyPair(provider)
        val signature = HybridSignature.sign(provider, keys.privateKey, message)

        assertFalse(HybridSignature.verify(provider, keys.publicKey, "other bytes".encodeToByteArray(), signature))
    }

    @Test
    fun `malformed lengths are rejected rather than thrown`() {
        val keys = HybridSignature.generateKeyPair(provider)
        val signature = HybridSignature.sign(provider, keys.privateKey, message)

        assertFalse(HybridSignature.verify(provider, keys.publicKey.copyOf(32), message, signature))
        assertFalse(HybridSignature.verify(provider, keys.publicKey, message, signature.copyOf(64)))
        assertFalse(HybridSignature.verify(provider, keys.publicKey, message, ByteArray(0)))
    }

    /** A signature truncated to exactly its classical leg must not be read as a valid Ed25519-only one. */
    @Test
    fun `stripping the post-quantum leg entirely is rejected`() {
        val keys = HybridSignature.generateKeyPair(provider)
        val signature = HybridSignature.sign(provider, keys.privateKey, message)
        val classicalOnly = signature.copyOfRange(0, HybridSignature.ED25519_SIGNATURE_SIZE)

        assertTrue(
            provider.ed25519Verify(HybridSignature.classicalPublic(keys.publicKey), message, classicalOnly),
            "the classical leg alone genuinely is a valid Ed25519 signature, which is what makes this the risk",
        )
        assertFalse(
            HybridSignature.verify(provider, keys.publicKey, message, classicalOnly),
            "a downgrade to the classical leg must be refused",
        )
    }
}
