package org.layeredencryption.playground

import org.layeredencryption.BouncyCastleCryptoProvider
import org.layeredencryption.CryptoProvider
import org.layeredencryption.HybridSignature
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.LaneEnvelope
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Guards the one claim on the algorithms panel a reader cannot check for themselves: that
 * sending a message signs nothing.
 *
 * It is behavioural rather than a scan of the source, so adding a signature to the message path
 * fails this test even if nobody remembers the panel exists.
 */
class AlgorithmMapTest {

    @Test
    fun `sealing and opening a message never signs`() {
        val counter = SignCountingProvider(BouncyCastleCryptoProvider())
        val namespace = ProtocolNamespace("playground-test")
        val masterKey = ByteArray(32) { it.toByte() }
        val plaintext = "Dentist, Tuesday, 9am".encodeToByteArray()

        val envelope = LaneEnvelope.seal(
            counter, EpochKeys.founding(masterKey), "context", "device-00112233445566aa", 0, plaintext,
            namespace = namespace,
        )
        val opened = LaneEnvelope.deserialise(envelope.serialise()).open(counter, EpochKeys.founding(masterKey), namespace)

        assertContentEquals(plaintext, opened)
        assertEquals(0, counter.signatures, "the message path signed something")
        assertEquals(0, counter.verifications, "the message path verified a signature")
    }

    @Test
    fun `the panel says Ed25519 is not used per message`() {
        val ed25519 = ALGORITHM_MAP.single { it.name == "Ed25519" }
        assertTrue(
            ed25519.whenUsed.contains("never per message"),
            "the panel no longer states where Ed25519 does and does not work",
        )
    }

    /**
     * Signing is the one place a classical-only algorithm could sit unnoticed, because a
     * signature that verifies looks identical whether or not a post-quantum leg was involved.
     */
    @Test
    fun `every signature the protocol makes has a post-quantum leg`() {
        val provider = BouncyCastleCryptoProvider()
        val keys = HybridSignature.generateKeyPair(provider)
        val message = "identity, membership, invites".encodeToByteArray()
        val signature = HybridSignature.sign(provider, keys.privateKey, message)

        assertEquals(HybridSignature.SIGNATURE_SIZE, signature.size, "both legs must be present")
        assertTrue(ALGORITHM_MAP.single { it.name == "ML-DSA-65" }.postQuantum)
        assertTrue(
            HybridSignature.verify(provider, keys.publicKey, message, signature) &&
                !HybridSignature.verify(
                    provider, keys.publicKey, message,
                    signature.copyOfRange(0, HybridSignature.ED25519_SIGNATURE_SIZE),
                ),
            "the classical leg alone must not be accepted",
        )
    }

    @Test
    fun `every algorithm the message journey names appears on the panel`() {
        val named = setOf("HKDF-SHA256", "ChaCha20-Poly1305", "AES-256-GCM", "SHA-256")
        val onPanel = ALGORITHM_MAP.map { it.name }.toSet()
        assertTrue(onPanel.containsAll(named), "missing from the panel: ${named - onPanel}")
    }
}

private class SignCountingProvider(private val delegate: CryptoProvider) : CryptoProvider by delegate {
    var signatures = 0
        private set
    var verifications = 0
        private set

    override fun ed25519Sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        signatures++
        return delegate.ed25519Sign(privateKey, message)
    }

    override fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        verifications++
        return delegate.ed25519Verify(publicKey, message, signature)
    }

    override fun mlDsa65Sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        signatures++
        return delegate.mlDsa65Sign(privateKey, message)
    }

    override fun mlDsa65Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        verifications++
        return delegate.mlDsa65Verify(publicKey, message, signature)
    }
}
