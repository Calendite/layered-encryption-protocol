package org.layeredencryption.suite

import org.layeredencryption.Cascade
import org.layeredencryption.CryptoProvider
import org.layeredencryption.HybridSignature
import org.layeredencryption.KemEncapsulation
import org.layeredencryption.KeyPair
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.XWing

/**
 * Suite 1 — `LEP_HYBRID_2026`: exactly the construction and encodings shipped today, frozen
 * (docs/POST_QUANTUM_HARDENING_AND_MIGRATION.md, "Suite 1: freeze the current protocol").
 *
 * - **KEM**: X-Wing (draft-connolly-cfrg-xwing-kem-10) — X25519 + ML-KEM-768, SHA3-256 combiner,
 *   1216-byte public keys, 1120-byte ciphertexts, 32-byte seed secrets.
 * - **Signatures**: hybrid Ed25519 + ML-DSA-65, classical leg first, both legs required to
 *   verify — 1984-byte public keys, 3373-byte signatures.
 * - **Payload encryption**: ChaCha20-Poly1305 (inner) then AES-256-GCM (outer), independent
 *   HKDF-SHA256 layer keys, `n1 ‖ n2 ‖ ciphertext` blobs.
 * - **KDFs, hashes, encodings, size limits, and every `ProtocolLabels` string** as currently
 *   shipped.
 *
 * This object is **pure delegation** to [XWing], [HybridSignature], and [Cascade] — those
 * facades *are* Suite 1's implementation, and their output is pinned byte for byte by the
 * `Suite1Fixtures` compatibility tests. Do not "fix", extend, or re-tune anything reachable from
 * here: a change that alters bytes or cryptographic meaning is a different suite and must be
 * registered under a new [SuiteId], never edited into this one.
 */
object Suite1 : ProtocolSuite {

    override val id: SuiteId = SuiteId.LEP_HYBRID_2026
    override val name: String = "LEP_HYBRID_2026"

    override val kem: SuiteKem = object : SuiteKem {
        override val publicKeySize: Int get() = XWing.PUBLIC_KEY_SIZE
        override val ciphertextSize: Int get() = XWing.CIPHERTEXT_SIZE
        override val secretKeySize: Int get() = XWing.SECRET_KEY_SIZE

        override fun generateKeyPair(provider: CryptoProvider): KeyPair =
            XWing.generateKeyPair(provider)

        override fun keyPairFromSeed(provider: CryptoProvider, seed: ByteArray): KeyPair =
            XWing.keyPairFromSeed(provider, seed)

        override fun encapsulate(provider: CryptoProvider, peerPublicKey: ByteArray): KemEncapsulation =
            XWing.encapsulate(provider, peerPublicKey)

        override fun decapsulate(provider: CryptoProvider, secretKey: ByteArray, ciphertext: ByteArray): ByteArray =
            XWing.decapsulate(provider, secretKey, ciphertext)

        override fun x25519PublicComponent(publicKey: ByteArray): ByteArray =
            XWing.x25519PublicComponent(publicKey)

        override fun x25519SecretComponent(provider: CryptoProvider, secretKey: ByteArray): ByteArray =
            XWing.x25519SecretComponent(provider, secretKey)
    }

    override val signature: SuiteSignature = object : SuiteSignature {
        override val publicKeySize: Int get() = HybridSignature.PUBLIC_KEY_SIZE
        override val signatureSize: Int get() = HybridSignature.SIGNATURE_SIZE

        override fun generateKeyPair(provider: CryptoProvider): KeyPair =
            HybridSignature.generateKeyPair(provider)

        override fun sign(provider: CryptoProvider, privateKey: ByteArray, message: ByteArray): ByteArray =
            HybridSignature.sign(provider, privateKey, message)

        override fun verify(provider: CryptoProvider, publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
            HybridSignature.verify(provider, publicKey, message, signature)

        override fun classicalPublic(publicKey: ByteArray): ByteArray =
            HybridSignature.classicalPublic(publicKey)

        override fun postQuantumPublic(publicKey: ByteArray): ByteArray =
            HybridSignature.postQuantumPublic(publicKey)
    }

    override val aead: SuiteAead = object : SuiteAead {
        override fun seal(
            provider: CryptoProvider,
            masterKey: ByteArray,
            plaintext: ByteArray,
            aad: ByteArray,
            namespace: ProtocolNamespace,
        ): ByteArray = Cascade.seal(provider, masterKey, plaintext, aad, namespace)

        override fun open(
            provider: CryptoProvider,
            masterKey: ByteArray,
            blob: ByteArray,
            aad: ByteArray,
            namespace: ProtocolNamespace,
        ): ByteArray = Cascade.open(provider, masterKey, blob, aad, namespace)
    }
}
