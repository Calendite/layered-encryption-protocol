package org.layeredencryption.suite

import org.layeredencryption.CryptoProvider
import org.layeredencryption.KemEncapsulation
import org.layeredencryption.KeyPair
import org.layeredencryption.ProtocolNamespace

/**
 * One complete, immutable cryptographic suite: the KEM, signature, and payload-encryption
 * constructions a protocol operation runs under, addressed by a stable [SuiteId]
 * (docs/POST_QUANTUM_HARDENING_AND_MIGRATION.md, "Recommended suite model").
 *
 * A suite is a *frozen bundle*, not a mix-and-match toolbox: every algorithm choice, byte
 * encoding, size, and domain-separation label inside it is fixed at assignment and never edited.
 * Corrections that change bytes or cryptographic meaning require a **new** suite id, so that
 * existing identities, signatures, membership histories, and ciphertext remain verifiable and
 * decryptable forever under the suite that produced them.
 *
 * The method shapes deliberately mirror the Suite 1 facades ([org.layeredencryption.XWing],
 * [org.layeredencryption.HybridSignature], [org.layeredencryption.Cascade]) signature for
 * signature, [CryptoProvider] threading included — Phase 0 routes existing call sites through
 * [Suite1] without changing a single argument or protocol byte. Generalising the shapes (and
 * binding the suite id into transcripts, KDF contexts, and associated data) is Phase 1 work,
 * because it changes bytes and belongs with the versioned wire formats that carry it.
 */
interface ProtocolSuite {
    val id: SuiteId

    /** A stable human-readable name for logs and diagnostics, e.g. `"LEP_HYBRID_2026"`. */
    val name: String

    /**
     * The suite's frozen strength rank, curator-assigned at registration and never edited —
     * anchored to the NIST security category of its weakest required component (Suite 1 = 1).
     *
     * Used ONLY by negotiation's "strongest mutually supported" selection. Deliberately not the
     * numeric [id]: ids are assigned chronologically, and a legitimate implementation-diversity
     * suite can arrive at the *same* strength with a higher id. Upgrade direction is likewise not
     * governed by strength — suite transitions are monotonic in [id] (see the migration brief).
     */
    val strength: Int

    val kem: SuiteKem
    val signature: SuiteSignature
    val aead: SuiteAead
}

/** The suite's key-encapsulation mechanism (Suite 1: X-Wing — X25519 + ML-KEM-768). */
interface SuiteKem {
    val publicKeySize: Int
    val ciphertextSize: Int
    val secretKeySize: Int

    fun generateKeyPair(provider: CryptoProvider): KeyPair
    fun keyPairFromSeed(provider: CryptoProvider, seed: ByteArray): KeyPair
    fun encapsulate(provider: CryptoProvider, peerPublicKey: ByteArray): KemEncapsulation
    fun decapsulate(provider: CryptoProvider, secretKey: ByteArray, ciphertext: ByteArray): ByteArray

    /**
     * The classical (X25519) component of a hybrid public key. Suite-1-shaped: a future suite
     * whose KEM composes differently gets its own accessor when Phase 1 generalises this.
     */
    fun x25519PublicComponent(publicKey: ByteArray): ByteArray

    /** The classical (X25519) secret expanded from a hybrid secret-key seed. Suite-1-shaped. */
    fun x25519SecretComponent(provider: CryptoProvider, secretKey: ByteArray): ByteArray
}

/** The suite's signature scheme (Suite 1: hybrid Ed25519 + ML-DSA-65, both legs required). */
interface SuiteSignature {
    val publicKeySize: Int
    val signatureSize: Int

    fun generateKeyPair(provider: CryptoProvider): KeyPair
    fun sign(provider: CryptoProvider, privateKey: ByteArray, message: ByteArray): ByteArray
    fun verify(provider: CryptoProvider, publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean

    /** The classical (Ed25519) half of a hybrid public key. Suite-1-shaped. */
    fun classicalPublic(publicKey: ByteArray): ByteArray

    /** The post-quantum (ML-DSA-65) half of a hybrid public key. Suite-1-shaped. */
    fun postQuantumPublic(publicKey: ByteArray): ByteArray
}

/**
 * The suite's authenticated payload encryption (Suite 1: the ChaCha20-Poly1305 → AES-256-GCM
 * cascade). Nonce handling is internal to the sealed blob; the same [aad] must be supplied to
 * [seal] and [open].
 */
interface SuiteAead {
    /**
     * The exact size of a sealed blob for a [plaintextSize]-byte plaintext. Every LEP AEAD
     * construction is deterministic in size (nonces + ciphertext + tags), which is what lets
     * fixed-width decoders — the wrapped-keys parser above all — validate a sealed field to a
     * single legal length instead of a range.
     */
    fun sealedSize(plaintextSize: Int): Int

    fun seal(
        provider: CryptoProvider,
        masterKey: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray = EMPTY_AAD,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray

    fun open(
        provider: CryptoProvider,
        masterKey: ByteArray,
        blob: ByteArray,
        aad: ByteArray = EMPTY_AAD,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray
}

/** Shared empty-AAD default, mirroring the Suite 1 facade defaults byte for byte. */
private val EMPTY_AAD = ByteArray(0)

/**
 * A [SuiteId] no registered suite answers to. Always thrown rather than guessed around: an
 * unknown suite in any parsed artifact means the artifact is from a future (or hostile) sender,
 * and the only safe behaviour is to fail closed.
 */
class UnsupportedSuiteException(val id: SuiteId) : IllegalArgumentException("Unsupported protocol suite: $id")
