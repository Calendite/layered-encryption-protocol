package org.layeredencryption

/**
 * Raw cryptographic primitives for the protocol, sourced per platform (docs/Protocol.md §5).
 *
 * This interface is deliberately a set of *thin primitives* — no protocol logic lives here. The
 * higher-level constructions that Calendite actually owns (the [Cascade] and the [XWing] combiner)
 * live in `commonMain` and are written *once*, against these primitives, so their behaviour is
 * identical on every platform (§4.3, §5.1). Each platform binds the primitives to audited code:
 *
 * | Primitive              | Android                     | iOS (deferred)        | Web/Wasm (deferred) |
 * |------------------------|-----------------------------|-----------------------|---------------------|
 * | ChaCha20-Poly1305      | JCA (Conscrypt/BoringSSL)   | CryptoKit ChaChaPoly  | libsodium.js        |
 * | AES-256-GCM            | JCA                         | CryptoKit AES.GCM     | WebCrypto           |
 * | X25519                 | Bouncy Castle / platform XDH | CryptoKit (in X-Wing) | WebCrypto           |
 * | ML-KEM-768             | Bouncy Castle ≥ 1.81        | CryptoKit (iOS 26+)   | Kodium (quarantined)|
 * | SHA3-256 / HKDF        | Bouncy Castle               | CryptoKit             | WebCrypto           |
 *
 * ### Fail-closed contract
 * All AEAD `open` operations MUST verify the authentication tag and throw [CryptoException] on any
 * failure — a rejected blob never returns partial or unauthenticated plaintext (§4.2).
 *
 * All byte arrays are raw, unframed key/ciphertext material. Sizes (in bytes):
 * - X25519 public/private key: 32
 * - ML-KEM-768 encapsulation key (public): 1184; ciphertext: 1088; shared secret: 32
 * - AEAD keys: 32; AEAD nonces: 12; AEAD tags: 16 (appended to ciphertext)
 */
interface CryptoProvider {

    /** Cryptographically secure random bytes from the platform CSPRNG (§5.1). */
    fun randomBytes(size: Int): ByteArray

    /** SHA3-256. Used by the X-Wing combiner (§4.3); a fixed-size 32-byte digest. */
    fun sha3_256(data: ByteArray): ByteArray

    /**
     * SHAKE256 (FIPS 202) extendable-output function, read to [outputLength] bytes.
     * Used by X-Wing's `expandDecapsulationKey` to expand the 32-byte seed into the ML-KEM and
     * X25519 components (draft-connolly-cfrg-xwing-kem-10 §5.2).
     */
    fun shake256(data: ByteArray, outputLength: Int): ByteArray

    /** SHA-256. Used for rendezvous ids and membership-log hash chaining (§6.3, §4.7). */
    fun sha256(data: ByteArray): ByteArray

    /** HMAC-SHA256. Backs the code-keyed transcript MAC in pairing authentication (§4.5). */
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray

    /**
     * HKDF-SHA256 (RFC 5869) extract-and-expand.
     *
     * @param salt optional salt; `null` means the all-zero salt block per RFC 5869.
     * @param length output key material length in bytes.
     */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray

    /**
     * ChaCha20-Poly1305 AEAD seal (RFC 8439). Returns ciphertext with the 16-byte tag appended.
     * This is the *inner* cascade layer (§4.2).
     */
    fun chaCha20Poly1305Seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray

    /** ChaCha20-Poly1305 AEAD open. Verifies the tag; throws [CryptoException] on failure. */
    fun chaCha20Poly1305Open(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray

    /**
     * AES-256-GCM AEAD seal. Returns ciphertext with the 16-byte tag appended.
     * This is the *outer* cascade layer (§4.2).
     */
    fun aes256GcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray

    /** AES-256-GCM AEAD open. Verifies the tag; throws [CryptoException] on failure. */
    fun aes256GcmOpen(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray

    /** Generates an ephemeral X25519 keypair (raw 32-byte public/private). */
    fun x25519GenerateKeyPair(): KeyPair

    /** X25519 Diffie-Hellman: returns the raw 32-byte shared secret for our private + peer public key. */
    fun x25519(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray

    /**
     * The X25519 public key for a given 32-byte scalar — scalar multiplication by the base point.
     * Needed where the private scalar comes out of a KDF rather than out of [x25519GenerateKeyPair]
     * (X-Wing seed expansion).
     */
    fun x25519PublicKey(privateKey: ByteArray): ByteArray

    /** Generates an ML-KEM-768 (FIPS 203) keypair. Public = encapsulation key; private = decapsulation key. */
    fun mlKem768GenerateKeyPair(): KeyPair

    /**
     * Deterministic ML-KEM-768 key generation from the FIPS 203 seeds — `KeyGen_internal(d, z)`,
     * both 32 bytes. Used by X-Wing seed expansion, where the same 32-byte X-Wing seed must
     * reproduce the same keypair on every call and every platform.
     */
    fun mlKem768KeyPairFromSeed(d: ByteArray, z: ByteArray): KeyPair

    /** ML-KEM-768 encapsulation against a peer's public (encapsulation) key. */
    fun mlKem768Encapsulate(peerPublicKey: ByteArray): KemEncapsulation

    /** ML-KEM-768 decapsulation: recovers the 32-byte shared secret from a ciphertext. */
    fun mlKem768Decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray

    /** Generates an Ed25519 device-identity keypair (raw 32-byte public/private) (§4.6). */
    fun ed25519GenerateKeyPair(): KeyPair

    /** Ed25519 signature over [message]; returns the 64-byte signature. */
    fun ed25519Sign(privateKey: ByteArray, message: ByteArray): ByteArray

    /** Ed25519 verification. Returns `true` iff [signature] is valid for [message] under [publicKey]. */
    fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean

    /**
     * Generates an ML-DSA-65 (FIPS 204) signing keypair — the post-quantum leg of [HybridSignature].
     *
     * ML-DSA-65 is NIST category 3, matching ML-KEM-768 on the agreement side, so neither half of
     * the protocol is the weak one.
     */
    fun mlDsa65GenerateKeyPair(): KeyPair

    /** ML-DSA-65 signature over [message]; returns the 3309-byte signature. */
    fun mlDsa65Sign(privateKey: ByteArray, message: ByteArray): ByteArray

    /** ML-DSA-65 verification. Returns `true` iff [signature] is valid for [message] under [publicKey]. */
    fun mlDsa65Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
}

/**
 * A raw asymmetric keypair. Encodings are provider-specific but round-trip within one provider.
 *
 * Deliberately a thin **mutable** carrier, unlike the protocol objects (which copy their arrays
 * both ways): every provider call allocates these on the hot path, their arrays are freshly
 * allocated and never shared on creation, and in-place mutability is what lets a holder zero its
 * own key material (the async invite scrubs its KEM seed this way). Protocol objects that accept
 * one copy out of it; do not hand the same [KeyPair] to two owners.
 */
class KeyPair(val publicKey: ByteArray, val privateKey: ByteArray)

/** The output of a KEM encapsulation: the ciphertext to send, and the shared secret to keep. Same mutable-carrier contract as [KeyPair]. */
class KemEncapsulation(val ciphertext: ByteArray, val sharedSecret: ByteArray)

/**
 * Thrown for every cryptographic failure that must fail closed — most importantly AEAD tag
 * verification (§4.2). Callers treat any [CryptoException] as "reject the blob", never as a
 * recoverable/partial result.
 */
class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Returns the platform-bound [CryptoProvider] (a cached singleton per platform). */
expect fun platformCryptoProvider(): CryptoProvider
