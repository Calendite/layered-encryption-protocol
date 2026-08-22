package org.layeredencryption

/**
 * The data-encryption cascade (docs/Protocol.md §4.2).
 *
 * ```
 * plaintext ── ChaCha20-Poly1305 (K1, n1) ── AES-256-GCM (K2, n2) ──> blob
 * ```
 *
 * ChaCha20 is the inner layer, AES-256-GCM the outer. The two keys are **independent**, each
 * derived from the master key by HKDF under a distinct domain-separation label — never the same
 * key twice. With independent keys a cascade is provably at least as strong as its strongest layer,
 * so reading the data requires breaking ChaCha20 **and** AES-256, or obtaining the keys (§4.2).
 *
 * On [open], both AEAD tags are verified — outer (AES) first, then inner (ChaCha20). If either tag
 * fails the blob is rejected with [CryptoException]; there is no path that returns unauthenticated
 * bytes (fail closed).
 *
 * The same [aad] must be supplied to [seal] and [open]; it is bound into both layers.
 */
object Cascade {

    /** Fresh 96-bit nonce per layer, per blob, from the platform CSPRNG (§4.2). */
    private const val NONCE_SIZE = 12
    private const val KEY_SIZE = 32

    /**
     * HKDF labels are pinned protocol constants (§4.6). Namespace normalised to `calendite` (brand
     * spelling) pre-ship; wire constant — frozen, never respell. They MUST be byte-identical across
     * every platform implementation for domain separation.
     */
    private const val SUFFIX_CHACHA = ProtocolLabels.LAYER_CHACHA
    private const val SUFFIX_AES = ProtocolLabels.LAYER_AES

    /**
     * Encrypts [plaintext] under the [masterKey]. The returned blob is `n1 ‖ n2 ‖ ciphertext`,
     * where the ciphertext is the doubly-sealed payload (ChaCha20 then AES-256-GCM).
     */
    fun seal(
        provider: CryptoProvider,
        masterKey: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray = EMPTY,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray {
        val (chachaKey, aesKey) = deriveLayerKeys(provider, masterKey, namespace)
        val innerNonce = provider.randomBytes(NONCE_SIZE)
        val outerNonce = provider.randomBytes(NONCE_SIZE)

        val inner = provider.chaCha20Poly1305Seal(chachaKey, innerNonce, plaintext, aad)
        val outer = provider.aes256GcmSeal(aesKey, outerNonce, inner, aad)

        return innerNonce + outerNonce + outer
    }

    /**
     * Decrypts a blob produced by [seal]. Verifies the outer (AES) tag first, then the inner
     * (ChaCha20) tag; either failure throws [CryptoException] and no plaintext is returned.
     */
    fun open(
        provider: CryptoProvider,
        masterKey: ByteArray,
        blob: ByteArray,
        aad: ByteArray = EMPTY,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray {
        if (blob.size < NONCE_SIZE * 2) {
            throw CryptoException("Cascade blob too short: ${blob.size} bytes")
        }
        val (chachaKey, aesKey) = deriveLayerKeys(provider, masterKey, namespace)
        val innerNonce = blob.copyOfRange(0, NONCE_SIZE)
        val outerNonce = blob.copyOfRange(NONCE_SIZE, NONCE_SIZE * 2)
        val outerCiphertext = blob.copyOfRange(NONCE_SIZE * 2, blob.size)

        val inner = provider.aes256GcmOpen(aesKey, outerNonce, outerCiphertext, aad)
        return provider.chaCha20Poly1305Open(chachaKey, innerNonce, inner, aad)
    }

    /**
     * Both layer keys, derived from an already-uniform 32-byte secret.
     *
     * The length is required, not merely expected (LEP-R13). HKDF is an *extract-and-expand*
     * function, not a password hash: hand it a short or low-entropy input — a passphrase
     * someone decided to use directly, a truncated restore, an empty placeholder — and it will
     * cheerfully produce two perfectly well-formed 32-byte layer keys carrying none of the
     * entropy this construction's security argument assumes. Every key that legitimately
     * reaches here (context keys, handshake and async keys, member wrap keys, at-rest store
     * keys) is already a uniform 32 bytes, so anything else is a caller error worth failing on.
     * Password-derived keys need a memory-hard KDF with explicit parameters and a salt, which
     * is a deliberate decision for the application to make, not one to stumble into here.
     */
    private fun deriveLayerKeys(
        provider: CryptoProvider,
        masterKey: ByteArray,
        namespace: ProtocolNamespace,
    ): Pair<ByteArray, ByteArray> {
        require(masterKey.size == KEY_SIZE) {
            "The cascade master key is exactly $KEY_SIZE uniform bytes, was ${masterKey.size}"
        }
        val chachaKey = provider.hkdfSha256(masterKey, salt = null, info = namespace.label(SUFFIX_CHACHA), length = KEY_SIZE)
        val aesKey = provider.hkdfSha256(masterKey, salt = null, info = namespace.label(SUFFIX_AES), length = KEY_SIZE)
        return chachaKey to aesKey
    }

    private val EMPTY = ByteArray(0)
}
