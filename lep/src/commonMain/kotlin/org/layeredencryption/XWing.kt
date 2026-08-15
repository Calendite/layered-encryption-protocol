package org.layeredencryption

/**
 * Hybrid X25519 + ML-KEM-768 key agreement implementing **X-Wing**
 * (draft-connolly-cfrg-xwing-kem-10; docs/Protocol.md §4.3).
 *
 * ```
 * X25519 (classical)  ─┐
 *                      ├─ X-Wing combiner ──> shared secret ──> HKDF ──> keys
 * ML-KEM-768 (PQ)     ─┘
 * ```
 *
 * Requiring **both** legs to fall means an attacker needs to break X25519 (a future quantum
 * computer, via Shor) *and* ML-KEM (an implementation bug) simultaneously (§4.4). If the unaudited
 * ML-KEM leg fails, security degrades only to the audited classical X25519 baseline — never below.
 *
 * ### Standards status — be precise about what this is
 * X-Wing is a **work-in-progress Internet-Draft**, not an RFC or an endorsed IETF standard. This
 * file implements draft **-10** (2 March 2026) exactly — combiner, seed-based key generation, and
 * serialisation — and `XWingKatTest` pins it to the draft's Appendix C test vectors plus an
 * independent implementation (noble `ml_kem768_x25519`). Pre-release checklist item: re-verify
 * against the published RFC when the draft lands, since vectors have changed between draft
 * versions before.
 *
 * ### What we own vs. what we transcribe
 * The security-critical [combiner] is the draft's, byte for byte:
 * `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)` — the fixed 6-byte label comes **last**. We do
 * **not** design a combiner: a naïve `HKDF(ss1 ‖ ss2)` fails to bind the public keys and
 * ciphertexts, opening identity-misbinding and re-encapsulation attacks (§4.3). An earlier
 * version of this file hashed the label *first*, which was its own construction, not X-Wing;
 * the KATs exist so that class of drift breaks a test instead of shipping.
 *
 * ### Key generation and encoding (draft §5.2)
 * The decapsulation key is a **32-byte seed**. Everything else is derived:
 *
 * ```
 * expanded = SHAKE256(sk, 96)
 * (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
 * sk_X = expanded[64:96]
 * pk_X = X25519(sk_X, BASE)
 * ```
 *
 * - secret key  = 32-byte seed
 * - public key  = `mlkem_pk(1184) ‖ x25519_pk(32)` = 1216 B
 * - ciphertext  = `mlkem_ct(1088) ‖ x25519_ephemeral_pk(32)` = 1120 B
 *
 * Decapsulation re-expands the seed on every call — one SHAKE256 plus one deterministic ML-KEM
 * keygen, negligible at pairing/rotation frequency. Callers hold the seed as an opaque array.
 */
object XWing {

    /** The X-Wing combiner label: the 6 ASCII bytes `\.//^\`, hashed **last** (draft §5.3). */
    private val COMBINER_LABEL = byteArrayOf(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c)

    private const val X25519_KEY_SIZE = 32
    private const val MLKEM768_PUBLIC_SIZE = 1184
    private const val MLKEM768_CIPHERTEXT_SIZE = 1088

    /** The decapsulation key is the 32-byte seed (draft §5.2). */
    const val SECRET_KEY_SIZE = 32

    /** Serialised ciphertext size: `mlkem_ct(1088) ‖ x25519_ephemeral_pk(32)`. */
    const val CIPHERTEXT_SIZE = MLKEM768_CIPHERTEXT_SIZE + X25519_KEY_SIZE

    /** Serialised public-key size: `mlkem_pk(1184) ‖ x25519_pk(32)`. */
    const val PUBLIC_KEY_SIZE = MLKEM768_PUBLIC_SIZE + X25519_KEY_SIZE

    private const val EXPANDED_SIZE = 96

    /** The draft's `expandDecapsulationKey(sk)` (§5.2), materialised. */
    private class Expanded(val mlkem: KeyPair, val x25519Secret: ByteArray, val x25519Public: ByteArray)

    private fun expand(provider: CryptoProvider, secretKey: ByteArray): Expanded {
        require(secretKey.size == SECRET_KEY_SIZE) { "X-Wing secret key must be a $SECRET_KEY_SIZE-byte seed" }
        val expanded = provider.shake256(secretKey, EXPANDED_SIZE)
        val d = expanded.copyOfRange(0, 32)
        val z = expanded.copyOfRange(32, 64)
        val skX = expanded.copyOfRange(64, 96)
        try {
            return Expanded(
                mlkem = provider.mlKem768KeyPairFromSeed(d, z),
                x25519Secret = skX,
                x25519Public = provider.x25519PublicKey(skX),
            )
        } finally {
            // Everything here re-derives from the stored 32-byte seed on demand; no expansion
            // by-product should outlive the call (RT-05).
            expanded.fill(0)
            d.fill(0)
            z.fill(0)
        }
    }

    /**
     * The X25519 public component of an X-Wing public key — used by the async invite as the
     * inviter's "signed prekey" for the `dh1` identity binding (Async_Invites_Spec.md §2.5).
     * Pure accessor over the draft serialisation.
     */
    fun x25519PublicComponent(publicKey: ByteArray): ByteArray {
        require(publicKey.size == PUBLIC_KEY_SIZE) { "Not an X-Wing public key" }
        return publicKey.copyOfRange(MLKEM768_PUBLIC_SIZE, publicKey.size)
    }

    /** The X25519 secret component: `SHAKE256(seed, 96)[64:96]` (draft §5.2). */
    fun x25519SecretComponent(provider: CryptoProvider, secretKey: ByteArray): ByteArray {
        val expanded = expand(provider, secretKey)
        expanded.mlkem.privateKey.fill(0)
        return expanded.x25519Secret
    }

    /** Generates an X-Wing keypair: a fresh 32-byte seed, expanded per the draft (§5.2). */
    fun generateKeyPair(provider: CryptoProvider): KeyPair =
        keyPairFromSeed(provider, provider.randomBytes(SECRET_KEY_SIZE))

    /** The draft's `GenerateKeyPairDerand(sk)` (§5.2): the keypair a given 32-byte seed expands to. */
    fun keyPairFromSeed(provider: CryptoProvider, seed: ByteArray): KeyPair {
        val expanded = expand(provider, seed)
        expanded.mlkem.privateKey.fill(0)
        expanded.x25519Secret.fill(0)
        return KeyPair(
            publicKey = expanded.mlkem.publicKey + expanded.x25519Public,
            privateKey = seed.copyOf(),
        )
    }

    /**
     * Encapsulates against a peer's X-Wing public key (draft §5.4), producing the ciphertext to
     * transmit and the shared secret to keep. Both legs run, then the [combiner] binds them.
     *
     * Randomness is drawn in the draft's `eseed` order — the ML-KEM message first, the X25519
     * ephemeral second — so a deterministically-seeded provider reproduces `EncapsulateDerand`
     * exactly, which is what lets the KATs drive this very function with official vectors.
     */
    fun encapsulate(provider: CryptoProvider, peerPublicKey: ByteArray): KemEncapsulation {
        val (mlkemPk, x25519Pk) = splitPublicKey(peerPublicKey)

        val mlkem = provider.mlKem768Encapsulate(mlkemPk)
        val ephemeral = provider.x25519GenerateKeyPair()
        val x25519Shared = provider.x25519(ephemeral.privateKey, x25519Pk)

        val sharedSecret = try {
            combiner(
                provider = provider,
                mlkemShared = mlkem.sharedSecret,
                x25519Shared = x25519Shared,
                x25519Ciphertext = ephemeral.publicKey,
                x25519PublicKey = x25519Pk,
            )
        } finally {
            // Only the combined secret leaves this function; the component secrets and the
            // ephemeral private scalar must not wait for the garbage collector (RT-05).
            mlkem.sharedSecret.fill(0)
            x25519Shared.fill(0)
            ephemeral.privateKey.fill(0)
        }
        val ciphertext = mlkem.ciphertext + ephemeral.publicKey
        return KemEncapsulation(ciphertext = ciphertext, sharedSecret = sharedSecret)
    }

    /** Decapsulates a ciphertext with our 32-byte seed, recovering the same shared secret (draft §5.5). */
    fun decapsulate(provider: CryptoProvider, secretKey: ByteArray, ciphertext: ByteArray): ByteArray {
        val expanded = expand(provider, secretKey)
        val (mlkemCt, x25519Ct) = splitCiphertext(ciphertext)

        val mlkemShared = provider.mlKem768Decapsulate(expanded.mlkem.privateKey, mlkemCt)
        val x25519Shared = provider.x25519(expanded.x25519Secret, x25519Ct)

        try {
            return combiner(
                provider = provider,
                mlkemShared = mlkemShared,
                x25519Shared = x25519Shared,
                x25519Ciphertext = x25519Ct,
                x25519PublicKey = expanded.x25519Public,
            )
        } finally {
            mlkemShared.fill(0)
            x25519Shared.fill(0)
            expanded.mlkem.privateKey.fill(0)
            expanded.x25519Secret.fill(0)
        }
    }

    /**
     * The X-Wing combiner (draft §5.3):
     * `SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ label)`.
     * The label is **last**. Transcribed from the draft; no design latitude.
     */
    private fun combiner(
        provider: CryptoProvider,
        mlkemShared: ByteArray,
        x25519Shared: ByteArray,
        x25519Ciphertext: ByteArray,
        x25519PublicKey: ByteArray,
    ): ByteArray {
        val preimage = mlkemShared + x25519Shared + x25519Ciphertext + x25519PublicKey + COMBINER_LABEL
        try {
            return provider.sha3_256(preimage)
        } finally {
            preimage.fill(0)
        }
    }

    private fun splitPublicKey(publicKey: ByteArray): Pair<ByteArray, ByteArray> {
        require(publicKey.size == PUBLIC_KEY_SIZE) { "X-Wing public key must be $PUBLIC_KEY_SIZE bytes, was ${publicKey.size}" }
        val mlkemPk = publicKey.copyOfRange(0, MLKEM768_PUBLIC_SIZE)
        val x25519Pk = publicKey.copyOfRange(MLKEM768_PUBLIC_SIZE, PUBLIC_KEY_SIZE)
        return mlkemPk to x25519Pk
    }

    private fun splitCiphertext(ciphertext: ByteArray): Pair<ByteArray, ByteArray> {
        require(ciphertext.size == CIPHERTEXT_SIZE) { "X-Wing ciphertext must be $CIPHERTEXT_SIZE bytes, was ${ciphertext.size}" }
        val mlkemCt = ciphertext.copyOfRange(0, MLKEM768_CIPHERTEXT_SIZE)
        val x25519Ct = ciphertext.copyOfRange(MLKEM768_CIPHERTEXT_SIZE, CIPHERTEXT_SIZE)
        return mlkemCt to x25519Ct
    }
}
