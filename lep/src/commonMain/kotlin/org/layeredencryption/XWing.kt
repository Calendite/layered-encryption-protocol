package org.layeredencryption

/**
 * Hybrid X25519 + ML-KEM-768 key agreement following the **X-Wing** construction
 * (docs/Protocol.md §4.3).
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
 * ### What we own vs. what we transcribe
 * The security-critical [combiner] is transcribed **verbatim** from the IETF X-Wing spec — SHA3-256
 * over a fixed 6-byte label and the concatenated secrets/ciphertext/public-key. We do **not** design
 * a combiner: a naïve `HKDF(ss1 ‖ ss2)` fails to bind the public keys and ciphertexts, opening
 * identity-misbinding and re-encapsulation attacks (§4.3). The combiner is pinned to the IETF test
 * vectors in CI.
 *
 * ### Key/ciphertext encoding
 * The public key, ciphertext, and secret key are serialised as fixed concatenations of the two
 * legs (below). This encoding is Calendite-internal and shared by every platform actual, so all our
 * implementations interoperate. It is **not** the IETF seed-expanded key encoding — matching the
 * IETF *key-encoding* vectors (as opposed to the combiner vectors) is tracked as remaining CI work.
 *
 * - public key  = `mlkem_pk(1184) ‖ x25519_pk(32)`
 * - ciphertext  = `mlkem_ct(1088) ‖ x25519_ephemeral_pk(32)`
 * - secret key  = `mlkem_sk(var) ‖ x25519_sk(32) ‖ x25519_pk(32)`  (fixed-length tail, split from the back)
 */
object XWing {

    /** The X-Wing combiner label: the 6 ASCII bytes `\.//^\` (§4.3, IETF X-Wing). */
    private val COMBINER_LABEL = byteArrayOf(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c)

    private const val X25519_KEY_SIZE = 32
    private const val MLKEM768_PUBLIC_SIZE = 1184
    private const val MLKEM768_CIPHERTEXT_SIZE = 1088

    /** Serialised ciphertext size: `mlkem_ct(1088) ‖ x25519_ephemeral_pk(32)`. */
    const val CIPHERTEXT_SIZE = MLKEM768_CIPHERTEXT_SIZE + X25519_KEY_SIZE

    /** Serialised public-key size: `mlkem_pk(1184) ‖ x25519_pk(32)`. */
    const val PUBLIC_KEY_SIZE = MLKEM768_PUBLIC_SIZE + X25519_KEY_SIZE

    /**
     * The X25519 public component of an X-Wing public key — used by the async invite as the
     * inviter's "signed prekey" for the `dh1` identity binding (Async_Invites_Spec.md §2.5).
     * Pure accessor over the fixed serialisation; no combiner or layout change.
     */
    fun x25519PublicComponent(publicKey: ByteArray): ByteArray {
        require(publicKey.size == MLKEM768_PUBLIC_SIZE + X25519_KEY_SIZE) { "Not an X-Wing public key" }
        return publicKey.copyOfRange(MLKEM768_PUBLIC_SIZE, publicKey.size)
    }

    /** The X25519 secret component of an X-Wing secret key (the middle 32-byte field). */
    fun x25519SecretComponent(secretKey: ByteArray): ByteArray {
        require(secretKey.size > X25519_KEY_SIZE * 2) { "X-Wing secret key too short" }
        val pkStart = secretKey.size - X25519_KEY_SIZE
        return secretKey.copyOfRange(pkStart - X25519_KEY_SIZE, pkStart)
    }

    /** Generates an X-Wing keypair by generating each leg independently and concatenating. */
    fun generateKeyPair(provider: CryptoProvider): KeyPair {
        val mlkem = provider.mlKem768GenerateKeyPair()
        val x25519 = provider.x25519GenerateKeyPair()

        val publicKey = mlkem.publicKey + x25519.publicKey
        val secretKey = mlkem.privateKey + x25519.privateKey + x25519.publicKey
        return KeyPair(publicKey = publicKey, privateKey = secretKey)
    }

    /**
     * Encapsulates against a peer's X-Wing public key, producing the ciphertext to transmit and the
     * shared secret to keep. Both legs run, then the [combiner] binds them together.
     */
    fun encapsulate(provider: CryptoProvider, peerPublicKey: ByteArray): KemEncapsulation {
        val (mlkemPk, x25519Pk) = splitPublicKey(peerPublicKey)

        val mlkem = provider.mlKem768Encapsulate(mlkemPk)
        val ephemeral = provider.x25519GenerateKeyPair()
        val x25519Shared = provider.x25519(ephemeral.privateKey, x25519Pk)

        val sharedSecret = combiner(
            provider = provider,
            mlkemShared = mlkem.sharedSecret,
            x25519Shared = x25519Shared,
            x25519Ciphertext = ephemeral.publicKey,
            x25519PublicKey = x25519Pk,
        )
        val ciphertext = mlkem.ciphertext + ephemeral.publicKey
        return KemEncapsulation(ciphertext = ciphertext, sharedSecret = sharedSecret)
    }

    /** Decapsulates a ciphertext with our X-Wing secret key, recovering the same shared secret. */
    fun decapsulate(provider: CryptoProvider, secretKey: ByteArray, ciphertext: ByteArray): ByteArray {
        val (mlkemSk, x25519Sk, x25519Pk) = splitSecretKey(secretKey)
        val (mlkemCt, x25519Ct) = splitCiphertext(ciphertext)

        val mlkemShared = provider.mlKem768Decapsulate(mlkemSk, mlkemCt)
        val x25519Shared = provider.x25519(x25519Sk, x25519Ct)

        return combiner(
            provider = provider,
            mlkemShared = mlkemShared,
            x25519Shared = x25519Shared,
            x25519Ciphertext = x25519Ct,
            x25519PublicKey = x25519Pk,
        )
    }

    /**
     * The X-Wing combiner (§4.3):
     * `SHA3-256(label ‖ ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519)`.
     * Transcribed from the IETF spec; no design latitude.
     */
    private fun combiner(
        provider: CryptoProvider,
        mlkemShared: ByteArray,
        x25519Shared: ByteArray,
        x25519Ciphertext: ByteArray,
        x25519PublicKey: ByteArray,
    ): ByteArray = provider.sha3_256(
        COMBINER_LABEL + mlkemShared + x25519Shared + x25519Ciphertext + x25519PublicKey
    )

    private fun splitPublicKey(publicKey: ByteArray): Pair<ByteArray, ByteArray> {
        val expected = MLKEM768_PUBLIC_SIZE + X25519_KEY_SIZE
        require(publicKey.size == expected) { "X-Wing public key must be $expected bytes, was ${publicKey.size}" }
        val mlkemPk = publicKey.copyOfRange(0, MLKEM768_PUBLIC_SIZE)
        val x25519Pk = publicKey.copyOfRange(MLKEM768_PUBLIC_SIZE, expected)
        return mlkemPk to x25519Pk
    }

    private fun splitCiphertext(ciphertext: ByteArray): Pair<ByteArray, ByteArray> {
        val expected = MLKEM768_CIPHERTEXT_SIZE + X25519_KEY_SIZE
        require(ciphertext.size == expected) { "X-Wing ciphertext must be $expected bytes, was ${ciphertext.size}" }
        val mlkemCt = ciphertext.copyOfRange(0, MLKEM768_CIPHERTEXT_SIZE)
        val x25519Ct = ciphertext.copyOfRange(MLKEM768_CIPHERTEXT_SIZE, expected)
        return mlkemCt to x25519Ct
    }

    /** The two fixed-length X25519 fields sit at the tail, so the variable ML-KEM key is the prefix. */
    private fun splitSecretKey(secretKey: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val tail = X25519_KEY_SIZE * 2
        require(secretKey.size > tail) { "X-Wing secret key too short: ${secretKey.size} bytes" }
        val mlkemSkEnd = secretKey.size - tail
        val mlkemSk = secretKey.copyOfRange(0, mlkemSkEnd)
        val x25519Sk = secretKey.copyOfRange(mlkemSkEnd, mlkemSkEnd + X25519_KEY_SIZE)
        val x25519Pk = secretKey.copyOfRange(mlkemSkEnd + X25519_KEY_SIZE, secretKey.size)
        return Triple(mlkemSk, x25519Sk, x25519Pk)
    }
}
