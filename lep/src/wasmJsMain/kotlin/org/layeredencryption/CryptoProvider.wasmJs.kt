package org.layeredencryption

/**
 * Web/Wasm [CryptoProvider], bound to the noble libraries (docs/Protocol.md §5.1).
 *
 * ### Why noble, not WebCrypto
 * [CryptoProvider] is deliberately synchronous, and WebCrypto's SubtleCrypto is Promise-only —
 * a browser cannot block on a Promise, so a synchronous provider cannot call it. The noble
 * family (`@noble/hashes`, `@noble/ciphers`, `@noble/curves`, `@noble/post-quantum`) is pure JS,
 * fully synchronous, from one maintainer, with hashes/ciphers/curves independently audited
 * (Cure53). ML-KEM-768 and ML-DSA-65 come from `@noble/post-quantum` (FIPS 203/204 final,
 * not yet independently audited) — acceptable because:
 * - [HybridSignature] is strict-AND: a defect in the ML-DSA leg cannot reduce authenticity
 *   below Ed25519 (whose implementation here IS audited).
 * - [XWing]'s combiner means a defect in the ML-KEM leg degrades confidentiality to X25519,
 *   the classical baseline the threat model already accepts.
 *
 * WebCrypto convergence (native, audited, faster) is deliberately deferred: it requires making
 * the provider suspend, a protocol-wide refactor to weigh on its own when browsers ship the
 * "Modern Algorithms" additions (ML-DSA/ML-KEM/ChaCha are in Chrome's origin trial, June 2026).
 *
 * ### Encodings
 * All keys/ciphertexts/signatures are the raw FIPS/RFC byte encodings, matching
 * [the JVM provider][docs/Protocol.md §5.1]'s Bouncy Castle output on every public artifact
 * (public keys, ciphertexts, signatures), so devices interoperate. Private-key encodings only
 * ever round-trip within one provider (ML-KEM secret 2400 B expanded, ML-DSA secret 4032 B).
 *
 * ### Fail-closed contract
 * noble throws a JS `Error` on AEAD tag mismatch or malformed input; every `open` here wraps
 * that into [CryptoException] so rejection is uniform across platforms (§4.2). `mlDsa65Verify`
 * and `ed25519Verify` return `false` on malformed attacker-supplied input rather than throwing,
 * mirroring the JVM provider.
 */
internal class NobleCryptoProvider : CryptoProvider {

    override fun randomBytes(size: Int): ByteArray = webRandomBytes(size)

    override fun sha3_256(data: ByteArray): ByteArray =
        NobleSha3.sha3_256(data.toUint8Array()).toByteArray()

    override fun sha256(data: ByteArray): ByteArray =
        NobleSha2.sha256(data.toUint8Array()).toByteArray()

    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
        NobleHmac.hmac(NobleSha2Refs.sha256Ref, key.toUint8Array(), data.toUint8Array()).toByteArray()

    override fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        // RFC 5869: an absent salt means the all-zero block. HMAC zero-pads keys to the block
        // size, so the empty array yields the identical PRK — same convention as the JVM provider.
        val effectiveSalt = salt ?: ByteArray(0)
        return NobleHkdf.hkdf(
            NobleSha2Refs.sha256Ref,
            ikm.toUint8Array(),
            effectiveSalt.toUint8Array(),
            info.toUint8Array(),
            length,
        ).toByteArray()
    }

    override fun chaCha20Poly1305Seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        chaCha(key, nonce, aad).encrypt(plaintext.toUint8Array()).toByteArray()

    override fun chaCha20Poly1305Open(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray =
        failClosed("ChaCha20-Poly1305") {
            chaCha(key, nonce, aad).decrypt(ciphertextAndTag.toUint8Array()).toByteArray()
        }

    override fun aes256GcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        gcm(key, nonce, aad).encrypt(plaintext.toUint8Array()).toByteArray()

    override fun aes256GcmOpen(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray =
        failClosed("AES-256-GCM") {
            gcm(key, nonce, aad).decrypt(ciphertextAndTag.toUint8Array()).toByteArray()
        }

    override fun x25519GenerateKeyPair(): KeyPair {
        val privateKey = webRandomBytes(32)
        val publicKey = NobleCurves.x25519.getPublicKey(privateKey.toUint8Array()).toByteArray()
        return KeyPair(publicKey = publicKey, privateKey = privateKey)
    }

    override fun x25519(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray =
        NobleCurves.x25519.getSharedSecret(privateKey.toUint8Array(), peerPublicKey.toUint8Array()).toByteArray()

    override fun mlKem768GenerateKeyPair(): KeyPair {
        val keys = NoblePqKem.ml_kem768.keygen()
        return KeyPair(publicKey = keys.publicKey.toByteArray(), privateKey = keys.secretKey.toByteArray())
    }

    override fun mlKem768Encapsulate(peerPublicKey: ByteArray): KemEncapsulation {
        val encapsulation = failClosed("ML-KEM-768 encapsulate") {
            NoblePqKem.ml_kem768.encapsulate(peerPublicKey.toUint8Array())
        }
        return KemEncapsulation(
            ciphertext = encapsulation.cipherText.toByteArray(),
            sharedSecret = encapsulation.sharedSecret.toByteArray(),
        )
    }

    override fun mlKem768Decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray =
        failClosed("ML-KEM-768 decapsulate") {
            NoblePqKem.ml_kem768.decapsulate(ciphertext.toUint8Array(), privateKey.toUint8Array()).toByteArray()
        }

    override fun ed25519GenerateKeyPair(): KeyPair {
        val privateKey = webRandomBytes(32)
        val publicKey = NobleCurves.ed25519.getPublicKey(privateKey.toUint8Array()).toByteArray()
        return KeyPair(publicKey = publicKey, privateKey = privateKey)
    }

    override fun ed25519Sign(privateKey: ByteArray, message: ByteArray): ByteArray =
        NobleCurves.ed25519.sign(message.toUint8Array(), privateKey.toUint8Array()).toByteArray()

    override fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        rejectOnError {
            NobleCurves.ed25519.verify(signature.toUint8Array(), message.toUint8Array(), publicKey.toUint8Array())
        }

    override fun mlDsa65GenerateKeyPair(): KeyPair {
        val keys = NoblePqDsa.ml_dsa65.keygen()
        return KeyPair(publicKey = keys.publicKey.toByteArray(), privateKey = keys.secretKey.toByteArray())
    }

    override fun mlDsa65Sign(privateKey: ByteArray, message: ByteArray): ByteArray =
        NoblePqDsa.ml_dsa65.sign(message.toUint8Array(), privateKey.toUint8Array()).toByteArray()

    override fun mlDsa65Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        rejectOnError {
            NoblePqDsa.ml_dsa65.verify(signature.toUint8Array(), message.toUint8Array(), publicKey.toUint8Array())
        }

    private fun chaCha(key: ByteArray, nonce: ByteArray, aad: ByteArray): NobleAead =
        if (aad.isEmpty()) {
            NobleChaCha.chacha20poly1305(key.toUint8Array(), nonce.toUint8Array())
        } else {
            NobleChaCha.chacha20poly1305(key.toUint8Array(), nonce.toUint8Array(), aad.toUint8Array())
        }

    private fun gcm(key: ByteArray, nonce: ByteArray, aad: ByteArray): NobleAead =
        if (aad.isEmpty()) {
            NobleAes.gcm(key.toUint8Array(), nonce.toUint8Array())
        } else {
            NobleAes.gcm(key.toUint8Array(), nonce.toUint8Array(), aad.toUint8Array())
        }

    /** Maps any JS-side failure to [CryptoException] — tag mismatch must fail closed (§4.2). */
    private inline fun <T> failClosed(operation: String, block: () -> T): T =
        try {
            block()
        } catch (e: CryptoException) {
            throw e
        } catch (e: Throwable) {
            throw CryptoException("$operation failed", e)
        }

    /**
     * A verifier fed attacker-supplied bytes must answer "no", not crash: noble throws on
     * malformed keys/signatures where Bouncy Castle does too, and the JVM provider maps that
     * to `false` — mirrored here.
     */
    private inline fun rejectOnError(block: () -> Boolean): Boolean =
        try {
            block()
        } catch (_: Throwable) {
            false
        }
}

private val webProvider: CryptoProvider by lazy { NobleCryptoProvider() }

actual fun platformCryptoProvider(): CryptoProvider = webProvider
