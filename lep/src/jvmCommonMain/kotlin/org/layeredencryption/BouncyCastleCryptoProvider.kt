package org.layeredencryption

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * JVM and Android [CryptoProvider] (docs/Protocol.md §5.1).
 *
 * - **Symmetric AEAD** runs on JCA (`ChaCha20-Poly1305`, `AES/GCM/NoPadding`) — the audited,
 *   hardware-accelerated platform providers (Conscrypt/BoringSSL). These are the hot path (§4.1).
 * - **SHA3, HKDF, X25519, ML-KEM-768** use Bouncy Castle's *lightweight* API by direct class
 *   reference. This deliberately avoids registering a `BouncyCastleProvider` in `java.security`, so
 *   there is no interaction with Android's own repackaged BouncyCastle. ML-KEM is the once-per-
 *   pairing KEM, not a hot path (§4.1).
 */
class BouncyCastleCryptoProvider(
    /**
     * The single source of randomness: key generation and nonces both draw from it.
     *
     * Injectable **only** so a recorded ceremony can be reproduced byte for byte from a seed,
     * which is what makes test vectors and the inspector possible. Production must never pass
     * anything here; the default is the platform CSPRNG, and a seeded generator would make every
     * key in the system predictable.
     */
    private val secureRandom: SecureRandom = SecureRandom(),
) : CryptoProvider {

    override fun randomBytes(size: Int): ByteArray = ByteArray(size).also(secureRandom::nextBytes)

    override fun sha3_256(data: ByteArray): ByteArray {
        val digest = SHA3Digest(256)
        digest.update(data, 0, data.size)
        return ByteArray(digest.digestSize).also { digest.doFinal(it, 0) }
    }

    override fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    override fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, salt, info))
        return ByteArray(length).also { hkdf.generateBytes(it, 0, length) }
    }

    override fun chaCha20Poly1305Seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        aeadSeal("ChaCha20-Poly1305", SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce), plaintext, aad)

    override fun chaCha20Poly1305Open(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray =
        aeadOpen("ChaCha20-Poly1305", SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce), ciphertextAndTag, aad)

    override fun aes256GcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        aeadSeal("AES/GCM/NoPadding", SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce), plaintext, aad)

    override fun aes256GcmOpen(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray =
        aeadOpen("AES/GCM/NoPadding", SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce), ciphertextAndTag, aad)

    override fun x25519GenerateKeyPair(): KeyPair {
        val privateKey = X25519PrivateKeyParameters(secureRandom)
        return KeyPair(publicKey = privateKey.generatePublicKey().encoded, privateKey = privateKey.encoded)
    }

    override fun x25519(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(privateKey, 0))
        val secret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(peerPublicKey, 0), secret, 0)
        return secret
    }

    override fun mlKem768GenerateKeyPair(): KeyPair {
        val generator = MLKEMKeyPairGenerator()
        generator.init(MLKEMKeyGenerationParameters(secureRandom, MLKEMParameters.ml_kem_768))
        val pair = generator.generateKeyPair()
        val publicKey = (pair.public as MLKEMPublicKeyParameters).encoded
        val privateKey = (pair.private as MLKEMPrivateKeyParameters).encoded
        return KeyPair(publicKey = publicKey, privateKey = privateKey)
    }

    override fun mlKem768Encapsulate(peerPublicKey: ByteArray): KemEncapsulation {
        val publicKey = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, peerPublicKey)
        val encapsulated = MLKEMGenerator(secureRandom).generateEncapsulated(publicKey)
        val result = KemEncapsulation(ciphertext = encapsulated.encapsulation, sharedSecret = encapsulated.secret)
        encapsulated.destroy()
        return result
    }

    override fun mlKem768Decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray {
        val key = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, privateKey)
        return MLKEMExtractor(key).extractSecret(ciphertext)
    }

    override fun ed25519GenerateKeyPair(): KeyPair {
        val privateKey = Ed25519PrivateKeyParameters(secureRandom)
        return KeyPair(publicKey = privateKey.generatePublicKey().encoded, privateKey = privateKey.encoded)
    }

    override fun ed25519Sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKey, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    override fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }

    override fun mlDsa65GenerateKeyPair(): KeyPair {
        val generator = MLDSAKeyPairGenerator()
        generator.init(MLDSAKeyGenerationParameters(secureRandom, MLDSAParameters.ml_dsa_65))
        val pair = generator.generateKeyPair()
        return KeyPair(
            publicKey = (pair.public as MLDSAPublicKeyParameters).encoded,
            privateKey = (pair.private as MLDSAPrivateKeyParameters).encoded,
        )
    }

    override fun mlDsa65Sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        val signer = MLDSASigner()
        signer.init(true, MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, privateKey))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    /**
     * Rejects rather than throws on a malformed key or signature: Bouncy Castle raises on a
     * wrong-length key, and a caller verifying an attacker-supplied identity must see that as an
     * ordinary "no" rather than a crash.
     */
    override fun mlDsa65Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        runCatching {
            val verifier = MLDSASigner()
            verifier.init(false, MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, publicKey))
            verifier.update(message, 0, message.size)
            verifier.verifySignature(signature)
        }.getOrDefault(false)

    private fun aeadSeal(
        transformation: String,
        key: SecretKeySpec,
        params: java.security.spec.AlgorithmParameterSpec,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, key, params)
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    private fun aeadOpen(
        transformation: String,
        key: SecretKeySpec,
        params: java.security.spec.AlgorithmParameterSpec,
        ciphertextAndTag: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        try {
            val cipher = Cipher.getInstance(transformation)
            cipher.init(Cipher.DECRYPT_MODE, key, params)
            if (aad.isNotEmpty()) cipher.updateAAD(aad)
            return cipher.doFinal(ciphertextAndTag)
        } catch (e: GeneralSecurityException) {
            // Tag mismatch / malformed ciphertext must fail closed (§4.2).
            throw CryptoException("AEAD authentication failed ($transformation)", e)
        }
    }

    private companion object {
        const val GCM_TAG_BITS = 128
    }
}

private val androidProvider: CryptoProvider by lazy { BouncyCastleCryptoProvider() }

actual fun platformCryptoProvider(): CryptoProvider = androidProvider
