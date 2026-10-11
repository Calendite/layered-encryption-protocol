@file:OptIn(ExperimentalForeignApi::class)

package org.layeredencryption

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import org.layeredencryption.native.LEP_CK_AUTH_FAILED
import org.layeredencryption.native.LEP_CK_OK
import org.layeredencryption.native.LEP_MLDSA65_BYTES
import org.layeredencryption.native.LEP_MLDSA65_PUBLICKEYBYTES
import org.layeredencryption.native.LEP_MLDSA65_SECRETKEYBYTES
import org.layeredencryption.native.LEP_MLKEM768_CIPHERTEXTBYTES
import org.layeredencryption.native.LEP_MLKEM768_PUBLICKEYBYTES
import org.layeredencryption.native.LEP_MLKEM768_SECRETKEYBYTES
import org.layeredencryption.native.lep_ck_aes_gcm_open
import org.layeredencryption.native.lep_ck_aes_gcm_seal
import org.layeredencryption.native.lep_ck_chachapoly_open
import org.layeredencryption.native.lep_ck_chachapoly_seal
import org.layeredencryption.native.lep_ck_x25519
import org.layeredencryption.native.lep_ck_x25519_public_key
import org.layeredencryption.native.lep_ed25519_public_key
import org.layeredencryption.native.lep_ed25519_public_key_is_valid
import org.layeredencryption.native.lep_ed25519_sign
import org.layeredencryption.native.lep_ed25519_verify
import org.layeredencryption.native.lep_mldsa65_keypair_derand
import org.layeredencryption.native.lep_mldsa65_sign_derand
import org.layeredencryption.native.lep_mldsa65_verify
import org.layeredencryption.native.lep_mlkem768_check_pk
import org.layeredencryption.native.lep_mlkem768_dec
import org.layeredencryption.native.lep_mlkem768_enc_derand
import org.layeredencryption.native.lep_mlkem768_keypair_derand
import org.layeredencryption.native.lep_sha3_256
import org.layeredencryption.native.lep_shake256
import platform.CoreCrypto.CCHmac
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.CoreCrypto.kCCHmacAlgSHA256
import platform.Security.SecRandomCopyBytes
import platform.Security.errSecSuccess
import platform.Security.kSecRandomDefault

/**
 * Where a provider's randomness comes from. A seam for the same reason as Bouncy Castle's
 * injectable `SecureRandom`: so a recorded run can be replayed byte for byte.
 */
fun interface RandomSource {
    /** Fills [bytes] completely. */
    fun nextBytes(bytes: ByteArray)
}

/** The system CSPRNG (`SecRandomCopyBytes`). */
object SystemRandomSource : RandomSource {
    override fun nextBytes(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        val status = bytes.usePinned { SecRandomCopyBytes(kSecRandomDefault, bytes.size.convert(), it.addressOf(0)) }
        if (status != errSecSuccess) throw IllegalStateException("SecRandomCopyBytes failed: $status")
    }
}

/**
 * macOS [CryptoProvider] for Kotlin/Native, the background daemons' provider
 * (docs/Protocol.md §5.1; lep/native/README.md).
 *
 * It must be indistinguishable from [BouncyCastleCryptoProvider] on the JVM, byte for byte, since
 * a daemon reads keys the Mac app wrote and talks to phones running Bouncy Castle. So each
 * primitive comes from code that uses the same encodings and is deterministic where Bouncy Castle
 * is:
 *
 * | Primitive                       | Source                                              |
 * |---------------------------------|-----------------------------------------------------|
 * | SHA-256, HMAC-SHA256, random    | CommonCrypto, Security                              |
 * | HKDF-SHA256                     | RFC 5869 over CommonCrypto's HMAC, below            |
 * | ChaCha20-Poly1305, AES-GCM      | CryptoKit                                           |
 * | X25519                          | CryptoKit                                           |
 * | SHA3-256, SHAKE256              | mlkem-native's Keccak                               |
 * | ML-KEM-768                      | mlkem-native (FIPS 203 encodings: dk is 2400 bytes) |
 * | ML-DSA-65                       | mldsa-native (FIPS 204 encodings: sk is 4032 bytes) |
 * | Ed25519                         | Monocypher (deterministic RFC 8032)                 |
 *
 * CryptoKit is not used for ML-KEM, ML-DSA or Ed25519: it loads post-quantum private keys only
 * from their seeds, not the expanded encodings already stored on every device, and its Ed25519
 * signatures are randomised.
 *
 * Randomness is drawn from [random] in exactly the calls and sizes Bouncy Castle draws it, and
 * passed into the C, which never draws its own. Every size is checked before any pointer crosses
 * into C: the C functions take fixed-size arrays and would otherwise read past a short one.
 * `AppleProviderParityTest` replays the JVM provider's recorded vectors against this one.
 */
class AppleCryptoProvider(
    /**
     * Injectable **only** so recorded vectors can be replayed; production must never pass
     * anything here (see [BouncyCastleCryptoProvider]'s `secureRandom`).
     */
    private val random: RandomSource = SystemRandomSource,
) : CryptoProvider {

    override fun randomBytes(size: Int): ByteArray = ByteArray(size).also(random::nextBytes)

    override fun sha3_256(data: ByteArray): ByteArray {
        val out = ByteArray(32)
        check(data.pointer { d -> out.pointer { o -> lep_sha3_256(o, d, data.size.convert()) } } == 0)
        return out
    }

    override fun shake256(data: ByteArray, outputLength: Int): ByteArray {
        require(outputLength >= 0) { "SHAKE256 output length must not be negative" }
        val out = ByteArray(outputLength)
        check(data.pointer { d -> out.pointer { o -> lep_shake256(o, outputLength.convert(), d, data.size.convert()) } } == 0)
        return out
    }

    override fun sha256(data: ByteArray): ByteArray {
        val out = ByteArray(CC_SHA256_DIGEST_LENGTH)
        data.pointer { d -> out.pointer { o -> CC_SHA256(d, data.size.convert(), o) } }
        return out
    }

    /** Refuses an empty key, as the JCA's `SecretKeySpec` behind Bouncy Castle's provider does. */
    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        require(key.isNotEmpty()) { "Empty key" }
        return hmac(key, data)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val out = ByteArray(CC_SHA256_DIGEST_LENGTH)
        key.pointer { k ->
            data.pointer { d ->
                out.pointer { o -> CCHmac(kCCHmacAlgSHA256, k, key.size.convert(), d, data.size.convert(), o) }
            }
        }
        return out
    }

    /**
     * RFC 5869 over CommonCrypto's HMAC, with Bouncy Castle's limits: at most 255 blocks of output, and
     * a null salt meaning 32 zero bytes (which an empty salt also amounts to, HMAC zero-padding
     * its key).
     */
    override fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        require(length >= 0) { "HKDF output length must not be negative" }
        require(length <= HKDF_MAX_OUTPUT) { "HKDF may only be used for 255 * HashLen bytes of output" }
        val prk = hmac(salt ?: ByteArray(32), ikm)
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < length) {
            previous = hmac(prk, previous + info + byteArrayOf(counter.toByte()))
            val take = minOf(previous.size, length - written)
            previous.copyInto(out, destinationOffset = written, endIndex = take)
            written += take
            counter++
        }
        return out
    }

    override fun chaCha20Poly1305Seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == 32) { "ChaCha20-Poly1305 key must be 32 bytes" }
        require(nonce.size == 12) { "ChaCha20-Poly1305 nonce must be 12 bytes" }
        return seal(key, nonce, plaintext, aad, ::lep_ck_chachapoly_seal, "ChaCha20-Poly1305")
    }

    override fun chaCha20Poly1305Open(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray {
        require(key.isNotEmpty()) { "Empty key" }
        if (key.size != 32 || nonce.size != 12) throw CryptoException("AEAD authentication failed (ChaCha20-Poly1305)")
        return open(key, nonce, ciphertextAndTag, aad, ::lep_ck_chachapoly_open, "ChaCha20-Poly1305")
    }

    override fun aes256GcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size in AES_KEY_SIZES) { "AES key must be 16, 24 or 32 bytes" }
        // As every provider: CryptoKit takes 12 or more, and LEP only ever uses 12 (Cascade).
        require(nonce.size >= 12) { "AES-GCM nonce must be at least 12 bytes" }
        return seal(key, nonce, plaintext, aad, ::lep_ck_aes_gcm_seal, "AES/GCM/NoPadding")
    }

    override fun aes256GcmOpen(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray {
        require(key.isNotEmpty()) { "Empty key" }
        if (key.size !in AES_KEY_SIZES || nonce.size < 12) throw CryptoException("AEAD authentication failed (AES/GCM/NoPadding)")
        return open(key, nonce, ciphertextAndTag, aad, ::lep_ck_aes_gcm_open, "AES/GCM/NoPadding")
    }

    /** Bouncy Castle draws 32 bytes and clamps them (RFC 7748 §5) into the stored private key. */
    override fun x25519GenerateKeyPair(): KeyPair {
        val privateKey = ByteArray(32).also(random::nextBytes)
        privateKey[0] = (privateKey[0].toInt() and 0xF8).toByte()
        privateKey[31] = ((privateKey[31].toInt() and 0x7F) or 0x40).toByte()
        return KeyPair(publicKey = x25519PublicKey(privateKey), privateKey = privateKey)
    }

    override fun x25519PublicKey(privateKey: ByteArray): ByteArray {
        val scalar = firstBytes(privateKey, 32, "X25519 private key")
        val out = ByteArray(32)
        check(scalar.pointer { k -> out.pointer { o -> lep_ck_x25519_public_key(k, o) } } == LEP_CK_OK) { "X25519 public key failed" }
        return out
    }

    override fun x25519(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        val scalar = firstBytes(privateKey, 32, "X25519 private key")
        val peer = firstBytes(peerPublicKey, 32, "X25519 public key")
        val out = ByteArray(32)
        val status = scalar.pointer { k -> peer.pointer { p -> out.pointer { o -> lep_ck_x25519(k, p, o) } } }
        // Bouncy Castle refuses an all-zero result (a low-order peer point), as RFC 7748 §6.1 allows.
        if (status != LEP_CK_OK || out.all { it == 0.toByte() }) throw IllegalStateException("X25519 agreement failed")
        return out
    }

    /** Bouncy Castle draws d, then z, 32 bytes each (FIPS 203 Algorithm 19). */
    override fun mlKem768GenerateKeyPair(): KeyPair {
        val d = ByteArray(32).also(random::nextBytes)
        val z = ByteArray(32).also(random::nextBytes)
        return mlKem768KeyPairFromSeed(d, z)
    }

    override fun mlKem768KeyPairFromSeed(d: ByteArray, z: ByteArray): KeyPair {
        require(d.size == 32 && z.size == 32) { "ML-KEM keygen seeds d and z must be 32 bytes each" }
        val coins = d + z
        val publicKey = ByteArray(LEP_MLKEM768_PUBLICKEYBYTES)
        val privateKey = ByteArray(LEP_MLKEM768_SECRETKEYBYTES)
        val status = coins.pointer { c -> publicKey.pointer { pk -> privateKey.pointer { sk -> lep_mlkem768_keypair_derand(pk, sk, c) } } }
        coins.fill(0)
        check(status == 0) { "ML-KEM-768 key generation failed: $status" }
        return KeyPair(publicKey = publicKey, privateKey = privateKey)
    }

    /**
     * Bouncy Castle checks the key (FIPS 203 §7.2) and only then draws the 32-byte message m
     * (Algorithm 20), so a bad key costs no randomness here either.
     */
    override fun mlKem768Encapsulate(peerPublicKey: ByteArray): KemEncapsulation {
        require(peerPublicKey.size == LEP_MLKEM768_PUBLICKEYBYTES) { "ML-KEM-768 public key must be $LEP_MLKEM768_PUBLICKEYBYTES bytes" }
        require(peerPublicKey.pointer { lep_mlkem768_check_pk(it) } == 0) { "ML-KEM-768 public key failed the FIPS 203 modulus check" }
        val m = ByteArray(32).also(random::nextBytes)
        val ciphertext = ByteArray(LEP_MLKEM768_CIPHERTEXTBYTES)
        val secret = ByteArray(32)
        val status = m.pointer { c ->
            peerPublicKey.pointer { pk -> ciphertext.pointer { ct -> secret.pointer { ss -> lep_mlkem768_enc_derand(ct, ss, pk, c) } } }
        }
        m.fill(0)
        require(status == 0) { "ML-KEM-768 public key failed the FIPS 203 modulus check" }
        return KemEncapsulation(ciphertext = ciphertext, sharedSecret = secret)
    }

    override fun mlKem768Decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray {
        require(privateKey.size == LEP_MLKEM768_SECRETKEYBYTES) { "ML-KEM-768 private key must be $LEP_MLKEM768_SECRETKEYBYTES bytes" }
        require(ciphertext.size == LEP_MLKEM768_CIPHERTEXTBYTES) { "ML-KEM-768 ciphertext must be $LEP_MLKEM768_CIPHERTEXTBYTES bytes" }
        val secret = ByteArray(32)
        val status = secret.pointer { ss -> ciphertext.pointer { ct -> privateKey.pointer { sk -> lep_mlkem768_dec(ss, ct, sk) } } }
        require(status == 0) { "ML-KEM-768 private key failed the FIPS 203 hash check" }
        return secret
    }

    /** Bouncy Castle draws the 32-byte seed; the private key is that seed (RFC 8032). */
    override fun ed25519GenerateKeyPair(): KeyPair {
        val privateKey = ByteArray(32).also(random::nextBytes)
        val publicKey = ByteArray(32)
        privateKey.pointer { s -> publicKey.pointer { pk -> lep_ed25519_public_key(pk, s) } }
        return KeyPair(publicKey = publicKey, privateKey = privateKey)
    }

    override fun ed25519Sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        val seed = firstBytes(privateKey, 32, "Ed25519 private key")
        val signature = ByteArray(64)
        seed.pointer { s -> message.pointer { m -> signature.pointer { sig -> lep_ed25519_sign(sig, s, m, message.size.convert()) } } }
        return signature
    }

    /**
     * Throws, as Bouncy Castle does, for a public key it would refuse to build (not canonical, of
     * small order, or off the curve); returns false for any other bad signature.
     */
    override fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val key = firstBytes(publicKey, 32, "Ed25519 public key")
        require(key.pointer { lep_ed25519_public_key_is_valid(it) } == 0) { "invalid public key" }
        if (signature.size != 64) return false
        return key.pointer { pk -> message.pointer { m -> signature.pointer { sig -> lep_ed25519_verify(sig, pk, m, message.size.convert()) } } } == 0
    }

    /** Bouncy Castle draws the 32-byte seed ξ (FIPS 204 Algorithm 1). */
    override fun mlDsa65GenerateKeyPair(): KeyPair {
        val seed = ByteArray(32).also(random::nextBytes)
        val publicKey = ByteArray(LEP_MLDSA65_PUBLICKEYBYTES)
        val privateKey = ByteArray(LEP_MLDSA65_SECRETKEYBYTES)
        val status = seed.pointer { s -> publicKey.pointer { pk -> privateKey.pointer { sk -> lep_mldsa65_keypair_derand(pk, sk, s) } } }
        seed.fill(0)
        check(status == 0) { "ML-DSA-65 key generation failed: $status" }
        return KeyPair(publicKey = publicKey, privateKey = privateKey)
    }

    /** Deterministic, as Bouncy Castle signs without a SecureRandom: rnd is 32 zero bytes. */
    override fun mlDsa65Sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        require(privateKey.size == LEP_MLDSA65_SECRETKEYBYTES) { "ML-DSA-65 private key must be $LEP_MLDSA65_SECRETKEYBYTES bytes" }
        val rnd = ByteArray(32)
        val signature = ByteArray(LEP_MLDSA65_BYTES)
        val status = message.pointer { m ->
            rnd.pointer { r -> privateKey.pointer { sk -> signature.pointer { sig -> lep_mldsa65_sign_derand(sig, m, message.size.convert(), r, sk) } } }
        }
        check(status == 0) { "ML-DSA-65 signing failed: $status" }
        return signature
    }

    /** Rejects rather than throws on a malformed key or signature, as Bouncy Castle's does. */
    override fun mlDsa65Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != LEP_MLDSA65_PUBLICKEYBYTES || signature.size != LEP_MLDSA65_BYTES) return false
        return message.pointer { m ->
            publicKey.pointer { pk -> signature.pointer { sig -> lep_mldsa65_verify(sig, m, message.size.convert(), pk) } }
        } == 0
    }

    private fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray, cipher: AeadCall, name: String): ByteArray {
        val out = ByteArray(plaintext.size + TAG_BYTES)
        val status = key.pointer { k ->
            nonce.pointer { n ->
                plaintext.pointer { p ->
                    aad.pointer { a ->
                        out.pointer { o -> cipher(k, key.size.convert(), n, nonce.size.convert(), p, plaintext.size.convert(), a, aad.size.convert(), o) }
                    }
                }
            }
        }
        check(status == LEP_CK_OK) { "$name seal failed" }
        return out
    }

    private fun open(key: ByteArray, nonce: ByteArray, sealed: ByteArray, aad: ByteArray, cipher: AeadCall, name: String): ByteArray {
        if (sealed.size < TAG_BYTES) throw CryptoException("AEAD authentication failed ($name)")
        val out = ByteArray(sealed.size - TAG_BYTES)
        val status = key.pointer { k ->
            nonce.pointer { n ->
                sealed.pointer { s ->
                    aad.pointer { a ->
                        out.pointer { o -> cipher(k, key.size.convert(), n, nonce.size.convert(), s, sealed.size.convert(), a, aad.size.convert(), o) }
                    }
                }
            }
        }
        if (status != LEP_CK_OK) {
            out.fill(0)
            // Fail closed (§4.2): a bad tag and anything else CryptoKit refuses read the same.
            throw CryptoException(if (status == LEP_CK_AUTH_FAILED) "AEAD authentication failed ($name)" else "AEAD open failed ($name)")
        }
        return out
    }

    private companion object {
        const val TAG_BYTES = 16
        const val HKDF_MAX_OUTPUT = 255 * 32
        val AES_KEY_SIZES = setOf(16, 24, 32)

        /**
         * Bouncy Castle's raw key parameters copy the first [size] bytes of a longer array and
         * throw on a shorter one; this does the same, so a key reads identically on both.
         */
        fun firstBytes(bytes: ByteArray, size: Int, what: String): ByteArray {
            if (bytes.size < size) throw IndexOutOfBoundsException("$what must be at least $size bytes, was ${bytes.size}")
            return if (bytes.size == size) bytes else bytes.copyOf(size)
        }
    }
}

private typealias AeadCall = (
    CPointer<UByteVar>?, Long, CPointer<UByteVar>?, Long, CPointer<UByteVar>?, Long, CPointer<UByteVar>?, Long, CPointer<UByteVar>?,
) -> Int

/**
 * Hands C a pointer to this array's bytes for the duration of [block]. An empty array has no
 * address, so it is given a one-byte stand-in rather than null (the callee is told its length is
 * 0): C's memcpy and friends are undefined on a null pointer even for zero bytes.
 */
private inline fun <R> ByteArray.pointer(block: (CPointer<UByteVar>?) -> R): R =
    (if (isEmpty()) ByteArray(1) else this).usePinned { block(it.addressOf(0).reinterpret()) }

private val provider: CryptoProvider by lazy { AppleCryptoProvider() }

actual fun platformCryptoProvider(): CryptoProvider = provider
