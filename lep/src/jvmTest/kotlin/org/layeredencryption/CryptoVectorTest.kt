package org.layeredencryption

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Known-answer + property tests for the Android [CryptoProvider] and the `commonMain`
 * cascade / X-Wing constructions (docs/Protocol.md §5.4).
 *
 * These pin the primitives to published vectors (RFC 8439, RFC 5869, FIPS 202 SHA3) and prove the
 * asymmetric round-trips and the cascade's fail-closed behaviour. Full ACVP ML-KEM-768 vectors and
 * the IETF X-Wing *key-encoding* vectors remain as CI work per the pre-launch checklist (§5.5).
 */
class CryptoVectorTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    // ── Symmetric AEAD ────────────────────────────────────────────────────────────────────────

    /** RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD known-answer test. */
    @Test
    fun chaCha20Poly1305_rfc8439Vector() {
        val key = ByteArray(32) { (0x80 + it).toByte() }
        val nonce = hex("070000004041424344454647")
        val aad = hex("50515253c0c1c2c3c4c5c6c7")
        val plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip " +
            "for the future, sunscreen would be it.").encodeToByteArray()
        val expected = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b6116" +
                "1ae10b594f09e26a7e902ecbd0600691" // Poly1305 tag
        )

        val sealed = provider.chaCha20Poly1305Seal(key, nonce, plaintext, aad)
        assertContentEquals(expected, sealed, "ChaCha20-Poly1305 seal must match RFC 8439 vector")

        val opened = provider.chaCha20Poly1305Open(key, nonce, expected, aad)
        assertContentEquals(plaintext, opened, "ChaCha20-Poly1305 open must recover the plaintext")
    }

    @Test
    fun aes256Gcm_roundTripsAndRejectsTamper() {
        val key = provider.randomBytes(32)
        val nonce = provider.randomBytes(12)
        val aad = "context".encodeToByteArray()
        val plaintext = "meet at 7pm".encodeToByteArray()

        val sealed = provider.aes256GcmSeal(key, nonce, plaintext, aad)
        assertContentEquals(plaintext, provider.aes256GcmOpen(key, nonce, sealed, aad))

        val tampered = sealed.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFailsWith<CryptoException> { provider.aes256GcmOpen(key, nonce, tampered, aad) }
        assertFailsWith<CryptoException> {
            provider.aes256GcmOpen(key, nonce, sealed, "wrong-aad".encodeToByteArray())
        }
    }

    // ── HKDF & SHA3 ───────────────────────────────────────────────────────────────────────────

    /** RFC 5869 Appendix A.1 (Test Case 1, HKDF-SHA256). */
    @Test
    fun hkdfSha256_rfc5869Case1() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val expected = hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
        assertContentEquals(expected, provider.hkdfSha256(ikm, salt, info, length = 42))
    }

    /** FIPS 202 SHA3-256 known answers. */
    @Test
    fun sha3_256_knownAnswers() {
        assertContentEquals(
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            provider.sha3_256(ByteArray(0)),
        )
        assertContentEquals(
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            provider.sha3_256("abc".encodeToByteArray()),
        )
    }

    // ── Asymmetric round-trips ────────────────────────────────────────────────────────────────

    @Test
    fun x25519_agreementIsSymmetric() {
        val alice = provider.x25519GenerateKeyPair()
        val bob = provider.x25519GenerateKeyPair()
        assertEquals(32, alice.publicKey.size)

        assertContentEquals(
            provider.x25519(alice.privateKey, bob.publicKey),
            provider.x25519(bob.privateKey, alice.publicKey),
        )
    }

    @Test
    fun mlKem768_encapsulateDecapsulateAgree() {
        val keyPair = provider.mlKem768GenerateKeyPair()
        assertEquals(1184, keyPair.publicKey.size, "ML-KEM-768 encapsulation key size")

        val encapsulation = provider.mlKem768Encapsulate(keyPair.publicKey)
        assertEquals(1088, encapsulation.ciphertext.size, "ML-KEM-768 ciphertext size")
        assertEquals(32, encapsulation.sharedSecret.size)

        val recovered = provider.mlKem768Decapsulate(keyPair.privateKey, encapsulation.ciphertext)
        assertContentEquals(encapsulation.sharedSecret, recovered)
    }

    @Test
    fun xWing_encapsulateDecapsulateAgree() {
        val keyPair = XWing.generateKeyPair(provider)
        assertEquals(1184 + 32, keyPair.publicKey.size, "X-Wing public key = ML-KEM pk ‖ X25519 pk")

        val encapsulation = XWing.encapsulate(provider, keyPair.publicKey)
        assertEquals(1088 + 32, encapsulation.ciphertext.size, "X-Wing ciphertext = ML-KEM ct ‖ X25519 pk")
        assertEquals(32, encapsulation.sharedSecret.size, "combiner output is a 32-byte SHA3-256 digest")

        val recovered = XWing.decapsulate(provider, keyPair.privateKey, encapsulation.ciphertext)
        assertContentEquals(encapsulation.sharedSecret, recovered, "both sides must derive the same secret")
    }

    @Test
    fun xWing_distinctPairingsProduceDistinctSecrets() {
        val keyPair = XWing.generateKeyPair(provider)
        val first = XWing.encapsulate(provider, keyPair.publicKey).sharedSecret
        val second = XWing.encapsulate(provider, keyPair.publicKey).sharedSecret
        assertFalse(first.contentEquals(second), "fresh randomness must yield fresh shared secrets")
    }

    // ── Cascade ───────────────────────────────────────────────────────────────────────────────

    @Test
    fun cascade_roundTrips() {
        val master = provider.randomBytes(32)
        val plaintext = "Dentist, Tue 14:00, hidden from Sarah".encodeToByteArray()
        val aad = "context-42".encodeToByteArray()

        val blob = Cascade.seal(provider, master, plaintext, aad)
        assertContentEquals(plaintext, Cascade.open(provider, master, blob, aad))
    }

    @Test
    fun cascade_rejectsTamperedBlobAndWrongKey() {
        val master = provider.randomBytes(32)
        val blob = Cascade.seal(provider, master, "secret".encodeToByteArray())

        val tampered = blob.copyOf().also { it[it.lastIndex] = (it[it.lastIndex] + 1).toByte() }
        assertFailsWith<CryptoException> { Cascade.open(provider, master, tampered) }
        assertFailsWith<CryptoException> { Cascade.open(provider, provider.randomBytes(32), blob) }
    }

    @Test
    fun cascade_layerKeysAreIndependent() {
        // The two cascade layers must never share a key (§4.2): HKDF under distinct labels differs.
        val master = provider.randomBytes(32)
        val chachaKey = provider.hkdfSha256(master, null, "calendite/v1/layer-chacha".encodeToByteArray(), 32)
        val aesKey = provider.hkdfSha256(master, null, "calendite/v1/layer-aes".encodeToByteArray(), 32)
        assertFalse(chachaKey.contentEquals(aesKey), "ChaCha and AES layer keys must be independent")
    }

    @Test
    fun cascade_nonceIsFreshPerBlob() {
        // Random nonces per layer per blob ⇒ identical plaintext seals to different bytes.
        val master = provider.randomBytes(32)
        val plaintext = "same input".encodeToByteArray()
        assertFalse(
            Cascade.seal(provider, master, plaintext).contentEquals(Cascade.seal(provider, master, plaintext)),
            "each seal must use fresh nonces",
        )
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
