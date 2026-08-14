package org.layeredencryption

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Cross-platform conformance suite for every [platformCryptoProvider] (docs/Protocol.md §5.4).
 *
 * Runs on **every target** — Bouncy Castle on JVM/Android, noble on Web/Wasm — pinning each
 * provider to the same published vectors (RFC 8439, RFC 5869, RFC 4231, RFC 7748, RFC 8032,
 * FIPS 202) and the same structural properties (sizes, fail-closed AEADs, ML-KEM implicit
 * rejection, strict-AND hybrid signatures). Two providers that both pass cannot disagree on
 * any public artifact, which is what lets a phone and a browser interoperate.
 *
 * Overlaps deliberately with the JVM-only `CryptoVectorTest` (which also exercises the seeded
 * inspector paths); the overlap is the point — identical answers everywhere.
 *
 * Platforms whose provider is still a throwing stub (iOS today) self-skip: every test starts
 * with `val provider = provider ?: return`, so the suite goes green there without pretending
 * to have verified anything, and starts biting the moment a real actual lands.
 */
class CryptoProviderConformanceTest {

    private val provider: CryptoProvider? = runCatching { platformCryptoProvider() }.getOrNull()

    /**
     * The self-skip, made loud (LEP-08f): on a platform whose provider is a throwing stub (iOS
     * today), every test in this suite silently verifies nothing. This test exists so that state
     * appears in the test *report* instead of hiding behind an innocent green run — its output
     * says exactly what green means here. CI must not count a self-skipping platform as a
     * verified crypto target; that enforcement is the required-checks work (LEP-08h).
     */
    @Test
    fun platformProviderStatus_greenMeansNothingHereIfThisReportsASkip() {
        if (provider == null) {
            println("CONFORMANCE SELF-SKIP: no CryptoProvider on this platform — this suite verified NO cryptography")
        } else {
            println("Conformance suite active: ${provider::class.simpleName}")
        }
    }

    // ── Hashes & MACs ─────────────────────────────────────────────────────────────────────────

    /** NIST SHA-256 known answer for "abc". */
    @Test
    fun sha256_knownAnswer() {
        val provider = provider ?: return
        assertContentEquals(
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            provider.sha256("abc".encodeToByteArray()),
        )
    }

    /** FIPS 202 SHA3-256 known answers. */
    @Test
    fun sha3_256_knownAnswers() {
        val provider = provider ?: return
        assertContentEquals(
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            provider.sha3_256(ByteArray(0)),
        )
        assertContentEquals(
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            provider.sha3_256("abc".encodeToByteArray()),
        )
    }

    /** FIPS 202 SHAKE256 known answers, plus the XOF prefix property the seed expansion relies on. */
    @Test
    fun shake256_knownAnswersAndXofPrefix() {
        val provider = provider ?: return
        assertContentEquals(
            hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
            provider.shake256(ByteArray(0), 32),
        )
        assertContentEquals(
            hex("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"),
            provider.shake256("abc".encodeToByteArray(), 32),
        )
        // An XOF's longer read starts with its shorter read — X-Wing's 96-byte expansion depends on it.
        assertContentEquals(
            provider.shake256("abc".encodeToByteArray(), 32),
            provider.shake256("abc".encodeToByteArray(), 96).copyOfRange(0, 32),
        )
    }

    /** RFC 4231 Test Case 1 (HMAC-SHA256). */
    @Test
    fun hmacSha256_rfc4231Case1() {
        val provider = provider ?: return
        val key = ByteArray(20) { 0x0b }
        val expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        assertContentEquals(expected, provider.hmacSha256(key, "Hi There".encodeToByteArray()))
    }

    /** RFC 5869 Appendix A.1 (Test Case 1, HKDF-SHA256). */
    @Test
    fun hkdfSha256_rfc5869Case1() {
        val provider = provider ?: return
        val ikm = ByteArray(22) { 0x0b }
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val expected = hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
        assertContentEquals(expected, provider.hkdfSha256(ikm, salt, info, length = 42))
    }

    /** RFC 5869: an absent salt is the all-zero block — `null` must equal 32 zero bytes. */
    @Test
    fun hkdfSha256_nullSaltMeansZeroSalt() {
        val provider = provider ?: return
        val ikm = "input keying material".encodeToByteArray()
        val info = "context".encodeToByteArray()
        assertContentEquals(
            provider.hkdfSha256(ikm, ByteArray(32), info, length = 64),
            provider.hkdfSha256(ikm, null, info, length = 64),
        )
    }

    // ── Symmetric AEAD ────────────────────────────────────────────────────────────────────────

    /** RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD known-answer test. */
    @Test
    fun chaCha20Poly1305_rfc8439Vector() {
        val provider = provider ?: return
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
    fun chaCha20Poly1305_failsClosed() {
        val provider = provider ?: return
        val key = provider.randomBytes(32)
        val nonce = provider.randomBytes(12)
        val sealed = provider.chaCha20Poly1305Seal(key, nonce, "payload".encodeToByteArray(), ByteArray(0))

        val tampered = sealed.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFailsWith<CryptoException> { provider.chaCha20Poly1305Open(key, nonce, tampered, ByteArray(0)) }
        assertFailsWith<CryptoException> {
            provider.chaCha20Poly1305Open(key, nonce, sealed, "unexpected-aad".encodeToByteArray())
        }
    }

    @Test
    fun aes256Gcm_roundTripsAndRejectsTamper() {
        val provider = provider ?: return
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

    // ── X25519 ────────────────────────────────────────────────────────────────────────────────

    /** RFC 7748 §6.1 Diffie-Hellman known-answer test. */
    @Test
    fun x25519_rfc7748Vector() {
        val provider = provider ?: return
        val alicePrivate = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val alicePublic = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val bobPublic = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val sharedSecret = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        assertContentEquals(sharedSecret, provider.x25519(alicePrivate, bobPublic))
        // The public key derivation must match the vector too — proven via a fresh agreement.
        assertContentEquals(
            provider.x25519(alicePrivate, bobPublic),
            provider.x25519(hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"), alicePublic),
        )
    }

    /** RFC 7748 §6.1: the public key for Alice's scalar, derived directly (X-Wing seed expansion path). */
    @Test
    fun x25519PublicKey_rfc7748Vector() {
        val provider = provider ?: return
        assertContentEquals(
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            provider.x25519PublicKey(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")),
        )
    }

    @Test
    fun x25519_agreementIsSymmetric() {
        val provider = provider ?: return
        val alice = provider.x25519GenerateKeyPair()
        val bob = provider.x25519GenerateKeyPair()
        assertEquals(32, alice.publicKey.size)
        assertContentEquals(
            provider.x25519(alice.privateKey, bob.publicKey),
            provider.x25519(bob.privateKey, alice.publicKey),
        )
    }

    // ── Ed25519 ───────────────────────────────────────────────────────────────────────────────

    /** RFC 8032 §7.1 TEST 2 (one-byte message) — deterministic, so the exact signature is pinned. */
    @Test
    fun ed25519_rfc8032Test2() {
        val provider = provider ?: return
        val privateKey = hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        val publicKey = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        val message = hex("72")
        val signature = hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )

        assertContentEquals(signature, provider.ed25519Sign(privateKey, message))
        assertTrue(provider.ed25519Verify(publicKey, message, signature))

        val flipped = signature.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertFalse(provider.ed25519Verify(publicKey, message, flipped))
    }

    @Test
    fun ed25519_generatedKeysRoundTrip() {
        val provider = provider ?: return
        val keys = provider.ed25519GenerateKeyPair()
        assertEquals(32, keys.publicKey.size)
        val message = "device identity binding".encodeToByteArray()
        val signature = provider.ed25519Sign(keys.privateKey, message)
        assertEquals(64, signature.size)
        assertTrue(provider.ed25519Verify(keys.publicKey, message, signature))
        assertFalse(provider.ed25519Verify(keys.publicKey, "other message".encodeToByteArray(), signature))
        assertFalse(provider.ed25519Verify(provider.ed25519GenerateKeyPair().publicKey, message, signature))
    }

    // ── ML-KEM-768 ────────────────────────────────────────────────────────────────────────────

    @Test
    fun mlKem768_encapsulateDecapsulateAgree() {
        val provider = provider ?: return
        val keyPair = provider.mlKem768GenerateKeyPair()
        assertEquals(1184, keyPair.publicKey.size, "ML-KEM-768 encapsulation key size")

        val encapsulation = provider.mlKem768Encapsulate(keyPair.publicKey)
        assertEquals(1088, encapsulation.ciphertext.size, "ML-KEM-768 ciphertext size")
        assertEquals(32, encapsulation.sharedSecret.size)

        val recovered = provider.mlKem768Decapsulate(keyPair.privateKey, encapsulation.ciphertext)
        assertContentEquals(encapsulation.sharedSecret, recovered)
    }

    /**
     * FIPS 203 `KeyGen_internal(d, z)`: deterministic, and *identical across providers* — the
     * pinned hash below was produced independently by Bouncy Castle 1.81 and noble post-quantum
     * from the same seed, so any provider that disagrees here breaks X-Wing interop.
     */
    @Test
    fun mlKem768_seededKeygenIsDeterministicAcrossProviders() {
        val provider = provider ?: return
        val d = ByteArray(32) { it.toByte() }
        val z = ByteArray(32) { (32 + it).toByte() }

        val first = provider.mlKem768KeyPairFromSeed(d, z)
        val second = provider.mlKem768KeyPairFromSeed(d, z)
        assertContentEquals(first.publicKey, second.publicKey, "seeded keygen must be deterministic")
        assertContentEquals(
            hex("0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"),
            provider.sha256(first.publicKey),
            "seeded keygen public key must match the cross-provider golden value",
        )

        // The seeded keypair must be usable end to end.
        val encapsulation = provider.mlKem768Encapsulate(first.publicKey)
        assertContentEquals(
            encapsulation.sharedSecret,
            provider.mlKem768Decapsulate(first.privateKey, encapsulation.ciphertext),
        )
    }

    /** FIPS 203 implicit rejection: a tampered ciphertext yields a *different* secret, not a crash. */
    @Test
    fun mlKem768_tamperedCiphertextImplicitlyRejects()  {
        val provider = provider ?: return
        val keyPair = provider.mlKem768GenerateKeyPair()
        val encapsulation = provider.mlKem768Encapsulate(keyPair.publicKey)

        val tampered = encapsulation.ciphertext.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        val recovered = provider.mlKem768Decapsulate(keyPair.privateKey, tampered)
        assertEquals(32, recovered.size)
        assertFalse(
            recovered.contentEquals(encapsulation.sharedSecret),
            "tampered ciphertext must not decapsulate to the honest secret",
        )
    }

    // ── ML-DSA-65 ─────────────────────────────────────────────────────────────────────────────

    @Test
    fun mlDsa65_signVerifyRoundTrip() {
        val provider = provider ?: return
        val keys = provider.mlDsa65GenerateKeyPair()
        assertEquals(HybridSignature.MLDSA65_PUBLIC_SIZE, keys.publicKey.size, "ML-DSA-65 public key size")

        val message = "membership log entry".encodeToByteArray()
        val signature = provider.mlDsa65Sign(keys.privateKey, message)
        assertEquals(HybridSignature.MLDSA65_SIGNATURE_SIZE, signature.size, "ML-DSA-65 signature size")

        assertTrue(provider.mlDsa65Verify(keys.publicKey, message, signature))
        assertFalse(provider.mlDsa65Verify(keys.publicKey, "other".encodeToByteArray(), signature))

        val flipped = signature.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertFalse(provider.mlDsa65Verify(keys.publicKey, message, flipped))
        assertFalse(provider.mlDsa65Verify(provider.mlDsa65GenerateKeyPair().publicKey, message, signature))
    }

    /** Malformed attacker-supplied inputs must answer `false`, never crash. */
    @Test
    fun mlDsa65_malformedInputsRejectQuietly() {
        val provider = provider ?: return
        val keys = provider.mlDsa65GenerateKeyPair()
        val message = "m".encodeToByteArray()
        val signature = provider.mlDsa65Sign(keys.privateKey, message)

        assertFalse(provider.mlDsa65Verify(ByteArray(7), message, signature), "truncated public key")
        assertFalse(provider.mlDsa65Verify(keys.publicKey, message, ByteArray(7)), "truncated signature")
    }

    // ── Hybrid signatures (strict-AND) ────────────────────────────────────────────────────────

    @Test
    fun hybridSignature_bothLegsRequired() {
        val provider = provider ?: return
        val keys = HybridSignature.generateKeyPair(provider)
        assertEquals(HybridSignature.PUBLIC_KEY_SIZE, keys.publicKey.size)

        val message = "device identity".encodeToByteArray()
        val signature = HybridSignature.sign(provider, keys.privateKey, message)
        assertEquals(HybridSignature.SIGNATURE_SIZE, signature.size)
        assertTrue(HybridSignature.verify(provider, keys.publicKey, message, signature))

        // Corrupt the classical leg only — the AND must fail.
        val brokenEd = signature.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertFalse(HybridSignature.verify(provider, keys.publicKey, message, brokenEd))

        // Corrupt the post-quantum leg only — the AND must fail.
        val brokenDsa = signature.copyOf().also {
            it[HybridSignature.ED25519_SIGNATURE_SIZE] =
                (it[HybridSignature.ED25519_SIGNATURE_SIZE].toInt() xor 0x01).toByte()
        }
        assertFalse(HybridSignature.verify(provider, keys.publicKey, message, brokenDsa))
    }

    // ── X-Wing & Cascade (commonMain constructions over the provider) ─────────────────────────

    @Test
    fun xWing_encapsulateDecapsulateAgree() {
        val provider = provider ?: return
        val keyPair = XWing.generateKeyPair(provider)
        assertEquals(1184 + 32, keyPair.publicKey.size, "X-Wing public key = ML-KEM pk ‖ X25519 pk")

        val encapsulation = XWing.encapsulate(provider, keyPair.publicKey)
        assertEquals(1088 + 32, encapsulation.ciphertext.size, "X-Wing ciphertext = ML-KEM ct ‖ X25519 pk")
        assertEquals(32, encapsulation.sharedSecret.size, "combiner output is a 32-byte SHA3-256 digest")

        val recovered = XWing.decapsulate(provider, keyPair.privateKey, encapsulation.ciphertext)
        assertContentEquals(encapsulation.sharedSecret, recovered, "both sides must derive the same secret")
    }

    @Test
    fun cascade_roundTripsAndFailsClosed() {
        val provider = provider ?: return
        val master = provider.randomBytes(32)
        val plaintext = "Dentist, Tue 14:00".encodeToByteArray()
        val aad = "context-42".encodeToByteArray()

        val blob = Cascade.seal(provider, master, plaintext, aad)
        assertContentEquals(plaintext, Cascade.open(provider, master, blob, aad))

        val tampered = blob.copyOf().also { it[it.lastIndex] = (it[it.lastIndex] + 1).toByte() }
        assertFailsWith<CryptoException> { Cascade.open(provider, master, tampered, aad) }
        assertFailsWith<CryptoException> { Cascade.open(provider, provider.randomBytes(32), blob, aad) }
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
