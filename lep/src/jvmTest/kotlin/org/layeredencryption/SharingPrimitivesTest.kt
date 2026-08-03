package org.layeredencryption

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** KAT + property tests for the primitives added for pairing: HMAC-SHA256 and Ed25519 (§4.5/§4.6). */
class SharingPrimitivesTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    /** RFC 4231 Test Case 2 (HMAC-SHA256). */
    @Test
    fun hmacSha256_rfc4231Case2() {
        val key = "Jefe".encodeToByteArray()
        val data = "what do ya want for nothing?".encodeToByteArray()
        val expected = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        assertContentEquals(expected, provider.hmacSha256(key, data))
    }

    @Test
    fun sha256_knownAnswer() {
        // FIPS 180-4 SHA-256("abc")
        assertContentEquals(
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            provider.sha256("abc".encodeToByteArray()),
        )
    }

    @Test
    fun ed25519_signsVerifiesAndRejects() {
        val keyPair = provider.ed25519GenerateKeyPair()
        val message = "membership entry".encodeToByteArray()
        val signature = provider.ed25519Sign(keyPair.privateKey, message)

        assertTrue(provider.ed25519Verify(keyPair.publicKey, message, signature), "valid signature must verify")

        val tamperedMessage = "membership entrz".encodeToByteArray()
        assertFalse(provider.ed25519Verify(keyPair.publicKey, tamperedMessage, signature), "wrong message must fail")

        val tamperedSig = signature.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFalse(provider.ed25519Verify(keyPair.publicKey, message, tamperedSig), "tampered signature must fail")

        val other = provider.ed25519GenerateKeyPair()
        assertFalse(provider.ed25519Verify(other.publicKey, message, signature), "wrong key must fail")
    }

    @Test
    fun ed25519_isDeterministicForAKey() {
        val keyPair = provider.ed25519GenerateKeyPair()
        val message = "deterministic".encodeToByteArray()
        assertContentEquals(
            provider.ed25519Sign(keyPair.privateKey, message),
            provider.ed25519Sign(keyPair.privateKey, message),
            "Ed25519 signatures are deterministic in (key, message)",
        )
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
