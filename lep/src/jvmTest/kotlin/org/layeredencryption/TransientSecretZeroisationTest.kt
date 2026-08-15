package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.invite.AsyncInviter
import org.layeredencryption.invite.AsyncJoiner
import org.layeredencryption.invite.AsyncJoinerResponse
import org.layeredencryption.invite.ResponseOutcome
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * RT-05: transient derived secrets are zeroed on every exit, not left for the garbage collector.
 * The probe wraps the provider and keeps a reference to every output that is secret by
 * construction — KEM shared secrets, DH outputs, seed expansions, ML-KEM private keys, HKDF
 * derivations. After a failed (or completed) operation, everything captured must read as zeros
 * unless the API deliberately handed that exact array to the caller.
 */
class TransientSecretZeroisationTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()
    private val now = 1_000_000L
    private val expiry = now + 7 * 86_400L

    /** Captures every provider output that is secret by construction. */
    private class SecretCapturingProvider(private val delegate: CryptoProvider) : CryptoProvider by delegate {
        val secrets = mutableListOf<ByteArray>()

        override fun shake256(data: ByteArray, outputLength: Int): ByteArray =
            delegate.shake256(data, outputLength).also { secrets += it }

        override fun sha3_256(data: ByteArray): ByteArray =
            delegate.sha3_256(data).also { secrets += it }

        override fun x25519(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray =
            delegate.x25519(privateKey, peerPublicKey).also { secrets += it }

        override fun x25519GenerateKeyPair(): KeyPair =
            delegate.x25519GenerateKeyPair().also { secrets += it.privateKey }

        override fun mlKem768Decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray =
            delegate.mlKem768Decapsulate(privateKey, ciphertext).also { secrets += it }

        override fun mlKem768KeyPairFromSeed(d: ByteArray, z: ByteArray): KeyPair =
            delegate.mlKem768KeyPairFromSeed(d, z).also { secrets += it.privateKey }

        override fun mlKem768Encapsulate(peerPublicKey: ByteArray): KemEncapsulation =
            delegate.mlKem768Encapsulate(peerPublicKey).also { secrets += it.sharedSecret }

        override fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray =
            delegate.hkdfSha256(ikm, salt, info, length).also { secrets += it }

        /** Every captured secret must be zeroed, except arrays deliberately still owned by the caller. */
        fun assertAllZeroed(except: List<ByteArray> = emptyList()) {
            assertTrue(secrets.isNotEmpty(), "the probe captured nothing — the test is not testing anything")
            for (secret in secrets) {
                if (except.any { it === secret }) continue
                assertTrue(
                    secret.all { it == 0.toByte() },
                    "a derived secret of ${secret.size} bytes survived unzeroed",
                )
            }
        }
    }

    // ── The retest's named path: async inviter, invalid joiner MAC ───────────────────────────

    @Test
    fun asyncInviterZeroesEverythingDerivedForAnInvalidMac() {
        val capturing = SecretCapturingProvider(provider)
        val inviter = AsyncInviter.create(capturing, DeviceKeys.generate(provider), nowEpochSeconds = now, expiryEpochSeconds = expiry)
        val response = AsyncJoiner(provider, DeviceKeys.generate(provider)).onBundle(inviter.link, inviter.bundle, now)

        // Same valid ceremony bytes, wrong MAC: the inviter derives the full KEM + DH + HKDF
        // chain before it can know, and must scrub all of it on the way out.
        val tampered = AsyncJoinerResponse(
            kemCiphertext = response.kemCiphertext,
            deviceIdentityS = response.deviceIdentityS,
            linkProofMac = response.linkProofMac,
            joinerMac = ByteArray(32),
        )

        capturing.secrets.clear()
        assertIs<ResponseOutcome.Invalid>(inviter.onResponse(tampered, now))
        capturing.assertAllZeroed()
    }

    @Test
    fun asyncInviterZeroesInputsAndKeepsOnlyTheClaimKeyForAValidResponse() {
        val capturing = SecretCapturingProvider(provider)
        val inviter = AsyncInviter.create(capturing, DeviceKeys.generate(provider), nowEpochSeconds = now, expiryEpochSeconds = expiry)
        val response = AsyncJoiner(provider, DeviceKeys.generate(provider)).onBundle(inviter.link, inviter.bundle, now)

        capturing.secrets.clear()
        assertIs<ResponseOutcome.Claimed>(inviter.onResponse(response, now))

        // Exactly one derived secret may survive a successful claim: the async key, whose
        // ownership transferred into the session. Everything else fed it and died.
        val survivors = capturing.secrets.filter { secret -> secret.any { it != 0.toByte() } }
        assertTrue(survivors.size == 1, "expected only the claim key to survive, got ${survivors.size} survivors")
    }

    // ── The synchronous handshake's failure path ─────────────────────────────────────────────

    @Test
    fun syncInviterZeroesEverythingDerivedForAWrongCode() {
        val capturing = SecretCapturingProvider(provider)
        val inviter = Inviter(capturing, DeviceKeys.generate(provider), PairingCode.generate(provider))
        val joiner = Joiner(provider, DeviceKeys.generate(provider), PairingCode.generate(provider))

        val response = joiner.onInviterHello(inviter.hello())

        capturing.secrets.clear()
        assertFailsWith<PairingException> { inviter.onJoinerResponse(response) }
        capturing.assertAllZeroed()
    }

    // ── X-Wing leaves no component secrets behind ────────────────────────────────────────────

    @Test
    fun xwingZeroesSeedExpansionsAndComponentSecrets() {
        val capturing = SecretCapturingProvider(provider)

        val keyPair = XWing.generateKeyPair(capturing)
        capturing.assertAllZeroed()

        val encapsulation = XWing.encapsulate(capturing, keyPair.publicKey)
        capturing.assertAllZeroed(except = listOf(encapsulation.sharedSecret))

        val decapsulated = XWing.decapsulate(capturing, keyPair.privateKey, encapsulation.ciphertext)
        capturing.assertAllZeroed(except = listOf(encapsulation.sharedSecret, decapsulated))

        // The hygiene must not have cost correctness: both sides still agree.
        assertContentEquals(encapsulation.sharedSecret, decapsulated)
    }
}
