package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Retest §6: transient secrets die on *exceptional* paths too. The probe throws instead of
 * performing the N-th secret-producing provider operation — for every N — and asserts that
 * everything derived before the fault was zeroed. Run to completion (N past the end), the same
 * assertion holds after the owning session is destroyed, so the invariant is uniform: no
 * captured secret survives, however the sequence ends.
 */
class ExceptionalPathZeroisationTest {

    private val plain: CryptoProvider = BouncyCastleCryptoProvider()

    /** Captures every secret-by-construction output; throws instead of performing op [throwAt]. */
    private class FaultInjectingProvider(
        private val delegate: CryptoProvider,
        private val throwAt: Int,
    ) : CryptoProvider by delegate {
        val secrets = mutableListOf<ByteArray>()
        var operations = 0
            private set

        private fun <T> gate(produce: () -> T, capture: (T) -> ByteArray?): T {
            if (++operations == throwAt) throw CryptoException("injected fault at operation $operations")
            val result = produce()
            capture(result)?.let { secrets += it }
            return result
        }

        override fun shake256(data: ByteArray, outputLength: Int): ByteArray =
            gate({ delegate.shake256(data, outputLength) }) { it }

        override fun sha3_256(data: ByteArray): ByteArray =
            gate({ delegate.sha3_256(data) }) { it }

        override fun x25519(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray =
            gate({ delegate.x25519(privateKey, peerPublicKey) }) { it }

        override fun x25519GenerateKeyPair(): KeyPair =
            gate({ delegate.x25519GenerateKeyPair() }) { it.privateKey }

        override fun mlKem768Decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray =
            gate({ delegate.mlKem768Decapsulate(privateKey, ciphertext) }) { it }

        override fun mlKem768KeyPairFromSeed(d: ByteArray, z: ByteArray): KeyPair =
            gate({ delegate.mlKem768KeyPairFromSeed(d, z) }) { it.privateKey }

        override fun mlKem768Encapsulate(peerPublicKey: ByteArray): KemEncapsulation =
            gate({ delegate.mlKem768Encapsulate(peerPublicKey) }) { it.sharedSecret }

        override fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray =
            gate({ delegate.hkdfSha256(ikm, salt, info, length) }) { it }

        fun assertAllZeroed(except: List<ByteArray> = emptyList()) {
            for (secret in secrets) {
                if (except.any { it === secret }) continue
                assertTrue(
                    secret.all { it == 0.toByte() },
                    "a derived secret of ${secret.size} bytes survived a fault at operation $throwAt",
                )
            }
        }
    }

    /** Runs [ceremony] with a fault at every operation index, and once with none. */
    private fun forEveryFault(ceremony: (FaultInjectingProvider) -> List<ByteArray>) {
        val counting = FaultInjectingProvider(plain, throwAt = Int.MAX_VALUE)
        val survivors = ceremony(counting)
        counting.assertAllZeroed(except = survivors)
        assertTrue(counting.operations > 0, "the probe observed nothing — the test is not testing")

        for (n in 1..counting.operations) {
            val injecting = FaultInjectingProvider(plain, throwAt = n)
            runCatching { ceremony(injecting) }
            injecting.assertAllZeroed()
        }
    }

    @Test
    fun xwingDecapsulationLeaksNothingWhereverTheProviderFails() {
        val keyPair = XWing.generateKeyPair(plain)
        val encapsulation = XWing.encapsulate(plain, keyPair.publicKey)
        forEveryFault { provider ->
            val secret = runCatching { XWing.decapsulate(provider, keyPair.privateKey, encapsulation.ciphertext) }
            listOfNotNull(secret.getOrNull())
        }
    }

    @Test
    fun xwingEncapsulationLeaksNothingWhereverTheProviderFails() {
        val keyPair = XWing.generateKeyPair(plain)
        forEveryFault { provider ->
            val result = runCatching { XWing.encapsulate(provider, keyPair.publicKey) }
            listOfNotNull(result.getOrNull()?.sharedSecret)
        }
    }

    @Test
    fun syncInviterLeaksNothingWhereverTheProviderFails() {
        forEveryFault { provider ->
            val code = PairingCode.generate(plain)
            val inviter = Inviter(provider, DeviceKeys.generate(plain), code)
            try {
                val response = Joiner(plain, DeviceKeys.generate(plain), code).onInviterHello(inviter.hello())
                inviter.onJoinerResponse(response)
            } finally {
                inviter.destroy()
            }
            emptyList()
        }
    }

    @Test
    fun syncJoinerLeaksNothingWhereverTheProviderFails() {
        forEveryFault { provider ->
            val code = PairingCode.generate(plain)
            val inviter = Inviter(plain, DeviceKeys.generate(plain), code)
            val joiner = Joiner(provider, DeviceKeys.generate(plain), code)
            try {
                val response = joiner.onInviterHello(inviter.hello())
                joiner.onInviterConfirm(inviter.onJoinerResponse(response))
            } finally {
                joiner.destroy()
            }
            emptyList()
        }
    }
}
