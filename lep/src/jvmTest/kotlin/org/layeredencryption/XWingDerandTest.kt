package org.layeredencryption

import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * The encapsulation half of the draft-10 KATs: `EncapsulateDerand(pk, eseed)`.
 *
 * [XWing.encapsulate] draws its randomness in the draft's `eseed` order — the ML-KEM message
 * first, the X25519 ephemeral scalar second — so a provider whose RNG replays `eseed` must
 * reproduce the official ciphertext and shared secret exactly. This also pins the Bouncy Castle
 * internals the seeding relies on (draw sizes and order): if a BC upgrade changes them, this
 * fails loudly instead of diverging silently.
 *
 * JVM-only because only [BouncyCastleCryptoProvider] has injectable randomness; the Wasm/noble
 * side of the same vectors is covered by `XWingKatTest`'s keygen and decapsulation halves.
 */
class XWingDerandTest {

    @Test
    fun encapsulation_reproducesTheDraftVectorsWhenDerandomised() {
        for ((index, vector) in XWingTestVectors.ALL.withIndex()) {
            val provider = BouncyCastleCryptoProvider(ReplaySecureRandom(hex(vector.eseed)))
            val encapsulation = XWing.encapsulate(provider, hex(vector.pk))
            assertContentEquals(hex(vector.ct), encapsulation.ciphertext, "vector $index ciphertext")
            assertContentEquals(hex(vector.ss), encapsulation.sharedSecret, "vector $index shared secret")
        }
    }

    private class ReplaySecureRandom(private val data: ByteArray) : SecureRandom() {
        private var offset = 0
        override fun nextBytes(bytes: ByteArray) {
            require(offset + bytes.size <= data.size) { "eseed exhausted at $offset + ${bytes.size}" }
            data.copyInto(bytes, destinationOffset = 0, startIndex = offset, endIndex = offset + bytes.size)
            offset += bytes.size
        }
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
