package org.layeredencryption

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/**
 * Known-answer tests pinning [XWing] to the official draft-connolly-cfrg-xwing-kem-10 vectors
 * ([XWingTestVectors]), on every platform's provider.
 *
 * These are the tests the assessment found missing: a self-round-trip cannot notice a
 * construction where both sides repeat the same mistake — the previous label-first combiner
 * round-tripped happily for months. Only an external reference breaks that symmetry, so this
 * suite drives key generation and decapsulation with the draft's bytes, and separately proves
 * the combiner's field ordering against the official shared secret (including proving the *old*
 * ordering wrong). Derandomised encapsulation is covered on the JVM by `XWingDerandTest`, where
 * the provider's randomness is injectable.
 */
class XWingKatTest {

    private val provider: CryptoProvider? = runCatching { platformCryptoProvider() }.getOrNull()

    @Test
    fun keyGeneration_matchesTheDraftVectors() {
        val provider = provider ?: return
        for ((index, vector) in XWingTestVectors.ALL.withIndex()) {
            val keyPair = XWing.keyPairFromSeed(provider, hex(vector.seed))
            assertContentEquals(hex(vector.pk), keyPair.publicKey, "vector $index public key")
            assertContentEquals(hex(vector.seed), keyPair.privateKey, "vector $index secret key is the seed")
        }
    }

    @Test
    fun decapsulation_matchesTheDraftVectors() {
        val provider = provider ?: return
        for ((index, vector) in XWingTestVectors.ALL.withIndex()) {
            assertContentEquals(
                hex(vector.ss),
                XWing.decapsulate(provider, hex(vector.seed), hex(vector.ct)),
                "vector $index shared secret",
            )
        }
    }

    /**
     * Rebuilds the combiner input from vector 0's raw components using provider primitives, and
     * checks every ordering against the *official* shared secret: the draft's ordering (label
     * last) must produce it; the label-first ordering this codebase used to ship, and any
     * omission or swap, must not.
     */
    @Test
    fun combiner_isTheDraftOrderingAndNothingElse() {
        val provider = provider ?: return
        val vector = XWingTestVectors.ALL.first()
        val officialSs = hex(vector.ss)
        val label = byteArrayOf(0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c)

        // expandDecapsulationKey(seed), by hand, from the primitives.
        val expanded = provider.shake256(hex(vector.seed), 96)
        val mlkem = provider.mlKem768KeyPairFromSeed(
            expanded.copyOfRange(0, 32),
            expanded.copyOfRange(32, 64),
        )
        val skX = expanded.copyOfRange(64, 96)
        val pkX = provider.x25519PublicKey(skX)

        val ct = hex(vector.ct)
        val ctM = ct.copyOfRange(0, 1088)
        val ctX = ct.copyOfRange(1088, 1120)
        val ssM = provider.mlKem768Decapsulate(mlkem.privateKey, ctM)
        val ssX = provider.x25519(skX, ctX)

        assertContentEquals(
            officialSs,
            provider.sha3_256(ssM + ssX + ctX + pkX + label),
            "the draft combiner is SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)",
        )
        assertFalse(
            officialSs.contentEquals(provider.sha3_256(label + ssM + ssX + ctX + pkX)),
            "label-first — the construction this codebase used to ship — is NOT X-Wing",
        )
        assertFalse(
            officialSs.contentEquals(provider.sha3_256(ssM + ssX + ctX + label)),
            "omitting pk_X must not verify",
        )
        assertFalse(
            officialSs.contentEquals(provider.sha3_256(ssX + ssM + ctX + pkX + label)),
            "swapping the shared-secret legs must not verify",
        )
        assertFalse(
            officialSs.contentEquals(provider.sha3_256(ssM + ssX + pkX + ctX + label)),
            "swapping ct_X and pk_X must not verify",
        )
    }

    @Test
    fun wrongLengths_areRejected() {
        val provider = provider ?: return
        val vector = XWingTestVectors.ALL.first()
        assertFailsWith<IllegalArgumentException> { XWing.keyPairFromSeed(provider, ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { XWing.decapsulate(provider, ByteArray(64), hex(vector.ct)) }
        assertFailsWith<IllegalArgumentException> { XWing.decapsulate(provider, hex(vector.seed), ByteArray(1088)) }
        assertFailsWith<IllegalArgumentException> { XWing.encapsulate(provider, ByteArray(1184)) }
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
