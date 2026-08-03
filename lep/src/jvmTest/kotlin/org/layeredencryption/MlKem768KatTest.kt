package org.layeredencryption

import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Deterministic known-answer / regression test for the ML-KEM-768 leg (docs/Protocol.md §5.4).
 *
 * ML-KEM-768 keygen is deterministic in its `(d, z)` seed and encapsulation is deterministic in its
 * message `m` (FIPS 203). By feeding Bouncy Castle a fixed RNG we get reproducible `ek`/`ct`/`ss`
 * outputs and pin them here as a **golden master**. This is a regression guard: if a Bouncy Castle
 * upgrade silently changes ML-KEM behaviour or encoding, these hashes break and force human review.
 *
 * Note: this is *not* a NIST ACVP vector — it pins BC to its own current, self-consistent output.
 * Independently validating BC against the official NIST ACVP JSON (and cross-checking against Kodium)
 * remains on the pre-launch checklist (§5.4 / §5.5).
 */
class MlKem768KatTest {

    /** d = bytes 0..31, z = bytes 32..63 — a fixed keygen seed. */
    private val keygenSeed = ByteArray(64) { it.toByte() }

    /** Fixed encapsulation message m. */
    private val encapsMessage = ByteArray(32) { (100 + it).toByte() }

    @Test
    fun mlKem768_isDeterministicAndConsistent() {
        val (ekA, dkA) = generateKeyPair()
        val (ekB, dkB) = generateKeyPair()
        assertContentEquals(ekA, ekB, "keygen must be deterministic in its seed (ek)")
        assertContentEquals(dkA, dkB, "keygen must be deterministic in its seed (dk)")

        val first = encapsulate(ekA)
        val second = encapsulate(ekA)
        assertContentEquals(first.encapsulation, second.encapsulation, "encaps must be deterministic in m (ct)")
        assertContentEquals(first.sharedSecret, second.sharedSecret, "encaps must be deterministic in m (ss)")

        val recovered = MLKEMExtractor(privateKeyOf(dkA)).extractSecret(first.encapsulation)
        assertContentEquals(first.sharedSecret, recovered, "decaps must recover the encapsulated secret")
    }

    @Test
    fun mlKem768_goldenMasterOutputsAreStable() {
        val (ek, dk) = generateKeyPair()
        val encaps = encapsulate(ek)

        assertEquals(1184, ek.size)
        assertEquals(1088, encaps.encapsulation.size)
        assertEquals(32, encaps.sharedSecret.size)

        assertEquals(EXPECTED_EK_SHA256, sha256Hex(ek), "ML-KEM-768 encapsulation-key output drifted")
        assertEquals(EXPECTED_DK_SHA256, sha256Hex(dk), "ML-KEM-768 decapsulation-key output drifted")
        assertEquals(EXPECTED_CT_SHA256, sha256Hex(encaps.encapsulation), "ML-KEM-768 ciphertext output drifted")
        assertEquals(EXPECTED_SS_HEX, hexOf(encaps.sharedSecret), "ML-KEM-768 shared secret output drifted")
    }

    private data class Encaps(val encapsulation: ByteArray, val sharedSecret: ByteArray)

    private fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val generator = MLKEMKeyPairGenerator()
        generator.init(MLKEMKeyGenerationParameters(FixedRandom(keygenSeed), MLKEMParameters.ml_kem_768))
        val pair = generator.generateKeyPair()
        val ek = (pair.public as MLKEMPublicKeyParameters).encoded
        val dk = (pair.private as MLKEMPrivateKeyParameters).encoded
        return ek to dk
    }

    private fun encapsulate(ek: ByteArray): Encaps {
        val publicKey = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, ek)
        val result = MLKEMGenerator(FixedRandom(encapsMessage)).generateEncapsulated(publicKey as AsymmetricKeyParameter)
        return Encaps(result.encapsulation, result.secret)
    }

    private fun privateKeyOf(dk: ByteArray) = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, dk)

    private fun sha256Hex(data: ByteArray): String = hexOf(MessageDigest.getInstance("SHA-256").digest(data))

    private fun hexOf(data: ByteArray): String = data.joinToString("") { "%02x".format(it) }

    /** A [SecureRandom] that replays fixed bytes, so BC's deterministic ML-KEM inputs are pinned. */
    private class FixedRandom(private val data: ByteArray) : SecureRandom() {
        private var offset = 0
        override fun nextBytes(bytes: ByteArray) {
            require(offset + bytes.size <= data.size) { "FixedRandom exhausted at $offset + ${bytes.size} > ${data.size}" }
            data.copyInto(bytes, destinationOffset = 0, startIndex = offset, endIndex = offset + bytes.size)
            offset += bytes.size
        }
    }

    private companion object {
        // Golden-master hashes captured from Bouncy Castle 1.81; see class doc.
        const val EXPECTED_EK_SHA256 = "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"
        const val EXPECTED_DK_SHA256 = "dac268bde6a8dd238e9887117d6b664e7a7a9350ad6b7c08a948e504809572a5"
        const val EXPECTED_CT_SHA256 = "57fe559432dbb3c5547c73f155820622f7efdd532e4330360a36ebf7d2ddec55"
        const val EXPECTED_SS_HEX = "c5a74110c158acbaf9c01deb86fa6cc10c14533feda54bec1fdd000d61f07e4e"
    }
}
