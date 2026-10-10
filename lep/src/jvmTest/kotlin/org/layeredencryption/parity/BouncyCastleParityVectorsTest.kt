package org.layeredencryption.parity

import org.bouncycastle.crypto.digests.SHAKEDigest
import org.layeredencryption.BouncyCastleCryptoProvider
import org.layeredencryption.CryptoProvider
import org.layeredencryption.XWing
import java.io.File
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Writes and guards lep/test-vectors/bouncycastle-parity.txt: Bouncy Castle's behaviour on
 * thousands of inputs, recorded so other providers (the macOS one first) can be held to it
 * byte for byte. See [ParityVectors] for the format.
 *
 * Regenerate after a deliberate change (a new case, a Bouncy Castle upgrade) with
 * `./gradlew :lep:jvmTest -Plep.parity.regenerate --tests '*BouncyCastleParityVectorsTest*'`,
 * then rerun every provider's parity test against the new file.
 */
class BouncyCastleParityVectorsTest {

    private val file = File(System.getProperty("lep.parity.vectors") ?: error("lep.parity.vectors is not set"))

    /** The committed file is exactly what this Bouncy Castle produces: no drift, no hand edits. */
    @Test
    fun committedVectorsAreWhatBouncyCastleProduces() {
        val generated = generate()
        if (System.getProperty("lep.parity.regenerate") == "true") {
            file.parentFile.mkdirs()
            file.writeText(generated)
            println("Wrote ${generated.lineSequence().count { it.isNotBlank() && !it.startsWith("#") }} parity cases to $file")
            return
        }
        assertTrue(file.exists(), "$file is missing; regenerate it (see the class doc)")
        val committed = file.readText()
        if (committed != generated) {
            val first = committed.lines().zip(generated.lines()).indexOfFirst { (a, b) -> a != b }
            fail("$file differs from what Bouncy Castle produces now (first at line ${first + 1}); regenerate it if the change is deliberate")
        }
    }

    /** The runner, replaying the file against Bouncy Castle itself, finds nothing: the control for every other provider's run. */
    @Test
    fun bouncyCastlePassesItsOwnVectors() {
        val report = ParityRunner.run(file.readText()) { replay -> BouncyCastleCryptoProvider(ReplayingRandom(replay)) }
        println("Bouncy Castle parity: ${report.cases} cases, ${report.byOp.size} operations")
        assertEquals(emptyList(), report.failures)
        assertTrue(report.cases > 2000, "suspiciously few cases: ${report.cases}")
    }

    /** A single wrong byte in a result is reported: the runner is not vacuous. */
    @Test
    fun aTamperedResultIsReported() {
        val text = file.readText()
        val line = text.lines().first { it.startsWith("sha256|") }
        val tampered = line.dropLast(1) + (if (line.last() == '0') '1' else '0')
        val report = ParityRunner.run(text.replace(line, tampered)) { replay -> BouncyCastleCryptoProvider(ReplayingRandom(replay)) }
        assertEquals(1, report.failures.size, report.failures.joinToString("\n"))
    }

    /** A provider that draws its randomness differently is reported even where its output could not show it. */
    @Test
    fun aDifferentDrawPatternIsReported() {
        val text = file.readText().lines().filter { it.startsWith("mlkem_keygen|") }.joinToString("\n")
        val report = ParityRunner.run(text) { replay ->
            // Draws d and z as one 64-byte request instead of two 32-byte ones: same bytes, other pattern.
            object : CryptoProvider by BouncyCastleCryptoProvider(ReplayingRandom(replay)) {
                override fun mlKem768GenerateKeyPair() =
                    replay.nextBytes(64).let { mlKem768KeyPairFromSeed(it.copyOfRange(0, 32), it.copyOfRange(32, 64)) }
            }
        }
        assertEquals(report.cases, report.failures.size, "a provider drawing 64 bytes at once passed")
    }
}

/** A [SecureRandom] that serves a case's recorded draws (and checks their sizes) through [Replay]. */
class ReplayingRandom(private val replay: Replay) : SecureRandom() {
    override fun nextBytes(bytes: ByteArray) {
        replay.nextBytes(bytes.size).copyInto(bytes)
    }
}

/** Records every draw a Bouncy Castle provider makes, from a seeded stream. */
private class RecordingRandom(private val source: Shake) : SecureRandom() {
    val draws = mutableListOf<ByteArray>()
    override fun nextBytes(bytes: ByteArray) {
        source.fill(bytes)
        draws += bytes.copyOf()
    }
}

/** A deterministic byte stream: SHAKE256 of a label, squeezed incrementally. Inputs only. */
private class Shake(label: String) {
    private val digest = SHAKEDigest(256).apply { label.encodeToByteArray().let { update(it, 0, it.size) } }
    fun fill(bytes: ByteArray) {
        if (bytes.isNotEmpty()) digest.doOutput(bytes, 0, bytes.size)
    }
    fun bytes(n: Int) = ByteArray(n).also(::fill)
    fun int(bound: Int): Int = ((bytes(4).fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }) % bound).toInt()
}

private const val HEADER = """# Bouncy Castle parity vectors (lep/test-vectors/README.md). Generated by
# BouncyCastleParityVectorsTest from fixed seeds: do not edit by hand, regenerate.
# Format: op|draws|args…|result. See ParityVectors.kt.
"""

/** Builds the whole file. Deterministic: same Bouncy Castle, same file. */
internal fun generate(): String {
    val input = Shake("lep parity vectors v1: inputs")
    val randomness = Shake("lep parity vectors v1: randomness")
    val lines = StringBuilder(HEADER)
    // Makes the keys, ciphertexts and signatures that later cases take as inputs; seeded, so the
    // file is the same on every run.
    val bc = BouncyCastleCryptoProvider(RecordingRandom(Shake("lep parity vectors v1: helper")))

    fun case(op: String, vararg args: String) {
        val recorder = RecordingRandom(randomness)
        val provider = BouncyCastleCryptoProvider(recorder)
        val outcome = runCatching { ParityVectors.operations.getValue(op)(provider, args.toList()) }
        val result = ParityVectors.describe(op, outcome, bc::sha256)
        lines.append(ParityCase(0, op, recorder.draws, args.toList(), result).serialize()).append('\n')
    }
    fun section(title: String) { lines.append("\n# ── ").append(title).append('\n') }
    fun hex(b: ByteArray) = b.toHex()
    fun flip(b: ByteArray, bit: Int): ByteArray = b.copyOf().also { it[bit / 8] = (it[bit / 8].toInt() xor (1 shl (bit % 8))).toByte() }
    fun flipRandom(b: ByteArray) = flip(b, input.int(b.size * 8))

    section("randomBytes")
    for (n in listOf(0, 1, 2, 12, 16, 31, 32, 33, 64, 100, 1000)) case("random", "$n")

    section("SHA-256: every length across the first two blocks, then boundaries and large inputs")
    for (n in 0..130) case("sha256", hex(input.bytes(n)))
    for (n in listOf(183, 184, 191, 192, 255, 256, 257, 511, 512, 513, 1000, 4095, 4096, 4097, 65536)) case("sha256", hex(input.bytes(n)))
    for ((n, seed) in listOf(1_048_583 to 1, 5_000_011 to 2)) case("sha256_pattern", "$n", "$seed")

    section("SHA3-256: every length across the first rate block (136), then boundaries and large inputs")
    for (n in 0..140) case("sha3_256", hex(input.bytes(n)))
    for (n in listOf(271, 272, 273, 407, 408, 409, 1000, 4096, 65536)) case("sha3_256", hex(input.bytes(n)))
    for ((n, seed) in listOf(1_048_583 to 3, 5_000_011 to 4)) case("sha3_256_pattern", "$n", "$seed")

    section("SHAKE256: input and output lengths across rate boundaries")
    val shakeOut = listOf(0, 1, 31, 32, 33, 64, 96, 135, 136, 137, 271, 272, 273, 1000, 2400)
    for (n in listOf(0, 1, 32, 64, 135, 136, 137, 272, 1000)) for (out in shakeOut) case("shake256", hex(input.bytes(n)), "$out")
    case("shake256_pattern", "1048583", "5", "64")
    case("shake256_pattern", "3", "6", "100000")
    case("shake256", hex(input.bytes(32)), "-1")

    section("HMAC-SHA256: key lengths either side of the 64-byte block, data across the block")
    for (k in listOf(0, 1, 16, 31, 32, 33, 63, 64, 65, 100, 131, 200)) for (d in listOf(0, 1, 55, 56, 63, 64, 65, 200)) {
        case("hmac_sha256", hex(input.bytes(k)), hex(input.bytes(d)))
    }
    case("hmac_sha256_pattern", hex(input.bytes(32)), "1048583", "7")

    section("HKDF-SHA256: salts (null, empty, short, long), info, every output boundary up to 255 blocks")
    for (salt in listOf<ByteArray?>(null, ByteArray(0), input.bytes(13), input.bytes(32), input.bytes(80))) {
        for (len in listOf(0, 1, 31, 32, 33, 42, 64, 82, 255 * 32)) {
            case("hkdf_sha256", hex(input.bytes(22)), salt?.let(::hex) ?: "-", hex(input.bytes(10)), "$len")
        }
    }
    for (ikm in listOf(0, 1, 32, 80)) for (info in listOf(0, 1, 80, 300)) case("hkdf_sha256", hex(input.bytes(ikm)), "-", hex(input.bytes(info)), "32")
    case("hkdf_sha256", hex(input.bytes(32)), "-", "", "${255 * 32 + 1}")
    case("hkdf_sha256", hex(input.bytes(32)), "-", "", "-1")

    for ((name, seal, open) in listOf(Triple("ChaCha20-Poly1305", "chacha_seal", "chacha_open"), Triple("AES-GCM", "aes_seal", "aes_open"))) {
        val keySizes = if (seal == "aes_seal") listOf(16, 24, 32) else listOf(32)
        section("$name: plaintext and AAD lengths, then every way to break an open")
        for (pt in (0..70) + listOf(127, 128, 129, 255, 256, 257, 1000, 4096)) {
            val key = input.bytes(keySizes[pt % keySizes.size])
            val nonce = input.bytes(12)
            val plaintext = input.bytes(pt)
            val aad = input.bytes(listOf(0, 1, 13, 16, 64)[pt % 5])
            case(seal, hex(key), hex(nonce), hex(plaintext), hex(aad))
            val sealed = (if (seal == "aes_seal") bc.aes256GcmSeal(key, nonce, plaintext, aad) else bc.chaCha20Poly1305Seal(key, nonce, plaintext, aad))
            case(open, hex(key), hex(nonce), hex(sealed), hex(aad))
            if (pt % 3 == 0) {
                case(open, hex(key), hex(nonce), hex(flipRandom(sealed)), hex(aad))
                case(open, hex(key), hex(nonce), hex(flip(sealed, sealed.size * 8 - 1)), hex(aad))
                case(open, hex(key), hex(flipRandom(nonce)), hex(sealed), hex(aad))
                case(open, hex(flipRandom(key)), hex(nonce), hex(sealed), hex(aad))
                case(open, hex(key), hex(nonce), hex(sealed), hex(aad + byteArrayOf(0)))
                case(open, hex(key), hex(nonce), hex(sealed.copyOf(sealed.size - 1)), hex(aad))
            }
        }
        case(seal + "_pattern", hex(input.bytes(32)), hex(input.bytes(12)), "1048583", "8", hex(input.bytes(16)))
        for (n in listOf(0, 1, 15)) case(open, hex(input.bytes(32)), hex(input.bytes(12)), hex(input.bytes(n)), "")
        for (k in listOf(0, 1, 15, 16, 17, 24, 31, 33, 64)) {
            case(seal, hex(input.bytes(k)), hex(input.bytes(12)), hex(input.bytes(20)), "")
            case(open, hex(input.bytes(k)), hex(input.bytes(12)), hex(input.bytes(36)), "")
        }
        for (n in listOf(0, 1, 8, 11, 13, 16, 24, 32, 64)) {
            val key = input.bytes(32)
            case(seal, hex(key), hex(input.bytes(n)), hex(input.bytes(20)), hex(input.bytes(5)))
        }
    }

    section("X25519: generation, public keys for arbitrary scalars, agreement, low-order and non-canonical points")
    repeat(24) { case("x25519_keygen") }
    val specialScalars = listOf(ByteArray(32), ByteArray(32) { -1 }, ByteArray(32).also { it[0] = 1 }, ByteArray(32).also { it[31] = 0x80.toByte() })
    for (s in specialScalars + List(30) { input.bytes(32) }) case("x25519_public", hex(s))
    for (n in listOf(0, 31)) case("x25519_public", hex(input.bytes(n)))
    case("x25519_public", hex(input.bytes(64)))
    repeat(40) { case("x25519", hex(input.bytes(32)), hex(bc.x25519GenerateKeyPair().publicKey)) }
    repeat(20) { case("x25519", hex(input.bytes(32)), hex(input.bytes(32))) }
    val lowOrder = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    for (point in lowOrder) repeat(2) { case("x25519", hex(input.bytes(32)), point) }
    for ((k, p) in listOf(31 to 32, 32 to 31, 33 to 32, 32 to 33, 64 to 64)) case("x25519", hex(input.bytes(k)), hex(input.bytes(p)))

    section("Ed25519: generation, deterministic signatures, and verification of every malformed shape")
    repeat(24) { case("ed25519_keygen") }
    val edKeys = List(8) { bc.ed25519GenerateKeyPair() }
    for (n in listOf(0, 1, 2, 31, 32, 33, 63, 64, 65, 111, 112, 113, 127, 128, 129, 255, 1000, 4096)) {
        case("ed25519_sign", hex(edKeys[n % 8].privateKey), hex(input.bytes(n)))
    }
    case("ed25519_sign_pattern", hex(edKeys[0].privateKey), "1048583", "9")
    case("ed25519_sign", hex(edKeys[1].privateKey + input.bytes(32)), hex(input.bytes(10)))
    case("ed25519_sign", hex(input.bytes(31)), hex(input.bytes(10)))
    val curveOrder = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010".hexToBytes()
    fun addLe(a: ByteArray, b: ByteArray): ByteArray {
        val out = ByteArray(32); var carry = 0
        for (i in 0 until 32) { val s = (a[i].toInt() and 0xFF) + (b[i].toInt() and 0xFF) + carry; out[i] = s.toByte(); carry = s shr 8 }
        return out
    }
    val smallOrderEd = listOf(
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )
    for (i in 0 until 40) {
        val key = edKeys[i % 8]
        val message = input.bytes(i * 3)
        val signature = bc.ed25519Sign(key.privateKey, message)
        case("ed25519_verify", hex(key.publicKey), hex(message), hex(signature))
        case("ed25519_verify", hex(key.publicKey), hex(if (message.isEmpty()) byteArrayOf(0) else flipRandom(message)), hex(signature))
        case("ed25519_verify", hex(key.publicKey), hex(message), hex(flipRandom(signature)))
        case("ed25519_verify", hex(flipRandom(key.publicKey)), hex(message), hex(signature))
        if (i < 8) {
            val s = signature.copyOfRange(32, 64)
            case("ed25519_verify", hex(key.publicKey), hex(message), hex(signature.copyOfRange(0, 32) + addLe(s, curveOrder)))
            case("ed25519_verify", hex(key.publicKey), hex(message), hex(signature.copyOfRange(0, 32) + curveOrder))
            case("ed25519_verify", hex(key.publicKey), hex(message), hex(signature.copyOf(63)))
            case("ed25519_verify", hex(key.publicKey), hex(message), hex(signature + byteArrayOf(0)))
        }
    }
    for (point in smallOrderEd) {
        val message = input.bytes(16)
        case("ed25519_verify", point, hex(message), hex(input.bytes(64)))
        case("ed25519_verify", point, hex(message), point + "00".repeat(32))
        case("ed25519_verify", hex(edKeys[0].publicKey), hex(message), point + hex(bc.ed25519Sign(edKeys[0].privateKey, message).copyOfRange(32, 64)))
    }
    for (n in listOf(0, 31, 33, 64)) case("ed25519_verify", hex(input.bytes(n)), hex(input.bytes(5)), hex(input.bytes(64)))

    section("ML-KEM-768: generation, seeded generation, encapsulation, decapsulation and implicit rejection")
    repeat(12) { case("mlkem_keygen") }
    repeat(12) { case("mlkem_seed", hex(input.bytes(32)), hex(input.bytes(32))) }
    for ((d, z) in listOf(31 to 32, 32 to 33, 0 to 0)) case("mlkem_seed", hex(input.bytes(d)), hex(input.bytes(z)))
    val kemKeys = List(6) { bc.mlKem768GenerateKeyPair() }
    for (i in 0 until 18) {
        val key = kemKeys[i % 6]
        case("mlkem_enc", hex(key.publicKey))
        val enc = bc.mlKem768Encapsulate(key.publicKey)
        case("mlkem_dec", hex(key.privateKey), hex(enc.ciphertext))
        case("mlkem_dec", hex(key.privateKey), hex(flipRandom(enc.ciphertext)))
        case("mlkem_dec", hex(kemKeys[(i + 1) % 6].privateKey), hex(enc.ciphertext))
    }
    run {
        val key = kemKeys[0]
        val ct = bc.mlKem768Encapsulate(key.publicKey).ciphertext
        val pk = key.publicKey
        case("mlkem_enc", hex(pk.copyOf().also { it[0] = -1; it[1] = (it[1].toInt() or 0x0F).toByte() }))
        case("mlkem_enc", hex(pk.copyOf().also { it[1150] = -1; it[1151] = -1 }))
        for (n in listOf(0, 1183, 1185, 2400)) case("mlkem_enc", hex(input.bytes(n)))
        // dk = dk_pke (1152) || ek (1184) || H(ek) (32) || z (32): break each part.
        for (offset in listOf(0, 1151, 1152, 2335, 2336, 2367, 2368, 2399)) {
            case("mlkem_dec", hex(flip(key.privateKey, offset * 8)), hex(ct))
            case("mlkem_dec", hex(flip(key.privateKey, offset * 8)), hex(flipRandom(ct)))
        }
        for (n in listOf(0, 1087, 1089)) case("mlkem_dec", hex(key.privateKey), hex(input.bytes(n)))
        for (n in listOf(0, 2399, 2401)) case("mlkem_dec", hex(input.bytes(n)), hex(ct))
    }

    section("ML-DSA-65: generation, deterministic signatures, and verification of every malformed shape")
    repeat(8) { case("mldsa_keygen") }
    val dsaKeys = List(4) { bc.mlDsa65GenerateKeyPair() }
    for (n in listOf(0, 1, 32, 64, 135, 136, 137, 1000, 4096)) case("mldsa_sign", hex(dsaKeys[n % 4].privateKey), hex(input.bytes(n)))
    case("mldsa_sign_pattern", hex(dsaKeys[0].privateKey), "1048583", "10")
    for (n in listOf(0, 4031, 4033)) case("mldsa_sign", hex(input.bytes(n)), hex(input.bytes(10)))
    // sk = rho (32) || K (32) || tr (64) || s1 || s2 || t0: break each part.
    for (offset in listOf(0, 32, 64, 128, 300, 768, 1500, 4031)) case("mldsa_sign", hex(flip(dsaKeys[1].privateKey, offset * 8)), hex(input.bytes(20)))
    case("mldsa_sign", hex(dsaKeys[2].privateKey.copyOf().also { it[128] = -1 }), hex(input.bytes(20)))
    for (i in 0 until 12) {
        val key = dsaKeys[i % 4]
        val message = input.bytes(i * 11)
        val signature = bc.mlDsa65Sign(key.privateKey, message)
        case("mldsa_verify", hex(key.publicKey), hex(message), hex(signature))
        case("mldsa_verify", hex(key.publicKey), hex(if (message.isEmpty()) byteArrayOf(0) else flipRandom(message)), hex(signature))
        case("mldsa_verify", hex(key.publicKey), hex(message), hex(flipRandom(signature)))
        case("mldsa_verify", hex(key.publicKey), hex(message), hex(flip(signature, (signature.size - 1 - i) * 8)))
        case("mldsa_verify", hex(flipRandom(key.publicKey)), hex(message), hex(signature))
        if (i < 2) {
            case("mldsa_verify", hex(key.publicKey), hex(message), hex(signature.copyOf(3308)))
            case("mldsa_verify", hex(key.publicKey), hex(message), hex(signature + byteArrayOf(0)))
            case("mldsa_verify", hex(key.publicKey.copyOf(1951)), hex(message), hex(signature))
            case("mldsa_verify", hex(key.publicKey), hex(message), hex(signature.copyOf().also { it.fill(-1, 3309 - 61) }))
            case("mldsa_verify", hex(key.publicKey), hex(message), hex(signature.copyOf().also { it.fill(0, 3309 - 61) }))
        }
    }

    section("Constructions over the primitives: X-Wing, the cascade, hybrid signatures")
    repeat(6) { case("xwing_keygen") }
    repeat(6) { case("xwing_seed", hex(input.bytes(32))) }
    val xKeys = List(3) { XWing.generateKeyPair(bc) }
    for (i in 0 until 6) {
        val key = xKeys[i % 3]
        case("xwing_enc", hex(key.publicKey))
        val enc = XWing.encapsulate(bc, key.publicKey)
        case("xwing_dec", hex(key.privateKey), hex(enc.ciphertext))
        case("xwing_dec", hex(key.privateKey), hex(flipRandom(enc.ciphertext)))
    }
    for (n in listOf(0, 1, 100, 4096)) {
        val key = input.bytes(32)
        val aad = input.bytes(n % 50)
        case("cascade_seal", hex(key), hex(input.bytes(n)), hex(aad))
        val blob = org.layeredencryption.Cascade.seal(bc, key, input.bytes(n), aad)
        case("cascade_open", hex(key), hex(blob), hex(aad))
        case("cascade_open", hex(key), hex(flipRandom(blob)), hex(aad))
    }
    repeat(3) { case("hybrid_keygen") }
    val hKeys = List(2) { org.layeredencryption.HybridSignature.generateKeyPair(bc) }
    for (i in 0 until 4) {
        val key = hKeys[i % 2]
        val message = input.bytes(i * 40)
        case("hybrid_sign", hex(key.privateKey), hex(message))
        val signature = org.layeredencryption.HybridSignature.sign(bc, key.privateKey, message)
        case("hybrid_verify", hex(key.publicKey), hex(message), hex(signature))
        case("hybrid_verify", hex(key.publicKey), hex(message), hex(flip(signature, 8)))
        case("hybrid_verify", hex(key.publicKey), hex(message), hex(flip(signature, (signature.size - 2) * 8)))
    }

    return lines.toString()
}
