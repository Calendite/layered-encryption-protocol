package org.layeredencryption.parity

import org.layeredencryption.Cascade
import org.layeredencryption.CryptoException
import org.layeredencryption.CryptoProvider
import org.layeredencryption.HybridSignature
import org.layeredencryption.KemEncapsulation
import org.layeredencryption.KeyPair
import org.layeredencryption.XWing

/**
 * Bouncy Castle parity vectors: what [org.layeredencryption.BouncyCastleCryptoProvider] does,
 * recorded, so another provider can be held to it byte for byte (lep/test-vectors/README.md).
 *
 * The file is written by the JVM generator (`BouncyCastleParityVectorsTest`) and replayed by
 * [ParityRunner] against any provider. One case per line, fields separated by `|`:
 *
 *     op | draws | arg… | result
 *
 * - `draws` is every randomness request the operation made, in order, as comma-separated hex
 *   (`.` for a request of zero bytes): a replaying provider must ask for exactly these sizes in
 *   exactly this order, and gets these bytes.
 * - Each `arg` is hex, `-` for null, or a decimal number where the op takes a length.
 * - `result` is `ok:<hex>[,<hex>…]`, `digest:<sha-256 hex>` (an output too big to store, hashed),
 *   `bool:true|false`, `throws:crypto` ([CryptoException], a fail-closed rejection) or
 *   `throws:error` (any other exception: bad input).
 *
 * Lines starting with `#` are comments.
 */
object ParityVectors {

    /** Every operation a case can name, with how to run it against a provider. */
    val operations: Map<String, (CryptoProvider, List<String>) -> Any> = mapOf(
        "random" to { p, a -> p.randomBytes(a[0].toInt()) },
        "sha256" to { p, a -> p.sha256(a.bytes(0)) },
        "sha256_pattern" to { p, a -> p.sha256(pattern(a[0].toInt(), a[1].toInt())) },
        "sha3_256" to { p, a -> p.sha3_256(a.bytes(0)) },
        "sha3_256_pattern" to { p, a -> p.sha3_256(pattern(a[0].toInt(), a[1].toInt())) },
        "shake256" to { p, a -> p.shake256(a.bytes(0), a[1].toInt()) },
        "shake256_pattern" to { p, a -> p.shake256(pattern(a[0].toInt(), a[1].toInt()), a[2].toInt()) },
        "hmac_sha256" to { p, a -> p.hmacSha256(a.bytes(0), a.bytes(1)) },
        "hmac_sha256_pattern" to { p, a -> p.hmacSha256(a.bytes(0), pattern(a[1].toInt(), a[2].toInt())) },
        "hkdf_sha256" to { p, a -> p.hkdfSha256(a.bytes(0), a.bytesOrNull(1), a.bytes(2), a[3].toInt()) },
        "chacha_seal" to { p, a -> p.chaCha20Poly1305Seal(a.bytes(0), a.bytes(1), a.bytes(2), a.bytes(3)) },
        "chacha_seal_pattern" to { p, a -> p.chaCha20Poly1305Seal(a.bytes(0), a.bytes(1), pattern(a[2].toInt(), a[3].toInt()), a.bytes(4)) },
        "chacha_open" to { p, a -> p.chaCha20Poly1305Open(a.bytes(0), a.bytes(1), a.bytes(2), a.bytes(3)) },
        "aes_seal" to { p, a -> p.aes256GcmSeal(a.bytes(0), a.bytes(1), a.bytes(2), a.bytes(3)) },
        "aes_seal_pattern" to { p, a -> p.aes256GcmSeal(a.bytes(0), a.bytes(1), pattern(a[2].toInt(), a[3].toInt()), a.bytes(4)) },
        "aes_open" to { p, a -> p.aes256GcmOpen(a.bytes(0), a.bytes(1), a.bytes(2), a.bytes(3)) },
        "x25519_keygen" to { p, _ -> p.x25519GenerateKeyPair() },
        "x25519_public" to { p, a -> p.x25519PublicKey(a.bytes(0)) },
        "x25519" to { p, a -> p.x25519(a.bytes(0), a.bytes(1)) },
        "ed25519_keygen" to { p, _ -> p.ed25519GenerateKeyPair() },
        "ed25519_sign" to { p, a -> p.ed25519Sign(a.bytes(0), a.bytes(1)) },
        "ed25519_sign_pattern" to { p, a -> p.ed25519Sign(a.bytes(0), pattern(a[1].toInt(), a[2].toInt())) },
        "ed25519_verify" to { p, a -> p.ed25519Verify(a.bytes(0), a.bytes(1), a.bytes(2)) },
        "mlkem_keygen" to { p, _ -> p.mlKem768GenerateKeyPair() },
        "mlkem_seed" to { p, a -> p.mlKem768KeyPairFromSeed(a.bytes(0), a.bytes(1)) },
        "mlkem_enc" to { p, a -> p.mlKem768Encapsulate(a.bytes(0)) },
        "mlkem_dec" to { p, a -> p.mlKem768Decapsulate(a.bytes(0), a.bytes(1)) },
        "mldsa_keygen" to { p, _ -> p.mlDsa65GenerateKeyPair() },
        "mldsa_sign" to { p, a -> p.mlDsa65Sign(a.bytes(0), a.bytes(1)) },
        "mldsa_sign_pattern" to { p, a -> p.mlDsa65Sign(a.bytes(0), pattern(a[1].toInt(), a[2].toInt())) },
        "mldsa_verify" to { p, a -> p.mlDsa65Verify(a.bytes(0), a.bytes(1), a.bytes(2)) },
        "xwing_keygen" to { p, _ -> XWing.generateKeyPair(p) },
        "xwing_seed" to { p, a -> XWing.keyPairFromSeed(p, a.bytes(0)) },
        "xwing_enc" to { p, a -> XWing.encapsulate(p, a.bytes(0)) },
        "xwing_dec" to { p, a -> XWing.decapsulate(p, a.bytes(0), a.bytes(1)) },
        "cascade_seal" to { p, a -> Cascade.seal(p, a.bytes(0), a.bytes(1), a.bytes(2)) },
        "cascade_open" to { p, a -> Cascade.open(p, a.bytes(0), a.bytes(1), a.bytes(2)) },
        "hybrid_keygen" to { p, _ -> HybridSignature.generateKeyPair(p) },
        "hybrid_sign" to { p, a -> HybridSignature.sign(p, a.bytes(0), a.bytes(1)) },
        "hybrid_verify" to { p, a -> HybridSignature.verify(p, a.bytes(0), a.bytes(1), a.bytes(2)) },
    )

    /** Ops whose output is stored as its SHA-256, being too large to keep in the file. */
    val digestedOperations = setOf(
        "chacha_seal_pattern", "aes_seal_pattern",
    )

    /**
     * A large input described by two numbers instead of stored: [length] bytes where byte i is
     * `(i * 131 + seed * 7 + (i ushr 9)) mod 256`. Deliberately not a hash, so generating it does
     * not depend on any primitive under test.
     */
    fun pattern(length: Int, seed: Int): ByteArray =
        ByteArray(length) { i -> (i * 131 + seed * 7 + (i ushr 9)).toByte() }

    /** The result field for [outcome], in the file's notation. */
    fun describe(op: String, outcome: Result<Any>, sha256: (ByteArray) -> ByteArray): String {
        val value = outcome.getOrElse { error ->
            return if (error is CryptoException) "throws:crypto" else "throws:error"
        }
        if (op in digestedOperations) return "digest:" + sha256(value as ByteArray).toHex()
        return when (value) {
            is Boolean -> "bool:$value"
            is ByteArray -> "ok:" + value.toHex()
            is KeyPair -> "ok:" + value.publicKey.toHex() + "," + value.privateKey.toHex()
            is KemEncapsulation -> "ok:" + value.ciphertext.toHex() + "," + value.sharedSecret.toHex()
            else -> error("unrecordable result type ${value::class}")
        }
    }

    private fun List<String>.bytes(index: Int): ByteArray = this[index].hexToBytes()
    private fun List<String>.bytesOrNull(index: Int): ByteArray? = if (this[index] == "-") null else this[index].hexToBytes()
}

/** One line of the file. */
class ParityCase(val line: Int, val op: String, val draws: List<ByteArray>, val args: List<String>, val result: String) {
    companion object {
        fun parse(line: Int, text: String): ParityCase {
            val fields = text.split('|')
            require(fields.size >= 3) { "line $line: expected op|draws|…|result" }
            val draws = if (fields[1].isEmpty()) emptyList() else fields[1].split(',').map { if (it == ".") ByteArray(0) else it.hexToBytes() }
            return ParityCase(line, fields[0], draws, fields.subList(2, fields.size - 1), fields.last())
        }
    }

    fun serialize(): String =
        (listOf(op, draws.joinToString(",") { if (it.isEmpty()) "." else it.toHex() }) + args + result).joinToString("|")
}

/**
 * Hands out a case's recorded draws, insisting they are requested in the same sizes and order
 * as Bouncy Castle requested them. A provider that draws more, less, or in other sizes produces
 * different keys from the same seed, and fails here even if its output happened to match.
 */
class Replay(private val draws: List<ByteArray>) {
    private var next = 0

    fun nextBytes(size: Int): ByteArray {
        check(next < draws.size) { "drew ${size} bytes more than Bouncy Castle (draw ${next + 1} of ${draws.size})" }
        val draw = draws[next]
        check(draw.size == size) { "draw ${next + 1} asked for $size bytes; Bouncy Castle asked for ${draw.size}" }
        next++
        return draw.copyOf()
    }

    val unused: Int get() = draws.size - next
}

/**
 * A deliberate, documented difference from Bouncy Castle: for cases of [op] whose arguments
 * satisfy [applies], the provider under test is held to [result] instead of the recorded one.
 * Every use is counted, so a test can pin exactly how many cases each covers.
 */
class Divergence(val op: String, val result: String, val reason: String, val applies: (List<String>) -> Boolean)

/** Runs a vector file against a provider and reports every disagreement. */
object ParityRunner {

    class Report(val cases: Int, val byOp: Map<String, Int>, val failures: List<String>, val divergent: Map<Divergence, Int>)

    /**
     * @param providerFor builds the provider under test around a case's [Replay]: its randomness
     * must come from nowhere else.
     */
    fun run(text: String, divergences: List<Divergence> = emptyList(), providerFor: (Replay) -> CryptoProvider): Report {
        val failures = mutableListOf<String>()
        val byOp = mutableMapOf<String, Int>()
        val divergent = divergences.associateWith { 0 }.toMutableMap()
        var cases = 0
        text.lineSequence().forEachIndexed { index, raw ->
            if (raw.isBlank() || raw.startsWith("#")) return@forEachIndexed
            val case = ParityCase.parse(index + 1, raw)
            cases++
            byOp[case.op] = (byOp[case.op] ?: 0) + 1
            val operation = ParityVectors.operations[case.op]
            if (operation == null) {
                failures += "line ${case.line}: unknown op ${case.op}"
                return@forEachIndexed
            }
            val replay = Replay(case.draws)
            val provider = providerFor(replay)
            val outcome = runCatching { operation(provider, case.args) }
            val replayProblem = outcome.exceptionOrNull()?.takeIf { it is IllegalStateException && it.message.orEmpty().contains("Bouncy Castle") }
            val actual = ParityVectors.describe(case.op, outcome, provider::sha256)
            val divergence = divergences.firstOrNull { it.op == case.op && it.applies(case.args) }
            val expected = divergence?.result ?: case.result
            if (divergence != null) divergent[divergence] = divergent.getValue(divergence) + 1
            when {
                replayProblem != null -> failures += "line ${case.line} ${case.op}: ${replayProblem.message}"
                actual != expected -> failures += "line ${case.line} ${case.op}: expected ${expected.abbreviate()}, got ${actual.abbreviate()}" +
                    (outcome.exceptionOrNull()?.let { " (${it::class.simpleName}: ${it.message})" } ?: "")
                replay.unused != 0 && outcome.isSuccess -> failures += "line ${case.line} ${case.op}: left ${replay.unused} of Bouncy Castle's draws unused"
            }
        }
        return Report(cases, byOp, failures, divergent)
    }

    private fun String.abbreviate(): String = if (length <= 120) this else take(100) + "…(${length} chars)"
}

private const val HEX = "0123456789abcdef"

fun ByteArray.toHex(): String = buildString(size * 2) {
    for (b in this@toHex) {
        append(HEX[(b.toInt() shr 4) and 0xF])
        append(HEX[b.toInt() and 0xF])
    }
}

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "odd-length hex" }
    return ByteArray(length / 2) { i -> ((HEX.indexOf(this[2 * i]) shl 4) or HEX.indexOf(this[2 * i + 1])).toByte() }
}
