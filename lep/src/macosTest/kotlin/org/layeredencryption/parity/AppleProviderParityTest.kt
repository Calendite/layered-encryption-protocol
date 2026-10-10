@file:OptIn(ExperimentalForeignApi::class)

package org.layeredencryption.parity

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import org.layeredencryption.AppleCryptoProvider
import org.layeredencryption.RandomSource
import platform.posix.SEEK_END
import platform.posix.SEEK_SET
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import platform.posix.fseek
import platform.posix.ftell
import platform.posix.getenv
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Holds [AppleCryptoProvider] to Bouncy Castle byte for byte: replays every case in
 * lep/test-vectors/bouncycastle-parity.txt (recorded on the JVM by BouncyCastleParityVectorsTest)
 * with the recorded randomness, and requires the same bytes, the same accept/reject, the same
 * kind of failure, and the same randomness draws in the same sizes and order.
 *
 * Except for [divergences]: two inputs LEP never produces, where this provider is deliberately
 * stricter than Bouncy Castle. Each is pinned to the exact number of recorded cases it covers.
 */
class AppleProviderParityTest {

    private val divergences = listOf(
        Divergence(
            op = "aes_seal",
            result = "throws:error",
            reason = "AES-GCM nonces of 1-11 bytes: Bouncy Castle derives a counter block from them (GHASH); " +
                "CryptoKit only takes 12 or more. LEP's only AES-GCM caller, Cascade, always uses 12.",
        ) { args -> args[1].length / 2 in 1..11 },
        Divergence(
            op = "mldsa_sign",
            result = "throws:error",
            reason = "An ML-DSA-65 private key that is not 4032 bytes: Bouncy Castle pads or truncates it and signs " +
                "anyway; this provider refuses, rather than sign with a key that is not the one stored.",
        ) { args -> args[0].length / 2 != 4032 && args[0].isNotEmpty() },
    )

    @Test
    fun matchesBouncyCastleOnEveryRecordedCase() {
        val report = ParityRunner.run(readVectors(), divergences) { replay ->
            AppleCryptoProvider(RandomSource { bytes -> replay.nextBytes(bytes.size).copyInto(bytes) })
        }
        println("Apple provider parity: ${report.cases} cases over ${report.byOp.size} operations, ${report.failures.size} disagreements")
        report.byOp.entries.sortedBy { it.key }.forEach { (op, n) -> println("  $op: $n") }
        report.divergent.forEach { (d, n) -> println("  deliberate difference, ${d.op} ($n cases): ${d.reason}") }
        assertTrue(report.cases > 2000, "suspiciously few cases: ${report.cases}")
        assertEquals("", report.failures.joinToString("\n"))
        // Pinned, so a new case cannot quietly fall under a difference: grow these only on purpose.
        assertEquals(listOf(3, 2), divergences.map { report.divergent.getValue(it) })
    }

    /** The control: one wrong byte in a recorded result fails this provider too, so a pass means something. */
    @Test
    fun aTamperedResultIsReported() {
        val text = readVectors()
        val line = text.lines().first { it.startsWith("mldsa_sign|") }
        val tampered = line.dropLast(1) + (if (line.last() == '0') '1' else '0')
        val report = ParityRunner.run(tampered) { replay ->
            AppleCryptoProvider(RandomSource { bytes -> replay.nextBytes(bytes.size).copyInto(bytes) })
        }
        assertEquals(1, report.failures.size, report.failures.joinToString("\n"))
    }

    private fun readVectors(): String {
        val path = getenv("LEP_PARITY_VECTORS")?.toKString() ?: error("LEP_PARITY_VECTORS is not set (lep/build.gradle.kts sets it)")
        val file = fopen(path, "rb") ?: error("cannot open $path")
        try {
            fseek(file, 0, SEEK_END)
            val size = ftell(file).toInt()
            fseek(file, 0, SEEK_SET)
            val bytes = ByteArray(size)
            val read = bytes.usePinned { fread(it.addressOf(0), 1u, size.convert(), file) }
            check(read.toInt() == size) { "short read of $path" }
            return bytes.decodeToString()
        } finally {
            fclose(file)
        }
    }
}
