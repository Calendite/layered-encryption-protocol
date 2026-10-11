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
 */
class AppleProviderParityTest {

    @Test
    fun matchesBouncyCastleOnEveryRecordedCase() {
        val report = ParityRunner.run(readVectors()) { replay ->
            AppleCryptoProvider(RandomSource { bytes -> replay.nextBytes(bytes.size).copyInto(bytes) })
        }
        println("Apple provider parity: ${report.cases} cases over ${report.byOp.size} operations, ${report.failures.size} disagreements")
        report.byOp.entries.sortedBy { it.key }.forEach { (op, n) -> println("  $op: $n") }
        assertTrue(report.cases > 2000, "suspiciously few cases: ${report.cases}")
        assertEquals("", report.failures.joinToString("\n"))
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
