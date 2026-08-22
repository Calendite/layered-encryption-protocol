package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.suite.SuiteId
import org.layeredencryption.suite.SuiteRegistry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Key material is validated where it enters the library (LEP-R13), and the suite registry cannot
 * be mutated through a returned collection (LEP-R15).
 *
 * These are misuse-hardening rather than attack surfaces: they close the gap between what the
 * construction's security argument assumes about its inputs and what the types actually enforce.
 */
class KeyMaterialValidationTest {

    private val provider = BouncyCastleCryptoProvider()

    // ── Context keys ──────────────────────────────────────────────────────────────────────────

    @Test
    fun everyEpochKeyMustBeExactlyThirtyTwoBytes() {
        assertFailsWith<IllegalArgumentException>("empty") { EpochKeys.founding(ByteArray(0)) }
        assertFailsWith<IllegalArgumentException>("short") { EpochKeys.founding(ByteArray(31)) }
        assertFailsWith<IllegalArgumentException>("long") { EpochKeys.founding(ByteArray(33)) }
        EpochKeys.founding(ByteArray(32)) // the only legal size
    }

    @Test
    fun rotationAndImportValidateToo() {
        val keys = EpochKeys.founding(provider.randomBytes(32))
        assertFailsWith<IllegalArgumentException>("rotation") { keys.withNextEpoch(ByteArray(16)) }
        assertFailsWith<IllegalArgumentException>("import") {
            EpochKeys.of(mapOf(0 to provider.randomBytes(32), 1 to ByteArray(8)))
        }
        // The decoder already refused wrong-size keys; it still does.
        val truncated = FrameWriter().putBytes(intToBytes(0)).putBytes(ByteArray(31)).toByteArray()
        assertNull(EpochKeys.deserialise(truncated))
    }

    @Test
    fun theCascadeRefusesAnythingButAUniformThirtyTwoByteKey() {
        val plaintext = "op".encodeToByteArray()
        // A passphrase is the hazard this guards: HKDF would turn it into perfectly well-formed
        // layer keys carrying none of the entropy the construction assumes.
        val passphrase = "correct horse battery staple".encodeToByteArray()
        assertFailsWith<IllegalArgumentException>("passphrase") {
            Cascade.seal(provider, passphrase, plaintext)
        }
        assertFailsWith<IllegalArgumentException>("empty") { Cascade.seal(provider, ByteArray(0), plaintext) }
        assertFailsWith<IllegalArgumentException>("short") { Cascade.seal(provider, ByteArray(31), plaintext) }

        val key = provider.randomBytes(32)
        val sealed = Cascade.seal(provider, key, plaintext)
        assertFailsWith<IllegalArgumentException>("open is guarded too") {
            Cascade.open(provider, ByteArray(31), sealed)
        }
        assertEquals("op", Cascade.open(provider, key, sealed).decodeToString())
    }

    // ── Registry immutability ─────────────────────────────────────────────────────────────────

    @Test
    fun theKnownSuiteSetCannotBeMutatedThroughItsReturnedView() {
        val known = SuiteRegistry.known
        assertTrue(SuiteId.LEP_HYBRID_2026 in known)

        // Kotlin's Set is read-only at the interface, not immutable at runtime: a JVM caller can
        // attempt exactly this cast against a live key view. It must not reach the registry.
        @Suppress("UNCHECKED_CAST")
        runCatching { (known as MutableSet<SuiteId>).clear() }

        assertTrue(SuiteRegistry.contains(SuiteId.LEP_HYBRID_2026), "the registry must be unchanged")
        assertTrue(SuiteId.LEP_HYBRID_2026 in SuiteRegistry.known)
        assertEquals(1, SuiteRegistry.known.size)
        SuiteRegistry.require(SuiteId.LEP_HYBRID_2026) // still resolvable
    }
}
