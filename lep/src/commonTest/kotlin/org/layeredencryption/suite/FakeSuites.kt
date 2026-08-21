package org.layeredencryption.suite

import org.layeredencryption.CryptoProvider

/**
 * Test suites for exercising multi-suite logic — negotiation selection, mixed-suite membership
 * verification, versioned envelopes — before a second real suite is standardized (the migration
 * brief forbids inventing one). Ids come from the reserved test range `0xFF00`–`0xFFFE`.
 *
 * Every fake is **Suite-1 size-compatible by construction** (pure delegation): Phase 1's wire
 * formats keep Suite-1 field sizes, and differently-sized suites are exactly what the deferred
 * entry-format v2 work exists for.
 */
internal object FakeSuites {

    val FAKE_ID = SuiteId(0xFFFEu)
    val SHIFTED_ID = SuiteId(0xFFFDu)

    /** A stronger-ranked suite that is cryptographically identical to Suite 1. */
    fun fakeSuite(id: SuiteId = FAKE_ID, strength: Int = 2, name: String = "TEST_FAKE"): ProtocolSuite =
        object : ProtocolSuite {
            override val id: SuiteId = id
            override val name: String = name
            override val strength: Int = strength
            override val kem: SuiteKem = Suite1.kem
            override val signature: SuiteSignature = Suite1.signature
            override val aead: SuiteAead = Suite1.aead
        }

    /**
     * A suite whose signatures are domain-shifted: [SuiteSignature.sign]/[SuiteSignature.verify]
     * prefix the message with one byte, so material signed under this suite genuinely fails to
     * verify when misrouted through Suite 1 (and vice versa). This is what makes mixed-suite
     * routing tests meaningful rather than vacuous — with pure delegation, wrong-era routing
     * would still verify.
     */
    fun domainShiftedFakeSuite(id: SuiteId = SHIFTED_ID, strength: Int = 2): ProtocolSuite =
        object : ProtocolSuite {
            override val id: SuiteId = id
            override val name: String = "TEST_SHIFTED"
            override val strength: Int = strength
            override val kem: SuiteKem = Suite1.kem
            override val aead: SuiteAead = Suite1.aead
            override val signature: SuiteSignature = object : SuiteSignature by Suite1.signature {
                private val shift = byteArrayOf(id.value.toByte())
                override fun sign(provider: CryptoProvider, privateKey: ByteArray, message: ByteArray): ByteArray =
                    Suite1.signature.sign(provider, privateKey, shift + message)
                override fun verify(provider: CryptoProvider, publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
                    Suite1.signature.verify(provider, publicKey, shift + message, signature)
            }
        }

    /** A resolver answering for Suite 1 plus [suites]; everything else fails closed as always. */
    fun resolverWith(vararg suites: ProtocolSuite): SuiteResolver = object : SuiteResolver {
        private val all = (listOf(Suite1) + suites).associateBy { it.id }
        override fun require(id: SuiteId): ProtocolSuite = all[id] ?: throw UnsupportedSuiteException(id)
        override fun contains(id: SuiteId): Boolean = id in all
        override val known: Set<SuiteId> get() = all.keys
    }
}
