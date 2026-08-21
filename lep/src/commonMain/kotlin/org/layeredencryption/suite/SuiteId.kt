package org.layeredencryption.suite

import kotlin.jvm.JvmInline

/**
 * The stable numeric identifier of a [ProtocolSuite] (docs/POST_QUANTUM_HARDENING_AND_MIGRATION.md,
 * "Recommended suite model").
 *
 * A suite id names a complete, frozen cryptographic construction — algorithms, encodings, sizes,
 * and domain-separation labels together. Ids are assigned once and never reused or renumbered:
 * they will eventually appear inside signed transcripts, KDF contexts, and AEAD associated data,
 * where a renumbering is a silent protocol break. An id unknown to [SuiteRegistry] fails closed.
 *
 * Ids `0xFF00`–`0xFFFE` are reserved for test suites and will never be assigned to a production
 * suite; `0xFFFF` is permanently invalid, kept free for fail-closed tests.
 */
@JvmInline
value class SuiteId(val value: UShort) {
    override fun toString(): String = "SuiteId(${value})"

    companion object {
        /**
         * Suite 1: exactly the construction shipped today, frozen — see [Suite1] for the full
         * contract. The name records the protocol family and the year the freeze was cut.
         */
        val LEP_HYBRID_2026: SuiteId = SuiteId(1u)
    }
}
