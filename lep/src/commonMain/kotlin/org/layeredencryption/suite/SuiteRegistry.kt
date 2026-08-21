package org.layeredencryption.suite

/**
 * Every [ProtocolSuite] this build of the library knows, indexed by [SuiteId]
 * (docs/POST_QUANTUM_HARDENING_AND_MIGRATION.md, "Recommended suite model").
 *
 * The map is a fixed compile-time constant, deliberately without a registration API: a suite is a
 * reviewed, frozen cryptographic construction shipped with the library, not something application
 * code composes at runtime — a mutable registry would let a dependency quietly answer for a suite
 * id the protocol was supposed to fail closed on. Unknown ids throw [UnsupportedSuiteException],
 * always ([require]): an artifact naming a suite this build cannot run is unreadable by design,
 * never approximated with a fallback.
 *
 * A future standardized successor is added here as a new entry with a new id (see the migration
 * brief's "Suite 2: reserve, but do not invent") — existing entries are never edited or removed
 * while any user may still hold data under them.
 */
object SuiteRegistry {

    private val suites: Map<SuiteId, ProtocolSuite> = listOf<ProtocolSuite>(Suite1)
        .associateBy { it.id }

    /** The suite registered under [id], or [UnsupportedSuiteException] — there is no fallback. */
    fun require(id: SuiteId): ProtocolSuite = suites[id] ?: throw UnsupportedSuiteException(id)

    fun contains(id: SuiteId): Boolean = id in suites

    /** Every registered id, for capability advertisement once Phase 1 adds negotiation. */
    val known: Set<SuiteId> get() = suites.keys
}
