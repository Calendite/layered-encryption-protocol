package org.layeredencryption.suite

/**
 * How suite-aware code turns a parsed [SuiteId] into a [ProtocolSuite].
 *
 * Production code always uses the default: the fixed, compile-time [SuiteRegistry]. The interface
 * exists so that multi-suite logic — negotiation selection, mixed-suite membership verification,
 * versioned envelopes — can be exercised in tests before a second real suite is standardized,
 * without giving the library any runtime registration API (docs/POST_QUANTUM_HARDENING_AND_MIGRATION.md
 * forbids inventing "Suite 2" ahead of a reviewed standard).
 *
 * Trust note: supplying a custom resolver is equivalent to patching the library. It can only
 * weaken the caller's own device, never a peer's — every suite-dependent byte a resolver
 * influences is bound into MAC'd or signed material that the peer independently validates
 * against *its* resolver.
 */
interface SuiteResolver {
    /** The suite registered under [id], or [UnsupportedSuiteException] — there is no fallback. */
    fun require(id: SuiteId): ProtocolSuite

    fun contains(id: SuiteId): Boolean

    /** Every id this resolver answers for; negotiation builds capability offers from it. */
    val known: Set<SuiteId>
}
