package org.layeredencryption

import dev.diagnostics.LogTag

/**
 * The protocol's subsystems, as its diagnostics name them — one tag per area an integrator might
 * need to follow on its own. Public so an application's log viewer can filter by them.
 *
 * The protocol emits through `dev.diagnostics.Diagnostics`, which is **inert until the
 * application installs a sink** and lambda-gated so no message is ever built when nothing is
 * listening. Two rules govern every emission here:
 *
 * 1. **No key material, ever.** Not at debug, not in developer builds: developer logs persist for
 *    days, stream in plaintext over a LAN, and get exported into files attached to bug reports.
 *    Counts, outcomes, stages, identifiers-already-on-the-wire — never keys, secrets, or
 *    plaintext. `DiagnosticSecrecyTest` enforces this by running full ceremonies with a
 *    recording sink and asserting none of the run's secrets appears in any emission.
 * 2. **Failures name their reason, successes name their shape.** The point is that a field
 *    report of "pairing failed" becomes "whose story stops at which line".
 */
enum class LepTag(override val tag: String) : LogTag {
    /** The live pairing ceremony: hello → response → confirm → SAS → complete. */
    PAIRING("LepPairing"),

    /** Async invites: create/resume, bundle, response, claim, approval, delivery. */
    INVITE("LepInvite"),

    /** Lane envelopes: sealing, the replay gate, refusals and their reasons. */
    ENVELOPE("LepEnvelope"),

    /** The membership log: verification failures, reconciliation, fork resolution. */
    MEMBERSHIP("LepMembership"),

    /** Freshness watermarks: what was refused and why. */
    FRESHNESS("LepFreshness"),

    /** The sealed-file stores: commits, corruption, rollback detection. */
    STORAGE("LepStorage"),
}
