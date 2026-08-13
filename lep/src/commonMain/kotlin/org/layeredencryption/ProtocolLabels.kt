package org.layeredencryption

/**
 * Every domain-separation label the protocol puts on the wire, in one auditable place.
 *
 * ### These are frozen
 * Each label is an HKDF `info` string, a signature domain separator, or a hash prefix. Changing one
 * changes the key or signature it produces, so two devices that disagree about a single character
 * cannot talk to each other. A label edit is therefore a wire break: existing pairings are orphaned
 * and every device has to pair again. Add new labels freely; change an existing one only as a
 * deliberate, versioned break.
 *
 * ### Why they live here rather than beside their users
 * They were previously private constants scattered across a dozen files, with a test that held its
 * own hand-written copy of the list. That test could not fail when the code drifted, and once
 * didn't: a rename sweep quietly changed a suffix, and the test was rewritten from the changed
 * state, enshrining the drift instead of catching it. Now [ALL] is the single source of truth, the
 * freeze test compares its own literal expectations against [ALL] itself, and any label that is
 * added, removed or edited breaks that test until someone acknowledges it.
 */
internal object ProtocolLabels {

    /** Cascade inner layer (ChaCha20-Poly1305) key derivation. */
    const val LAYER_CHACHA = "v1/layer-chacha"

    /** Cascade outer layer (AES-256-GCM) key derivation. */
    const val LAYER_AES = "v1/layer-aes"

    /** In-person pairing transcript hash. */
    const val TRANSCRIPT = "v1/transcript"

    /** In-person pairing master-key derivation. */
    const val PAIRING = "v1/pairing"

    /**
     * The inviter's SAS commitment.
     *
     * New in v2. Without it the joiner moves last and can recompute the SAS offline until it
     * matches any value it likes, which lets a machine in the middle show both people identical
     * digits. See [org.layeredencryption.pairing.Handshake.sasCommitment].
     */
    const val SAS_COMMITMENT = "v2/sas-commitment"

    /** Derivation of the shared secret from the typed pairing code. */
    const val CODE_SECRET = "v1/code-secret"

    /**
     * Device identity binding signature.
     *
     * v2: the signature became hybrid Ed25519 + ML-DSA-65, and the signed message grew to cover the
     * signing public key as well as the X25519 identity key.
     */
    const val DEVICE_IDENTITY = "v3/device-identity"

    /**
     * Wrapping a context key for one member's device identity.
     *
     * New in v3, and the reason the identity format changed. Rotating the master key means handing
     * the new one to everybody who remains, and after pairing there is no shared per-pair key left
     * to do it with. Wrapping under the identity's X25519 key would have worked and would have been
     * classical-only, so a recorded rotation would fall to a quantum adversary and undo the rest of
     * the protocol's post-quantum work.
     */
    const val MEMBER_KEY_WRAP = "v1/member-key-wrap"

    /** Membership log entry signatures. v2: hybrid Ed25519 + ML-DSA-65. */
    const val MEMBERSHIP = "v2/membership"

    /** Async invite bundle signature. v2: hybrid Ed25519 + ML-DSA-65. */
    const val INVITE_BUNDLE = "v2/invite-bundle"

    /** Async pairing transcript hash. */
    const val TRANSCRIPT_ASYNC = "v1/transcript-async"

    /** Async pairing master-key derivation. */
    const val PAIRING_ASYNC = "v1/pairing-async"

    /** Rendezvous identifier for in-person pairing. */
    const val RENDEZVOUS = "rendezvous/v1"

    /** Rendezvous identifier for async invites. */
    const val RENDEZVOUS_ASYNC = "rendezvous-async/v1"

    /**
     * Context (shared dataset) identifier.
     *
     * v2 changes what the id is derived *from*, not merely its spelling. It used to hash the master
     * key, which tied the calendar's name to a value that now has to rotate: revoking a member
     * generates a new key, and under v1 that renamed the calendar and orphaned every lane. It is
     * now the founding log entry's hash, which never changes.
     *
     * The spelling change rides along. This read "calendar-id" for a long time because that is what
     * shipped and renaming it alone would have orphaned pairings for no gain; since v2 orphans them
     * regardless, the odd name finally goes with it.
     */
    const val CONTEXT_ID = "context-id/v2"

    /** The complete set, for the freeze test to compare against. */
    val ALL: Set<String> = setOf(
        LAYER_CHACHA, LAYER_AES, TRANSCRIPT, PAIRING, CODE_SECRET, SAS_COMMITMENT, DEVICE_IDENTITY,
        MEMBER_KEY_WRAP,
        MEMBERSHIP, INVITE_BUNDLE, TRANSCRIPT_ASYNC, PAIRING_ASYNC, RENDEZVOUS,
        RENDEZVOUS_ASYNC, CONTEXT_ID,
    )
}
