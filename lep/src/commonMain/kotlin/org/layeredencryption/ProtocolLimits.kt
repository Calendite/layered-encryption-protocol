package org.layeredencryption

/**
 * Input-size budgets for the public decoders (LEP-09 retest, issue 9.1), in one auditable place.
 *
 * Every budget is checked *before* field copies are made or cryptography runs, so a transport
 * that accepts a large body cannot turn it into large allocations here. [FrameChannel.MAX_FRAME_BYTES]
 * is the outermost transport bound; these are the message-specific bounds inside it, and
 * relay/HTTP/WebSocket transports should enforce the same numbers while streaming, before
 * buffering a full message.
 */
internal object ProtocolLimits {

    /**
     * A serialised membership log (also the variable field of the pairing `InviterComplete`).
     * Real logs are a handful of entries at ~11 KB each plus wrapped keys; this is generous
     * headroom, not an expected size.
     */
    const val MAX_MEMBERSHIP_LOG_BYTES = 4 * 1024 * 1024

    /**
     * One entry's `wrappedKeys` blob: ~5.2 KB per recipient copy, and the recipient-count limit
     * is derived from this budget in `WrappedKeys` so the two can never disagree.
     */
    const val MAX_WRAPPED_KEYS_BYTES = 1024 * 1024

    /**
     * The most devices a context may have active at once (LEP-R4).
     *
     * This is a **protocol constant, deliberately not a per-application setting**: it is a
     * membership *verification* rule, so two devices that disagreed about it would disagree
     * about whether a log is valid — a split-brain far worse than the limit being wrong.
     *
     * Why a cap exists at all: rotation and revocation must wrap the fresh context key once per
     * remaining member, and that blob has its own [MAX_WRAPPED_KEYS_BYTES] budget. Suite 1 fits
     * 202 copies, while a log of keyless `ADD`s could hold far more members — so without a cap a
     * context could grow into a state where an ordinary one-member revocation cannot produce a
     * blob its own parser accepts. Emergency revocation failing because the group is too large
     * is the worst possible time to discover a limit.
     *
     * 64 is chosen to be generous for the shared-calendar model this protocol serves (a large
     * household with several devices each) while leaving a wide margin under every supported
     * suite's wrapping capacity.
     */
    const val MAX_ACTIVE_MEMBERS = 64

    /** A serialised lane envelope, matching the transport's own frame bound. */
    const val MAX_ENVELOPE_BYTES = FrameChannel.MAX_FRAME_BYTES

    /** A serialised [org.layeredencryption.envelope.EpochKeys] blob: 10 000 framed epoch/key pairs. */
    const val MAX_EPOCH_KEYS_BYTES = 10_000 * (4 + 4 + 4 + 32)
}
