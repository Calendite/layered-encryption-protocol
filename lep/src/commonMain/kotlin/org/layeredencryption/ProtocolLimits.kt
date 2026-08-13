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

    /** One entry's `wrappedKeys` blob: ~5.3 KB per recipient copy; ~190 copies fit. */
    const val MAX_WRAPPED_KEYS_BYTES = 1024 * 1024

    /** One sealed copy inside a wrapped-keys blob — a cascade-wrapped 32-byte context key. */
    const val MAX_WRAPPED_SEALED_BYTES = 4096

    /** A serialised lane envelope, matching the transport's own frame bound. */
    const val MAX_ENVELOPE_BYTES = FrameChannel.MAX_FRAME_BYTES

    /** A serialised [org.layeredencryption.envelope.EpochKeys] blob: 10 000 framed epoch/key pairs. */
    const val MAX_EPOCH_KEYS_BYTES = 10_000 * (4 + 4 + 4 + 32)
}
