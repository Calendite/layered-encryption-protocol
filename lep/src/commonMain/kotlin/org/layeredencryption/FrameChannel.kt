package org.layeredencryption

/**
 * A bidirectional, ordered channel of length-delimited byte frames — the abstraction every LAN
 * session speaks over (Calendar_Sharing.md §7.2).
 *
 * The TCP implementation lives per platform (Ktor raw sockets); tests use an in-memory pipe. All
 * protocol logic is written against this interface, so the ceremony and sync code are byte-identical
 * regardless of what carries the frames.
 *
 * Contract:
 * - Frames arrive whole and in order, or not at all.
 * - [receive] throws when the peer closes or the frame exceeds [MAX_FRAME_BYTES] — fail closed,
 *   never a truncated frame.
 * - No TLS by design: every payload is already cascade-encrypted or protocol-authenticated, and the
 *   sync session adds a signed challenge before any data moves (§7.2).
 */
interface FrameChannel {
    suspend fun send(frame: ByteArray)

    suspend fun receive(): ByteArray

    fun close()

    companion object {
        /**
         * Upper bound on a single frame. Generous enough for an initial full-calendar ops exchange
         * (envelopes are ~kilobytes each), small enough that garbage on the port cannot ask us to
         * allocate unbounded memory.
         */
        const val MAX_FRAME_BYTES: Int = 16 * 1024 * 1024
    }
}
