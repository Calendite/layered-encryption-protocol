package org.layeredencryption.pairing

import org.layeredencryption.CryptoProvider

/**
 * The rendezvous identifier both devices meet at (docs/Protocol.md §6.3).
 *
 * `rid = SHA-256("calendite/rendezvous/v1" ‖ S)`, where `S` is the canonical pairing code. The
 * inviter advertises at `rid` (mDNS name in Phase 1, mailbox slot in Phase 2); the joiner derives
 * the same `rid` from the entered code and fetches the bundle. Because `rid` is a hash of the code,
 * it reveals nothing about the code and is meaningless to anyone who doesn't already hold it.
 */
object Rendezvous {

    private val LABEL = "calendite/rendezvous/v1".encodeToByteArray()

    /** Derives the rendezvous id from a canonical pairing code (`S`). */
    fun id(provider: CryptoProvider, canonicalCode: String): ByteArray =
        provider.sha256(LABEL + canonicalCode.encodeToByteArray())
}
