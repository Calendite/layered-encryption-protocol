package org.layeredencryption.invite

import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.CryptoProvider

/**
 * The rendezvous id for an async invite (Async_Invites_Spec.md §2.3):
 *
 * ```
 * rid_async = SHA-256( "calendite/rendezvous-async/v1" ‖ secret_bytes )
 * ```
 *
 * The distinct label guarantees async slots can never collide with live-code slots.
 *
 * Hashing hides the secret from anyone who has not seen the link, but `rid_async` itself is an
 * **offline** verifier: the relay sees it and can test candidate secrets locally, with no rate
 * limit or interaction. Security therefore rests entirely on the secret's entropy —
 * 256 bits in the `A2` link, after the 64-bit `A1` secret proved searchable at GPU-farm scale.
 */
object AsyncRendezvous {

    private const val SUFFIX = ProtocolLabels.RENDEZVOUS_ASYNC

    fun id(
        provider: CryptoProvider,
        secret: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray = provider.sha256(namespace.label(SUFFIX) + secret)
}
