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
 * The distinct label guarantees async slots can never collide with live-code slots. Like the live
 * `rid`, it is a hash of the secret, so it reveals nothing and enumeration is online-only.
 */
object AsyncRendezvous {

    private const val SUFFIX = ProtocolLabels.RENDEZVOUS_ASYNC

    fun id(
        provider: CryptoProvider,
        secret: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray = provider.sha256(namespace.label(SUFFIX) + secret)
}
