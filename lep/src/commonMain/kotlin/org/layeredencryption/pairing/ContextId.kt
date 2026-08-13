package org.layeredencryption.pairing

import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.CryptoProvider
import org.layeredencryption.membership.MembershipLog

/**
 * The shared context's identifier, derived rather than chosen.
 *
 * `contextId = SHA-256("<vendor>/context-id/v2" ‖ genesisEntryHash)`
 *
 * It has to be derived because every device must arrive at the same value without exchanging it.
 * The id scopes the sync lanes and is bound into the signed sync transcript, so two phones that
 * picked different ids would pair successfully, show matching safety numbers, say they were
 * connected, and then silently refuse every sync afterwards.
 *
 * ### Why not the master key
 * It used to hash the master key, which was fine while that key was permanent. It is not: removing
 * a member rotates it, and under the old derivation that renamed the calendar, orphaning every lane
 * and every chain at exactly the moment the user least wants surprises. A calendar's identity and
 * its current key are different things and are now derived from different values.
 *
 * The founding entry's hash is the natural choice. It is fixed for the calendar's whole life, every
 * member has it as soon as they have the log, and it reveals nothing to anyone who does not.
 */
object ContextId {

    /**
     * Frozen. This one reads "calendar-id" while everything around it says "context", because it
     * is a wire constant: devices paired before the rename derived their id from these exact
     * bytes, and changing it would give them a different id on their next launch and orphan their
     * data. The type is named for what it does; the label is named for what shipped.
     */
    private const val SUFFIX = ProtocolLabels.CONTEXT_ID

    /** The id for the calendar [membershipLog] founds. Throws if the log has no genesis entry. */
    fun forCalendar(
        provider: CryptoProvider,
        membershipLog: MembershipLog,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): String {
        val genesis = membershipLog.genesisHash(provider)
            ?: throw IllegalArgumentException("An empty membership log founds no calendar")
        return derive(provider, genesis, namespace)
    }

    /** Shared derivation, exposed for tests that need to pin the bytes without building a log. */
    internal fun derive(
        provider: CryptoProvider,
        genesisHash: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): String =
        provider.sha256(namespace.label(SUFFIX) + genesisHash).joinToString("") { byte ->
            val value = byte.toInt() and 0xFF
            HEX[value shr 4].toString() + HEX[value and 0x0F]
        }

    private const val HEX = "0123456789abcdef"
}
