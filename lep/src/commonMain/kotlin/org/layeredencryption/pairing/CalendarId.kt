package org.layeredencryption.pairing

import org.layeredencryption.CryptoProvider

/**
 * The shared calendar's identifier, derived rather than chosen.
 *
 * `calendarId = SHA-256("calendite/calendar-id/v1" ‖ masterKey)`
 *
 * It has to be derived because both devices must arrive at the same value without exchanging it.
 * The id scopes the sync lanes and is bound into the signed sync transcript, so two phones that
 * picked different ids would pair successfully, show matching safety numbers, say they were
 * connected, and then silently refuse every sync afterwards.
 *
 * Being a hash of the master key it reveals nothing: anyone who could invert it already holds the
 * key and does not need the id. It is stable for the life of the pairing, which is what lets lanes
 * survive a restart.
 *
 * **This derivation is permanent.** Changing it would give already-paired devices a different id on
 * their next launch, which would orphan their lanes and stop them syncing with each other.
 */
object CalendarId {

    private val LABEL = "calendite/calendar-id/v1".encodeToByteArray()

    fun derive(provider: CryptoProvider, masterKey: ByteArray): String =
        provider.sha256(LABEL + masterKey).joinToString("") { byte ->
            val value = byte.toInt() and 0xFF
            HEX[value shr 4].toString() + HEX[value and 0x0F]
        }

    private const val HEX = "0123456789abcdef"
}
