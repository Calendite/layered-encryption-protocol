package org.layeredencryption.pairing

import org.layeredencryption.FrameChannel

/**
 * Drives the pairing ceremony (docs/Protocol.md §6.3) over a [FrameChannel].
 *
 * The protocol logic lives entirely in [Inviter]/[Joiner] — this file only ferries their messages
 * and gates on the humans. Steps 2–7 are byte-identical in every phase (§6.3); over LAN, the
 * inviter's phone *is* the mailbox: it listens on the socket and its `hello` is the posted bundle.
 *
 * ```
 * inviter                          joiner
 *   send InviterHello ──────────────▶ recv
 *   recv ◀────────────── send JoinerResponse       (code-keyed MAC verified at the inviter)
 *   send InviterConfirm ────────────▶ recv          (code-keyed MAC verified at the joiner)
 *   [human: SAS]                      [human: SAS]
 *   recv ◀────────────── send SasConfirmed
 *   send InviterComplete ───────────▶ recv → unwrap master key
 * ```
 *
 * Key release is gated on **both** humans: the inviter's own `confirmSas` *and* the joiner's
 * `SasConfirmed` frame must both pass before the wrapped master key is sent. A mismatch on either
 * side closes the channel; the other side surfaces the closure as a failed pairing.
 */
object PairingFerry {

    /**
     * Runs the inviting side over an accepted [channel]. Returns the context master key once the
     * ceremony completes. [confirmSas] shows the 6-digit SAS to this device's human.
     */
    suspend fun runInviter(
        channel: FrameChannel,
        inviter: Inviter,
        confirmSas: suspend (String) -> Boolean,
    ): ByteArray {
        try {
            channel.send(PairingWire.encode(inviter.hello()))
            val confirm = inviter.onJoinerResponse(PairingWire.decodeJoinerResponse(channel.receive()))
            channel.send(PairingWire.encode(confirm))

            val sas = inviter.shortAuthString ?: throw PairingException("SAS unavailable after handshake")
            if (!confirmSas(sas)) throw PairingException("SAS rejected on the inviting device")
            PairingWire.decodeSasConfirmed(channel.receive()) // the joiner's human confirmed too

            channel.send(PairingWire.encode(inviter.complete()))
            return inviter.masterKey()
        } finally {
            channel.close()
        }
    }

    /**
     * Runs the joining side over a connected [channel]. Returns the recovered context master key.
     */
    suspend fun runJoiner(
        channel: FrameChannel,
        joiner: Joiner,
        confirmSas: suspend (String) -> Boolean,
    ): ByteArray {
        try {
            val response = joiner.onInviterHello(PairingWire.decodeInviterHello(channel.receive()))
            channel.send(PairingWire.encode(response))
            joiner.onInviterConfirm(PairingWire.decodeInviterConfirm(channel.receive()))

            val sas = joiner.shortAuthString ?: throw PairingException("SAS unavailable after handshake")
            if (!confirmSas(sas)) throw PairingException("SAS rejected on the joining device")
            channel.send(PairingWire.encodeSasConfirmed())

            joiner.onInviterComplete(PairingWire.decodeInviterComplete(channel.receive()))
            return joiner.masterKey()
        } finally {
            channel.close()
        }
    }
}
