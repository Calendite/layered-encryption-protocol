package org.layeredencryption.pairing

import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameChannel
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.suite.SuiteRegistry
import org.layeredencryption.suite.SuiteResolver

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
 *
 * ### Two flows, never mixed
 * [runInviter]/[runJoiner] are the explicit legacy Suite 1 flow — its bytes are frozen.
 * [runNegotiatedInviter]/[runNegotiatedJoiner] prefix one suite-negotiation round trip
 * ([SuiteNegotiator]) and then run the same ceremony suite-routed with the v2 transcript. A
 * failed negotiation throws and closes the channel; nothing here ever retries the other flow —
 * silent fallback is exactly what the negotiation exists to prevent.
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
    ): ByteArray = ferryInviter(channel, inviter, confirmSas)

    /**
     * Runs the joining side over a connected [channel]. Returns the recovered context master key.
     */
    suspend fun runJoiner(
        channel: FrameChannel,
        joiner: Joiner,
        confirmSas: suspend (String) -> Boolean,
    ): ByteArray = ferryJoiner(channel, joiner, confirmSas)

    /**
     * The negotiated inviting side: sends the suite offer, validates the accept, then runs the
     * ceremony under the selected suite. Throws [PairingException] (channel closed) on any
     * negotiation failure — a legacy session is never constructed as a fallback.
     */
    suspend fun runNegotiatedInviter(
        channel: FrameChannel,
        provider: CryptoProvider,
        device: DeviceKeys,
        code: PairingCode,
        existing: ExistingCalendar? = null,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
        policy: PairingSuitePolicy = PairingSuitePolicy(),
        confirmSas: suspend (String) -> Boolean,
    ): ByteArray {
        val context = try {
            val negotiation = SuiteNegotiator.beginInviter(provider, resolver, policy)
            channel.send(negotiation.offerFrame)
            negotiation.onAccept(channel.receive())
        } catch (e: Throwable) {
            channel.close()
            throw e
        }
        return ferryInviter(channel, Inviter(provider, device, code, existing, namespace, context), confirmSas)
    }

    /**
     * The negotiated joining side: expects the suite offer as the first frame (a legacy hello is
     * rejected — the negotiated flow never auto-detects legacy), answers with its accept, then
     * runs the ceremony under the selected suite.
     */
    suspend fun runNegotiatedJoiner(
        channel: FrameChannel,
        provider: CryptoProvider,
        device: DeviceKeys,
        code: PairingCode,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
        policy: PairingSuitePolicy = PairingSuitePolicy(),
        confirmSas: suspend (String) -> Boolean,
    ): ByteArray {
        val context = try {
            val negotiation = SuiteNegotiator.respond(channel.receive(), provider, resolver, policy)
            channel.send(negotiation.acceptFrame)
            negotiation.context
        } catch (e: Throwable) {
            channel.close()
            throw e
        }
        return ferryJoiner(channel, Joiner(provider, device, code, namespace, context), confirmSas)
    }

    /** The ceremony body, shared verbatim by the legacy and negotiated inviter entry points. */
    private suspend fun ferryInviter(
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
            val confirmation = inviter.confirmSas() // the human gate: issues the token complete() requires
            PairingWire.decodeSasConfirmed(channel.receive()) // the joiner's human confirmed too

            channel.send(PairingWire.encode(inviter.complete(confirmation)))
            return inviter.masterKey()
        } finally {
            // Terminal on every path: success already scrubbed inside complete() (idempotent),
            // and a thrown MAC mismatch, rejection, or channel failure scrubs here.
            inviter.destroy()
            channel.close()
        }
    }

    /** The ceremony body, shared verbatim by the legacy and negotiated joiner entry points. */
    private suspend fun ferryJoiner(
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
            val confirmation = joiner.confirmSas() // the human gate: issues the token onInviterComplete() requires
            channel.send(PairingWire.encodeSasConfirmed())

            joiner.onInviterComplete(PairingWire.decodeInviterComplete(channel.receive()), confirmation)
            return joiner.masterKey()
        } finally {
            // Terminal on every path, mirroring the inviter side.
            joiner.destroy()
            channel.close()
        }
    }
}
