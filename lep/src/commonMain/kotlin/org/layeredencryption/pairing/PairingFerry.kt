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
 * Every ceremony begins with one suite-negotiation round trip ([SuiteNegotiator]) and then runs
 * the classic five messages suite-routed, with the transcript binding the negotiation frames:
 *
 * ```
 * inviter                          joiner
 *   send SuiteOffer ────────────────▶ recv, select
 *   recv ◀──────────────── send SuiteAccept
 *   send InviterHello ──────────────▶ recv
 *   recv ◀────────────── send JoinerResponse       (code-keyed MAC verified at the inviter)
 *   send InviterConfirm ────────────▶ recv          (code-keyed MAC verified at the joiner)
 *   [human: SAS]                      [human: SAS]
 *   recv ◀────────────── send SasConfirmed
 *   send InviterComplete ───────────▶ recv → unwrap master key
 * ```
 *
 * The protocol logic lives entirely in [Inviter]/[Joiner] — this file only ferries their
 * messages and gates on the humans. Over LAN, the inviter's phone *is* the mailbox: it listens
 * on the socket and its offer/hello are the posted bundle.
 *
 * A device offers exactly the suites it holds identities for (its one identity's suite today);
 * a failed negotiation throws and closes the channel — there is no fallback flow to retry.
 * Key release is gated on **both** humans: the inviter's own `confirmSas` *and* the joiner's
 * `SasConfirmed` frame must both pass before the wrapped master key is sent. A mismatch on
 * either side closes the channel; the other side surfaces the closure as a failed pairing.
 */
object PairingFerry {

    /**
     * Everything a completed ceremony hands the application: the context master key, every
     * epoch key this device now holds, and the verified membership log to persist alongside
     * them. Returned rather than left on the session because the ferry owns the session's
     * lifecycle — by the time this is in hand, the session has already scrubbed itself.
     */
    class PairingResult internal constructor(
        masterKey: ByteArray,
        val calendarKeys: org.layeredencryption.envelope.EpochKeys,
        val membershipLog: org.layeredencryption.membership.MembershipLog,
    ) {
        private val _masterKey = masterKey.copyOf()
        val masterKey: ByteArray get() = _masterKey.copyOf()
    }

    /**
     * Runs the inviting side over an accepted [channel]: negotiates the suite, then runs the
     * ceremony. Returns the context master key once the ceremony completes. [confirmSas] shows
     * the 6-digit SAS to this device's human.
     */
    suspend fun runInviter(
        channel: FrameChannel,
        provider: CryptoProvider,
        device: DeviceKeys,
        code: PairingCode,
        existing: ExistingCalendar? = null,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
        policy: PairingSuitePolicy = PairingSuitePolicy(),
        confirmSas: suspend (String) -> Boolean,
    ): PairingResult {
        val context = try {
            val negotiation = SuiteNegotiator.beginInviter(
                provider, resolver, policy, supported = listOf(device.identity.suiteId),
            )
            channel.send(negotiation.offerFrame)
            negotiation.onAccept(channel.receive())
        } catch (e: Throwable) {
            channel.close()
            throw e
        }
        return ferryInviter(channel, Inviter(provider, device, code, existing, namespace, context), confirmSas)
    }

    /**
     * Runs the joining side over a connected [channel]: expects the suite offer as the first
     * frame, answers with its accept, then runs the ceremony. Returns the recovered context
     * master key.
     */
    suspend fun runJoiner(
        channel: FrameChannel,
        provider: CryptoProvider,
        device: DeviceKeys,
        code: PairingCode,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
        policy: PairingSuitePolicy = PairingSuitePolicy(),
        confirmSas: suspend (String) -> Boolean,
    ): PairingResult {
        val context = try {
            val negotiation = SuiteNegotiator.respond(
                channel.receive(), provider, resolver, policy, supported = listOf(device.identity.suiteId),
            )
            channel.send(negotiation.acceptFrame)
            negotiation.context
        } catch (e: Throwable) {
            channel.close()
            throw e
        }
        return ferryJoiner(channel, Joiner(provider, device, code, namespace, context), confirmSas)
    }

    /** The inviting ceremony body, driving a constructed session. */
    internal suspend fun ferryInviter(
        channel: FrameChannel,
        inviter: Inviter,
        confirmSas: suspend (String) -> Boolean,
    ): PairingResult {
        try {
            channel.send(PairingWire.encode(inviter.hello()))
            val confirm = inviter.onJoinerResponse(
                PairingWire.decodeJoinerResponse(channel.receive(), inviter.suiteResolver),
            )
            channel.send(PairingWire.encode(confirm))

            val sas = inviter.shortAuthString ?: throw PairingException("SAS unavailable after handshake")
            if (!confirmSas(sas)) throw PairingException("SAS rejected on the inviting device")
            val confirmation = inviter.confirmSas() // the human gate: issues the token complete() requires
            PairingWire.decodeSasConfirmed(channel.receive()) // the joiner's human confirmed too

            channel.send(PairingWire.encode(inviter.complete(confirmation)))
            return PairingResult(
                inviter.masterKey(), inviter.calendarKeys(),
                inviter.membershipLog() ?: throw PairingException("Ceremony completed without a log"),
            )
        } finally {
            // Terminal on every path: success already scrubbed inside complete() (idempotent),
            // and a thrown MAC mismatch, rejection, or channel failure scrubs here.
            inviter.destroy()
            channel.close()
        }
    }

    /** The joining ceremony body, driving a constructed session. */
    internal suspend fun ferryJoiner(
        channel: FrameChannel,
        joiner: Joiner,
        confirmSas: suspend (String) -> Boolean,
    ): PairingResult {
        try {
            val response = joiner.onInviterHello(
                PairingWire.decodeInviterHello(channel.receive(), joiner.suiteResolver),
            )
            channel.send(PairingWire.encode(response))
            joiner.onInviterConfirm(PairingWire.decodeInviterConfirm(channel.receive()))

            val sas = joiner.shortAuthString ?: throw PairingException("SAS unavailable after handshake")
            if (!confirmSas(sas)) throw PairingException("SAS rejected on the joining device")
            val confirmation = joiner.confirmSas() // the human gate: issues the token onInviterComplete() requires
            channel.send(PairingWire.encodeSasConfirmed())

            joiner.onInviterComplete(PairingWire.decodeInviterComplete(channel.receive()), confirmation)
            return PairingResult(
                joiner.masterKey(), joiner.calendarKeys(),
                joiner.membershipLog() ?: throw PairingException("Ceremony completed without a log"),
            )
        } finally {
            // Terminal on every path, mirroring the inviter side.
            joiner.destroy()
            channel.close()
        }
    }
}
