package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.InviterConfirm
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.TestNegotiation
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.SasConfirmation
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The low-level pairing sessions enforce the ceremony order themselves (LEP-05), not merely by
 * convention: the master key is released only after the code-keyed MAC, the SAS commitment, and an
 * explicit human confirmation, and every out-of-order call is rejected. A consumer driving the raw
 * [Inviter]/[Joiner] API cannot skip a step the safe [org.layeredencryption.pairing.PairingFerry]
 * would have enforced.
 *
 * `SasConfirmation`'s constructor is `internal`; these tests are in the same module, so they can
 * fabricate a wrong-session token to prove that even one does not bypass the stage gate.
 */
class PairingStateMachineTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private val negotiation = TestNegotiation.pair(provider)

    /** A token no session ever issued — the only way a test can even attempt to forge one. */
    private val forgedToken = SasConfirmation(Any())

    private fun sessions(sameCode: Boolean = true): Pair<Inviter, Joiner> {
        val code = PairingCode.generate(provider)
        val inviter = Inviter(provider, DeviceKeys.generate(provider), code, negotiated = negotiation.first)
        val joiner = Joiner(provider, DeviceKeys.generate(provider), if (sameCode) code else PairingCode.generate(provider), negotiated = negotiation.second)
        return inviter to joiner
    }

    // ── The joiner cannot accept a key without confirming the SAS ─────────────────────────────

    @Test
    fun joinerCompleteBeforeConfirmIsRejected() {
        val (inviter, joiner) = sessions()
        // The joiner has only sent its response — the inviter's MAC and commitment are unchecked.
        val response = joiner.onInviterHello(inviter.hello())
        val complete = inviter.complete(runCeremonyToConfirmation(inviter, response))

        // Skipping onInviterConfirm: no SAS was ever verified. confirmSas must refuse...
        assertFailsWith<PairingException> { joiner.confirmSas() }
        // ...and onInviterComplete cannot be reached, even with a fabricated token: the stage gate
        // (SAS_CONFIRMED) is checked before the token, and the joiner never reached it.
        assertFailsWith<PairingException> { joiner.onInviterComplete(complete, forgedToken) }
    }

    @Test
    fun joinerCompleteAfterConfirmButWithoutSasConfirmationIsRejected() {
        val (inviter, joiner) = sessions()
        val response = joiner.onInviterHello(inviter.hello())
        val confirm = inviter.onJoinerResponse(response)
        joiner.onInviterConfirm(confirm) // MAC + commitment verified, SAS now available
        val complete = inviter.complete(inviter.confirmSas())

        // The joiner's human has NOT confirmed (no confirmSas call), so no valid token exists and
        // the stage is still AWAITING_SAS: completion is refused.
        assertFailsWith<PairingException> { joiner.onInviterComplete(complete, forgedToken) }
    }

    // ── The inviter cannot release the key without confirming the SAS ─────────────────────────

    @Test
    fun inviterCompleteBeforeSasConfirmationIsRejected() {
        val (inviter, joiner) = sessions()
        val response = joiner.onInviterHello(inviter.hello())
        inviter.onJoinerResponse(response) // SAS available, but the human has not confirmed

        // The only way to obtain a token is confirmSas(); a fabricated one fails the stage gate.
        assertFailsWith<PairingException> { inviter.complete(forgedToken) }
    }

    // ── A confirmation is bound to its own session ────────────────────────────────────────────

    @Test
    fun aConfirmationFromAnotherSessionIsRejected() {
        val (inviter, joiner) = sessions()
        val response = joiner.onInviterHello(inviter.hello())
        inviter.onJoinerResponse(response)
        inviter.confirmSas() // the inviter reaches SAS_CONFIRMED with its own (discarded) token

        // A different session's / fabricated token does not complete this one, despite the stage
        // being correct — the session binding is checked too.
        assertFailsWith<PairingException> { inviter.complete(forgedToken) }
    }

    // ── Every earlier step is order-checked too ───────────────────────────────────────────────

    @Test
    fun stepsBeforeTheirPrerequisiteAreRejected() {
        val (inviter, joiner) = sessions()

        // Inviter: confirmSas before a response is out of order.
        assertFailsWith<PairingException> { inviter.confirmSas() }
        // Joiner: onInviterConfirm before a hello is out of order.
        assertFailsWith<PairingException> { joiner.onInviterConfirm(InviterConfirm(ByteArray(32), ByteArray(32))) }

        // Drive the inviter one step and confirm confirmSas is still too early.
        val response = joiner.onInviterHello(inviter.hello())
        assertFailsWith<PairingException> { inviter.confirmSas() } // response not yet processed
        inviter.onJoinerResponse(response)
        inviter.confirmSas() // now valid
    }

    // ── The full ordered ceremony still succeeds ──────────────────────────────────────────────

    @Test
    fun theCorrectlyOrderedCeremonySucceeds() {
        val (inviter, joiner) = sessions()
        val response = joiner.onInviterHello(inviter.hello())
        val confirm = inviter.onJoinerResponse(response)
        joiner.onInviterConfirm(confirm)
        assertTrue(inviter.shortAuthString == joiner.shortAuthString)

        val complete = inviter.complete(inviter.confirmSas())
        joiner.onInviterComplete(complete, joiner.confirmSas())
        assertTrue(inviter.masterKey().contentEquals(joiner.masterKey()))
    }

    // ── A wrong code never reaches the key-acceptance step ────────────────────────────────────

    @Test
    fun aWrongCodeNeverReachesTheKeyAcceptanceStep() {
        val (inviter, joiner) = sessions(sameCode = false) // the joiner has the wrong code
        val response = joiner.onInviterHello(inviter.hello())

        // The inviter rejects the joiner's MAC — the ceremony dies before any SAS is available,
        // so neither side can obtain a confirmation token to complete with.
        assertFailsWith<PairingException> { inviter.onJoinerResponse(response) }
        assertFailsWith<PairingException> { inviter.confirmSas() }
        assertTrue(inviter.shortAuthString == null, "no SAS is derived on a failed handshake")
    }

    /** Drives an inviter through its own valid confirmation, for producing a real InviterComplete. */
    private fun runCeremonyToConfirmation(inviter: Inviter, response: org.layeredencryption.pairing.JoinerResponse): SasConfirmation {
        inviter.onJoinerResponse(response)
        return inviter.confirmSas()
    }
}
