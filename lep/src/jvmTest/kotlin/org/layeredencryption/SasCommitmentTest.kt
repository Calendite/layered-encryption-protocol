package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.pairing.Handshake
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.InviterConfirm
import org.layeredencryption.pairing.InviterHello
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.PairingTranscript
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The SAS is the last line of defence in pairing: if an attacker recovers the code, the six digits
 * the two humans compare are the only thing left. These tests exist because that line was
 * previously defeatable.
 *
 * The joiner used to move last, choosing its KEM ciphertext *after* seeing everything that fed the
 * SAS, so it could re-encapsulate offline until the digits matched any target it liked. Measured
 * against this library that took about 39 seconds on eight threads, comfortably inside a code's
 * lifetime, which would have let a machine in the middle show both people identical digits and pass
 * a correctly performed human check.
 */
class SasCommitmentTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private fun pair(): Triple<Inviter, Joiner, PairingCode> {
        val code = PairingCode.generate(provider)
        val inviter = Inviter(provider, DeviceKeys.generate(provider), code)
        val joiner = Joiner(provider, DeviceKeys.generate(provider), code)
        return Triple(inviter, joiner, code)
    }

    @Test
    fun `an honest pairing agrees on the same six digits`() {
        val (inviter, joiner, _) = pair()

        val response = joiner.onInviterHello(inviter.hello())
        val confirm = inviter.onJoinerResponse(response)
        joiner.onInviterConfirm(confirm)

        val sas = assertNotNull(inviter.shortAuthString)
        assertEquals(sas, joiner.shortAuthString)
        assertEquals(7, sas.length, "6 digits grouped 3-3 with a space")
    }

    /**
     * The heart of it. The joiner must not be able to learn anything about the SAS at the moment it
     * has to commit to its ciphertext, because that is precisely when grinding would happen.
     */
    @Test
    fun `the joiner cannot know the SAS before it commits to its ciphertext`() {
        val (inviter, joiner, _) = pair()

        joiner.onInviterHello(inviter.hello())

        assertNull(
            joiner.shortAuthString,
            "the joiner could compute the SAS while still free to re-encapsulate, which is grindable",
        )
    }

    /**
     * Grinding, attempted directly: re-encapsulate many times against the same inviter key and see
     * whether any candidate lets an attacker steer the digits. Without the nonce it cannot even
     * compute a candidate, so every trial is a shot in the dark rather than a search.
     */
    @Test
    fun `re-encapsulating cannot steer the digits without the nonce`() {
        val inviterDevice = DeviceKeys.generate(provider)
        val joinerDevice = DeviceKeys.generate(provider)
        val code = PairingCode.generate(provider)
        val inviter = Inviter(provider, inviterDevice, code)
        val hello = inviter.hello()

        // What an attacker holds after the hello: everything except the nonce behind the commitment.
        val target = "123 456"
        var steered = false
        repeat(200) {
            val encapsulation = XWing.encapsulate(provider, hello.xWingPublicKey)
            val transcript = PairingTranscript(
                inviterXWingPublicKey = hello.xWingPublicKey,
                inviterDeviceIdentity = hello.inviterDeviceIdentity.serialise(),
                kemCiphertext = encapsulation.ciphertext,
                joinerDeviceIdentity = joinerDevice.identity.serialise(),
                sasCommitment = hello.sasCommitment,
            )
            // The best an attacker can do is guess a nonce; the real one is still committed.
            val guessedNonce = provider.randomBytes(Handshake.SAS_NONCE_SIZE)
            val predicted = Handshake.shortAuthString(provider, encapsulation.sharedSecret, transcript, guessedNonce)
            if (predicted == target) steered = true
        }
        assertFalse(steered, "200 blind trials should not hit a specific 6-digit value")
    }

    @Test
    fun `a nonce that does not open the commitment is rejected`() {
        val (inviter, joiner, _) = pair()

        val response = joiner.onInviterHello(inviter.hello())
        val confirm = inviter.onJoinerResponse(response)
        val forged = InviterConfirm(confirm.inviterMac, provider.randomBytes(Handshake.SAS_NONCE_SIZE))

        val failure = assertFailsWith<PairingException> { joiner.onInviterConfirm(forged) }
        assertTrue(failure.message!!.contains("commitment"), "actual: ${failure.message}")
        assertNull(joiner.shortAuthString, "no SAS is derived from an unopened commitment")
    }

    /**
     * The commitment is inside the transcript, so an attacker who rewrites it in flight changes
     * what the joiner MACs over, and the inviter's check fails. Without this binding the commitment
     * would be an unauthenticated field that could simply be replaced.
     */
    @Test
    fun `rewriting the commitment in flight breaks the MAC`() {
        val code = PairingCode.generate(provider)
        val inviter = Inviter(provider, DeviceKeys.generate(provider), code)
        val joiner = Joiner(provider, DeviceKeys.generate(provider), code)

        val hello = inviter.hello()
        val tampered = InviterHello(
            hello.xWingPublicKey,
            hello.inviterDeviceIdentity,
            provider.sha256("a commitment the inviter never made".encodeToByteArray()),
        )

        // The joiner responds honestly, but to the rewritten hello.
        val response = joiner.onInviterHello(tampered)

        assertFailsWith<PairingException> { inviter.onJoinerResponse(response) }
    }

    @Test
    fun `opening a commitment is exact`() {
        val nonce = Handshake.sasNonce(provider)
        val commitment = Handshake.sasCommitment(provider, nonce)

        assertTrue(Handshake.opensSasCommitment(provider, commitment, nonce))
        assertFalse(Handshake.opensSasCommitment(provider, commitment, provider.randomBytes(32)))

        val nudged = nonce.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(Handshake.opensSasCommitment(provider, commitment, nudged), "one flipped bit must fail")
    }

    @Test
    fun `a different vendor namespace produces a different commitment`() {
        val nonce = Handshake.sasNonce(provider)
        val ours = Handshake.sasCommitment(provider, nonce)
        val theirs = Handshake.sasCommitment(provider, nonce, ProtocolNamespace("other"))

        assertFalse(ours.contentEquals(theirs))
    }
}
