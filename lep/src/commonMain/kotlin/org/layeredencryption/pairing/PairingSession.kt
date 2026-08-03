package org.layeredencryption.pairing

import org.layeredencryption.Cascade
import org.layeredencryption.CryptoProvider
import org.layeredencryption.XWing
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.toHexString

/** Raised when a pairing cannot proceed — a MAC mismatch, an invalid log, or misuse of the state machine. */
class PairingException(message: String) : Exception(message)

// ── Wire messages (transport-agnostic; §6.3 steps 1–6) ────────────────────────────────────────

/** Step 1: inviter → joiner. The ephemeral X-Wing public key + inviter device identity. */
class InviterHello(val xWingPublicKey: ByteArray, val inviterDeviceIdentity: DeviceIdentity)

/** Step 2/4: joiner → inviter. The KEM ciphertext, joiner device identity, and the joiner's MAC. */
class JoinerResponse(val kemCiphertext: ByteArray, val joinerDeviceIdentity: DeviceIdentity, val joinerMac: ByteArray)

/** Step 4: inviter → joiner. The inviter's MAC, proving the inviter also knows the code. */
class InviterConfirm(val inviterMac: ByteArray)

/** Step 6: inviter → joiner. The membership log carrying the master key wrapped under K_handshake. */
class InviterComplete(val membershipLog: ByteArray)

/**
 * The inviting device's side of the pairing handshake (docs/Protocol.md §6.3).
 *
 * The inviter generates the ephemeral X-Wing keypair and the calendar master key, then: publishes
 * [hello], authenticates the [onJoinerResponse] via its code-keyed MAC, and — only after the human
 * SAS comparison — hands over the master key wrapped under `K_handshake` inside the membership log
 * ([complete]). The master key never leaves unwrapped.
 */
class Inviter(
    private val provider: CryptoProvider,
    private val device: DeviceKeys,
    private val code: PairingCode,
) {
    private val xWingKeyPair = XWing.generateKeyPair(provider)
    private val masterKey = provider.randomBytes(MASTER_KEY_SIZE)
    private var membershipLog: MembershipLog? = null

    private var handshakeKey: ByteArray? = null
    private var joinerDeviceIdentity: DeviceIdentity? = null

    /** The 6-digit SAS to show the user, available once [onJoinerResponse] has run. */
    var shortAuthString: String? = null
        private set

    fun hello(): InviterHello = InviterHello(xWingKeyPair.publicKey, device.identity)

    /** Verifies the joiner's code-keyed MAC and returns the inviter's own MAC. Throws on mismatch. */
    fun onJoinerResponse(response: JoinerResponse): InviterConfirm {
        if (!response.joinerDeviceIdentity.verifyBinding(provider)) {
            throw PairingException("Joiner device-identity binding is invalid")
        }
        val sharedSecret = XWing.decapsulate(provider, xWingKeyPair.privateKey, response.kemCiphertext)
        val transcript = PairingTranscript(
            inviterXWingPublicKey = xWingKeyPair.publicKey,
            inviterDeviceIdentity = device.identity.serialise(),
            kemCiphertext = response.kemCiphertext,
            joinerDeviceIdentity = response.joinerDeviceIdentity.serialise(),
        )
        val handshakeKey = Handshake.handshakeKey(provider, sharedSecret, transcript)
        val codeSecret = Handshake.codeSecret(provider, code.canonical)

        val expectedJoinerMac = Handshake.transcriptMac(provider, handshakeKey, codeSecret, transcript, PairingRole.JOINER)
        if (!response.joinerMac.constantTimeEquals(expectedJoinerMac)) {
            throw PairingException("Joiner MAC mismatch — wrong code or man-in-the-middle")
        }

        this.handshakeKey = handshakeKey
        this.joinerDeviceIdentity = response.joinerDeviceIdentity
        this.shortAuthString = Handshake.shortAuthString(provider, sharedSecret, transcript)
        return InviterConfirm(Handshake.transcriptMac(provider, handshakeKey, codeSecret, transcript, PairingRole.INVITER))
    }

    /** Call only after the human SAS comparison matches. Wraps the master key for the joiner. */
    fun complete(): InviterComplete {
        val joiner = joinerDeviceIdentity ?: throw PairingException("complete() called before a joiner response")
        val handshakeKey = handshakeKey ?: throw PairingException("complete() called before the handshake")
        val wrappedMasterKey = Cascade.seal(provider, handshakeKey, masterKey, aad = joiner.serialise())
        val log = MembershipLog.found(provider, device.identity, device.signingKeyPair)
            .append(provider, MembershipOp.ADD, joiner, wrappedMasterKey, signer = device.signingKeyPair)
        membershipLog = log
        return InviterComplete(log.serialise())
    }

    /** The calendar master key this device owns. */
    fun masterKey(): ByteArray = masterKey

    /** The log this pairing founded, for persisting alongside the key; null before [complete]. */
    fun membershipLog(): MembershipLog? = membershipLog

    private companion object {
        const val MASTER_KEY_SIZE = 32
    }
}

/**
 * The joining device's side of the pairing handshake (docs/Protocol.md §6.3).
 *
 * The joiner encapsulates against the inviter's X-Wing key, proves knowledge of the code via its
 * MAC ([onInviterHello]), verifies the inviter's MAC ([onInviterConfirm]) and — after the human SAS
 * comparison — verifies the membership log and unwraps the master key ([onInviterComplete]).
 */
class Joiner(
    private val provider: CryptoProvider,
    private val device: DeviceKeys,
    private val code: PairingCode,
) {
    private var handshakeKey: ByteArray? = null
    private var expectedInviterMac: ByteArray? = null
    private var recoveredMasterKey: ByteArray? = null
    private var membershipLog: MembershipLog? = null

    /** The 6-digit SAS to show the user, available once [onInviterHello] has run. */
    var shortAuthString: String? = null
        private set

    /** Encapsulates against the inviter's key and returns the joiner's response with its MAC. */
    fun onInviterHello(hello: InviterHello): JoinerResponse {
        if (!hello.inviterDeviceIdentity.verifyBinding(provider)) {
            throw PairingException("Inviter device-identity binding is invalid")
        }
        val encapsulation = XWing.encapsulate(provider, hello.xWingPublicKey)
        val transcript = PairingTranscript(
            inviterXWingPublicKey = hello.xWingPublicKey,
            inviterDeviceIdentity = hello.inviterDeviceIdentity.serialise(),
            kemCiphertext = encapsulation.ciphertext,
            joinerDeviceIdentity = device.identity.serialise(),
        )
        val handshakeKey = Handshake.handshakeKey(provider, encapsulation.sharedSecret, transcript)
        val codeSecret = Handshake.codeSecret(provider, code.canonical)

        this.handshakeKey = handshakeKey
        this.shortAuthString = Handshake.shortAuthString(provider, encapsulation.sharedSecret, transcript)
        this.expectedInviterMac = Handshake.transcriptMac(provider, handshakeKey, codeSecret, transcript, PairingRole.INVITER)
        val joinerMac = Handshake.transcriptMac(provider, handshakeKey, codeSecret, transcript, PairingRole.JOINER)
        return JoinerResponse(encapsulation.ciphertext, device.identity, joinerMac)
    }

    /** Verifies the inviter's code-keyed MAC. Throws on mismatch. */
    fun onInviterConfirm(confirm: InviterConfirm) {
        val expected = expectedInviterMac ?: throw PairingException("onInviterConfirm() called before the handshake")
        if (!confirm.inviterMac.constantTimeEquals(expected)) {
            throw PairingException("Inviter MAC mismatch — wrong code or man-in-the-middle")
        }
    }

    /** Call only after the human SAS comparison matches. Verifies the log and unwraps the master key. */
    fun onInviterComplete(complete: InviterComplete) {
        val handshakeKey = handshakeKey ?: throw PairingException("onInviterComplete() called before the handshake")
        val log = MembershipLog.deserialise(complete.membershipLog)

        val verification = log.verify(provider)
        if (verification !is MembershipVerification.Valid) {
            throw PairingException("Membership log failed verification: $verification")
        }
        val ownKey = device.identity.ed25519PublicKey
        if (ownKey.toHexString() !in verification.activeMembers) {
            throw PairingException("This device is not in the membership log")
        }

        val entry = log.addEntryFor(ownKey) ?: throw PairingException("No ADD entry for this device")
        val wrapped = entry.wrappedKeys ?: throw PairingException("No wrapped keys for this device")
        recoveredMasterKey = Cascade.open(provider, handshakeKey, wrapped, aad = device.identity.serialise())
        membershipLog = log
    }

    /** The calendar master key recovered from the inviter; throws if pairing has not completed. */
    fun masterKey(): ByteArray = recoveredMasterKey ?: throw PairingException("Pairing is not complete")

    /** The verified log received from the inviter; null before [onInviterComplete]. */
    fun membershipLog(): MembershipLog? = membershipLog
}
