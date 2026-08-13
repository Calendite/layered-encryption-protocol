package org.layeredencryption.pairing

import org.layeredencryption.Cascade
import org.layeredencryption.envelope.EpochKeys
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
//
// Every message copies its byte arrays on construction: what the state machines verify is the
// message's own snapshot, which the producer of the arrays cannot mutate afterwards.

/** Step 1: inviter → joiner. The ephemeral X-Wing public key + inviter device identity. */
class InviterHello(
    xWingPublicKey: ByteArray,
    val inviterDeviceIdentity: DeviceIdentity,
    sasCommitment: ByteArray,
) {
    val xWingPublicKey: ByteArray = xWingPublicKey.copyOf()

    /** Binds the inviter to a SAS nonce before it can see the joiner's ciphertext. */
    val sasCommitment: ByteArray = sasCommitment.copyOf()
}

/** Step 2/4: joiner → inviter. The KEM ciphertext, joiner device identity, and the joiner's MAC. */
class JoinerResponse(kemCiphertext: ByteArray, val joinerDeviceIdentity: DeviceIdentity, joinerMac: ByteArray) {
    val kemCiphertext: ByteArray = kemCiphertext.copyOf()
    val joinerMac: ByteArray = joinerMac.copyOf()
}

/** Step 4: inviter → joiner. The inviter's MAC, proving the inviter also knows the code. */
class InviterConfirm(inviterMac: ByteArray, sasNonce: ByteArray) {
    val inviterMac: ByteArray = inviterMac.copyOf()

    /** Opens the commitment from the hello; only now can the joiner compute the SAS. */
    val sasNonce: ByteArray = sasNonce.copyOf()
}

/** Step 6: inviter → joiner. The membership log carrying the master key wrapped under K_handshake. */
class InviterComplete(membershipLog: ByteArray) {
    val membershipLog: ByteArray = membershipLog.copyOf()
}

/**
 * A calendar that already exists, for inviting a second or third person into it.
 *
 * Without this an invite always founds something new, which is right for the first person and
 * catastrophic for the second: a fresh master key would orphan every event already shared, since
 * the context id derives from the key and nothing could name the old calendar again.
 */
class ExistingCalendar(
    val keys: EpochKeys,
    val membershipLog: MembershipLog,
)

/**
 * The inviting device's side of the pairing handshake (docs/Protocol.md §6.3).
 *
 * The inviter generates the ephemeral X-Wing keypair and the context master key, then: publishes
 * [hello], authenticates the [onJoinerResponse] via its code-keyed MAC, and — only after the human
 * SAS comparison — hands over the master key wrapped under `K_handshake` inside the membership log
 * ([complete]). The master key never leaves unwrapped.
 *
 * Pass [existing] to add someone to a calendar this device is already in. The master key is then
 * the one already in use rather than a fresh one, and the new member is appended to the existing
 * log rather than founding a new one. Any active member may do this: verification requires only
 * that the signer was a member at that point in the chain, not that they founded it.
 */
class Inviter(
    private val provider: CryptoProvider,
    private val device: DeviceKeys,
    private val code: PairingCode,
    private val existing: ExistingCalendar? = null,
) {
    private val xWingKeyPair = XWing.generateKeyPair(provider)

    /**
     * Chosen up front and committed to in [hello], revealed only in the confirm. Fixing it before
     * the joiner's ciphertext arrives is what stops either side steering the SAS.
     */
    private val sasNonce = Handshake.sasNonce(provider)
    /**
     * Every epoch, not just the current one. A newcomer receives the whole set so the shared
     * history stays readable to them: handing over only the newest key would leave everything
     * written before the last rotation permanently opaque on their phone.
     */
    private val keys = existing?.keys ?: EpochKeys.founding(provider.randomBytes(MASTER_KEY_SIZE))
    private var membershipLog: MembershipLog? = null

    private var handshakeKey: ByteArray? = null
    private var joinerDeviceIdentity: DeviceIdentity? = null

    /** The 6-digit SAS to show the user, available once [onJoinerResponse] has run. */
    var shortAuthString: String? = null
        private set

    fun hello(): InviterHello =
        InviterHello(xWingKeyPair.publicKey, device.identity, Handshake.sasCommitment(provider, sasNonce))

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
            sasCommitment = Handshake.sasCommitment(provider, sasNonce),
        )
        val handshakeKey = Handshake.handshakeKey(provider, sharedSecret, transcript)
        val codeSecret = Handshake.codeSecret(provider, code.canonical)

        val expectedJoinerMac = Handshake.transcriptMac(provider, handshakeKey, codeSecret, transcript, PairingRole.JOINER)
        if (!response.joinerMac.constantTimeEquals(expectedJoinerMac)) {
            throw PairingException("Joiner MAC mismatch — wrong code or man-in-the-middle")
        }

        this.handshakeKey = handshakeKey
        this.joinerDeviceIdentity = response.joinerDeviceIdentity
        this.shortAuthString = Handshake.shortAuthString(provider, sharedSecret, transcript, sasNonce)
        return InviterConfirm(
            Handshake.transcriptMac(provider, handshakeKey, codeSecret, transcript, PairingRole.INVITER),
            sasNonce,
        )
    }

    /** Call only after the human SAS comparison matches. Wraps the master key for the joiner. */
    fun complete(): InviterComplete {
        val joiner = joinerDeviceIdentity ?: throw PairingException("complete() called before a joiner response")
        val handshakeKey = handshakeKey ?: throw PairingException("complete() called before the handshake")
        val wrappedMasterKey = Cascade.seal(provider, handshakeKey, keys.serialise(), aad = joiner.serialise())
        val base = existing?.membershipLog
            ?: MembershipLog.found(provider, device.identity, device.signingKeyPair)
        val log = base.append(provider, MembershipOp.ADD, joiner, wrappedMasterKey, signer = device.signingKeyPair)
        membershipLog = log
        return InviterComplete(log.serialise())
    }

    /** Every context key this device holds, newest last. */
    fun calendarKeys(): EpochKeys = keys

    /** The key currently sealed under. */
    fun masterKey(): ByteArray = keys.currentKey

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
    private var recoveredKeys: EpochKeys? = null
    private var membershipLog: MembershipLog? = null
    private var sasCommitment: ByteArray? = null
    private var sharedSecret: ByteArray? = null
    private var transcript: PairingTranscript? = null

    /**
     * The 6-digit SAS to show the user, available only once [onInviterConfirm] has run.
     *
     * Deliberately *not* available after the hello: the joiner must commit to its ciphertext while
     * the SAS is still unknowable to it, which is the whole point of the inviter's commitment.
     */
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
            sasCommitment = hello.sasCommitment,
        )
        val handshakeKey = Handshake.handshakeKey(provider, encapsulation.sharedSecret, transcript)
        val codeSecret = Handshake.codeSecret(provider, code.canonical)

        this.handshakeKey = handshakeKey
        this.sasCommitment = hello.sasCommitment
        this.sharedSecret = encapsulation.sharedSecret
        this.transcript = transcript
        this.expectedInviterMac = Handshake.transcriptMac(provider, handshakeKey, codeSecret, transcript, PairingRole.INVITER)
        val joinerMac = Handshake.transcriptMac(provider, handshakeKey, codeSecret, transcript, PairingRole.JOINER)
        return JoinerResponse(encapsulation.ciphertext, device.identity, joinerMac)
    }

    /**
     * Verifies the inviter's code-keyed MAC, checks that the revealed nonce opens the commitment
     * from the hello, and only then derives the SAS. Throws on any mismatch.
     */
    fun onInviterConfirm(confirm: InviterConfirm) {
        val expected = expectedInviterMac ?: throw PairingException("onInviterConfirm() called before the handshake")
        if (!confirm.inviterMac.constantTimeEquals(expected)) {
            throw PairingException("Inviter MAC mismatch — wrong code or man-in-the-middle")
        }
        val commitment = sasCommitment ?: throw PairingException("onInviterConfirm() called before the handshake")
        if (!Handshake.opensSasCommitment(provider, commitment, confirm.sasNonce)) {
            throw PairingException("SAS nonce does not open the inviter's commitment — man-in-the-middle")
        }
        val sharedSecret = sharedSecret ?: throw PairingException("onInviterConfirm() called before the handshake")
        val transcript = transcript ?: throw PairingException("onInviterConfirm() called before the handshake")
        shortAuthString = Handshake.shortAuthString(provider, sharedSecret, transcript, confirm.sasNonce)
    }

    /** Call only after the human SAS comparison matches. Verifies the log and unwraps the master key. */
    fun onInviterComplete(complete: InviterComplete) {
        val handshakeKey = handshakeKey ?: throw PairingException("onInviterComplete() called before the handshake")
        val log = MembershipLog.deserialise(complete.membershipLog)

        val verification = log.verify(provider)
        if (verification !is MembershipVerification.Valid) {
            throw PairingException("Membership log failed verification: $verification")
        }
        val ownKey = device.identity.signingPublicKey
        if (ownKey.toHexString() !in verification.activeMembers) {
            throw PairingException("This device is not in the membership log")
        }

        val entry = log.addEntryFor(ownKey) ?: throw PairingException("No ADD entry for this device")
        val wrapped = entry.wrappedKeys ?: throw PairingException("No wrapped keys for this device")
        val unwrapped = Cascade.open(provider, handshakeKey, wrapped, aad = device.identity.serialise())
        recoveredKeys = EpochKeys.deserialise(unwrapped)
            ?: throw PairingException("The wrapped keys did not decode")
        membershipLog = log
    }

    /** Every context key recovered from the inviter; throws if pairing has not completed. */
    fun calendarKeys(): EpochKeys = recoveredKeys ?: throw PairingException("Pairing is not complete")

    /** The key currently sealed under; throws if pairing has not completed. */
    fun masterKey(): ByteArray = calendarKeys().currentKey

    /** The verified log received from the inviter; null before [onInviterComplete]. */
    fun membershipLog(): MembershipLog? = membershipLog
}
