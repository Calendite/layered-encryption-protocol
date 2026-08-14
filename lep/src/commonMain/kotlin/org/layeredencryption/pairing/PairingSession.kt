package org.layeredencryption.pairing

import org.layeredencryption.Cascade
import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.CryptoProvider
import org.layeredencryption.ProtocolLimits
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
// Every message validates its protocol-fixed sizes BEFORE copying (a transport feeding one peer
// bytes should treat the IllegalArgumentException as "invalid message"), and every read returns
// a copy: the message is an immutable snapshot from construction onward.

private const val WIRE_MAC_BYTES = 32
private const val SAS_COMMITMENT_BYTES = 32
private const val SAS_NONCE_BYTES = 32

/** Step 1: inviter → joiner. The ephemeral X-Wing public key + inviter device identity. */
class InviterHello(
    xWingPublicKey: ByteArray,
    val inviterDeviceIdentity: DeviceIdentity,
    sasCommitment: ByteArray,
) {
    init {
        require(xWingPublicKey.size == XWing.PUBLIC_KEY_SIZE) { "X-Wing public key must be ${XWing.PUBLIC_KEY_SIZE} bytes" }
        require(sasCommitment.size == SAS_COMMITMENT_BYTES) { "SAS commitment must be $SAS_COMMITMENT_BYTES bytes" }
    }

    private val _xWingPublicKey = xWingPublicKey.copyOf()
    private val _sasCommitment = sasCommitment.copyOf()

    val xWingPublicKey: ByteArray get() = _xWingPublicKey.copyOf()

    /** Binds the inviter to a SAS nonce before it can see the joiner's ciphertext. */
    val sasCommitment: ByteArray get() = _sasCommitment.copyOf()
}

/** Step 2/4: joiner → inviter. The KEM ciphertext, joiner device identity, and the joiner's MAC. */
class JoinerResponse(kemCiphertext: ByteArray, val joinerDeviceIdentity: DeviceIdentity, joinerMac: ByteArray) {
    init {
        require(kemCiphertext.size == XWing.CIPHERTEXT_SIZE) { "KEM ciphertext must be ${XWing.CIPHERTEXT_SIZE} bytes" }
        require(joinerMac.size == WIRE_MAC_BYTES) { "joinerMac must be $WIRE_MAC_BYTES bytes" }
    }

    private val _kemCiphertext = kemCiphertext.copyOf()
    private val _joinerMac = joinerMac.copyOf()

    val kemCiphertext: ByteArray get() = _kemCiphertext.copyOf()
    val joinerMac: ByteArray get() = _joinerMac.copyOf()
}

/** Step 4: inviter → joiner. The inviter's MAC, proving the inviter also knows the code. */
class InviterConfirm(inviterMac: ByteArray, sasNonce: ByteArray) {
    init {
        require(inviterMac.size == WIRE_MAC_BYTES) { "inviterMac must be $WIRE_MAC_BYTES bytes" }
        require(sasNonce.size == SAS_NONCE_BYTES) { "SAS nonce must be $SAS_NONCE_BYTES bytes" }
    }

    private val _inviterMac = inviterMac.copyOf()
    private val _sasNonce = sasNonce.copyOf()

    val inviterMac: ByteArray get() = _inviterMac.copyOf()

    /** Opens the commitment from the hello; only now can the joiner compute the SAS. */
    val sasNonce: ByteArray get() = _sasNonce.copyOf()
}

/** Step 6: inviter → joiner. The membership log carrying the master key wrapped under K_handshake. */
class InviterComplete(membershipLog: ByteArray) {
    init {
        require(membershipLog.size <= ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES) {
            "Membership log of ${membershipLog.size} bytes exceeds the ${ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES}-byte limit"
        }
    }

    private val _membershipLog = membershipLog.copyOf()

    val membershipLog: ByteArray get() = _membershipLog.copyOf()
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
/**
 * Opaque, non-forgeable proof that the human SAS comparison was confirmed on a specific session.
 *
 * Its constructor is `internal`, so a consumer cannot fabricate one; a session issues exactly one,
 * from [Inviter.confirmSas] / [Joiner.confirmSas], and only after that side's code-keyed MAC — and
 * on the joiner, the SAS commitment — have already been verified. [Inviter.complete] and
 * [Joiner.onInviterComplete] require and validate it, so the master key cannot be released without
 * passing the human gate, even by a consumer driving the low-level session API directly rather than
 * through [PairingFerry]. The token is bound to its issuing session and consumed once.
 */
class SasConfirmation internal constructor(internal val session: Any)

private enum class InviterStage { AWAITING_HELLO, AWAITING_RESPONSE, AWAITING_SAS, SAS_CONFIRMED, COMPLETED }

class Inviter(
    private val provider: CryptoProvider,
    private val device: DeviceKeys,
    private val code: PairingCode,
    private val existing: ExistingCalendar? = null,
) {
    private val xWingKeyPair = XWing.generateKeyPair(provider)
    private var stage = InviterStage.AWAITING_HELLO

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
    private var destroyed = false

    /** The 6-digit SAS to show the user, available once [onJoinerResponse] has run. */
    var shortAuthString: String? = null
        private set

    /**
     * Scrubs the session-scoped secrets — the ephemeral X-Wing private key, the handshake key,
     * and the SAS nonce — and rejects further protocol steps. Runs automatically when [complete]
     * succeeds; on a failure path (a thrown MAC mismatch, a cancelled ceremony) the caller runs
     * it, as [PairingFerry] does in its `finally`. Idempotent.
     *
     * Long-term material is deliberately untouched: the device keys and the context [keys]
     * (possibly an existing calendar's) belong to the application, and the ceremony's *results* —
     * [masterKey], [calendarKeys], [membershipLog], [shortAuthString] — stay readable.
     */
    fun destroy() {
        destroyed = true
        xWingKeyPair.privateKey.fill(0)
        sasNonce.fill(0)
        handshakeKey?.fill(0)
        handshakeKey = null
        joinerDeviceIdentity = null
    }

    private fun checkLive() {
        check(!destroyed) { "Pairing session has been destroyed" }
    }

    private fun requireStage(vararg allowed: InviterStage) {
        checkLive()
        if (stage !in allowed) throw PairingException("Out-of-order pairing step: stage is $stage")
    }

    fun hello(): InviterHello {
        requireStage(InviterStage.AWAITING_HELLO, InviterStage.AWAITING_RESPONSE) // resend is allowed
        stage = InviterStage.AWAITING_RESPONSE
        return InviterHello(xWingKeyPair.publicKey, device.identity, Handshake.sasCommitment(provider, sasNonce))
    }

    /** Verifies the joiner's code-keyed MAC and returns the inviter's own MAC. Throws on mismatch. */
    fun onJoinerResponse(response: JoinerResponse): InviterConfirm {
        requireStage(InviterStage.AWAITING_RESPONSE)
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
        stage = InviterStage.AWAITING_SAS
        return InviterConfirm(
            Handshake.transcriptMac(provider, handshakeKey, codeSecret, transcript, PairingRole.INVITER),
            sasNonce,
        )
    }

    /**
     * Records that this device's human confirmed the displayed SAS matches, and returns the
     * [SasConfirmation] that [complete] requires. Only callable once the SAS is available — i.e.
     * after [onJoinerResponse] has verified the joiner's code-keyed MAC — so a token cannot exist
     * without the MAC check having passed.
     */
    fun confirmSas(): SasConfirmation {
        requireStage(InviterStage.AWAITING_SAS)
        stage = InviterStage.SAS_CONFIRMED
        return SasConfirmation(this)
    }

    /**
     * Wraps the master key for the joiner. Requires the [SasConfirmation] from [confirmSas] — the
     * key is never released without the human gate, and the token is bound to this session.
     * Success is terminal: the session scrubs its handshake secrets on the way out.
     */
    fun complete(confirmation: SasConfirmation): InviterComplete {
        requireStage(InviterStage.SAS_CONFIRMED)
        if (confirmation.session !== this) throw PairingException("SAS confirmation belongs to a different session")
        val joiner = joinerDeviceIdentity ?: throw PairingException("complete() called before a joiner response")
        val handshakeKey = handshakeKey ?: throw PairingException("complete() called before the handshake")
        val wrappedMasterKey = Cascade.seal(provider, handshakeKey, keys.serialise(), aad = joiner.serialise())
        val base = existing?.membershipLog
            ?: MembershipLog.found(provider, device.identity, device.signingKeyPair)
        val log = base.append(provider, MembershipOp.ADD, joiner, wrappedMasterKey, signer = device.signingKeyPair)
        membershipLog = log
        val message = InviterComplete(log.serialise())
        stage = InviterStage.COMPLETED
        destroy()
        return message
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
private enum class JoinerStage { AWAITING_HELLO, AWAITING_CONFIRM, AWAITING_SAS, SAS_CONFIRMED, COMPLETED }

class Joiner(
    private val provider: CryptoProvider,
    private val device: DeviceKeys,
    private val code: PairingCode,
) {
    private var stage = JoinerStage.AWAITING_HELLO
    private var handshakeKey: ByteArray? = null
    private var expectedInviterMac: ByteArray? = null
    private var recoveredKeys: EpochKeys? = null
    private var membershipLog: MembershipLog? = null
    private var sasCommitment: ByteArray? = null
    private var sharedSecret: ByteArray? = null
    private var transcript: PairingTranscript? = null
    private var destroyed = false

    /**
     * Scrubs the session-scoped secrets — the handshake key, KEM shared secret, and expected
     * MAC — and rejects further protocol steps. Runs automatically when [onInviterComplete]
     * succeeds; on a failure path the caller runs it, as [PairingFerry] does in its `finally`.
     * Idempotent. The ceremony's results — [masterKey], [calendarKeys], [membershipLog],
     * [shortAuthString] — stay readable; those belong to the application.
     */
    fun destroy() {
        destroyed = true
        handshakeKey?.fill(0)
        handshakeKey = null
        sharedSecret?.fill(0)
        sharedSecret = null
        expectedInviterMac?.fill(0)
        expectedInviterMac = null
        sasCommitment = null
        transcript = null
    }

    private fun checkLive() {
        check(!destroyed) { "Pairing session has been destroyed" }
    }

    private fun requireStage(vararg allowed: JoinerStage) {
        checkLive()
        if (stage !in allowed) throw PairingException("Out-of-order pairing step: stage is $stage")
    }

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
        requireStage(JoinerStage.AWAITING_HELLO)
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
        stage = JoinerStage.AWAITING_CONFIRM
        return JoinerResponse(encapsulation.ciphertext, device.identity, joinerMac)
    }

    /**
     * Verifies the inviter's code-keyed MAC, checks that the revealed nonce opens the commitment
     * from the hello, and only then derives the SAS. Throws on any mismatch.
     */
    fun onInviterConfirm(confirm: InviterConfirm) {
        requireStage(JoinerStage.AWAITING_CONFIRM)
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
        stage = JoinerStage.AWAITING_SAS
    }

    /**
     * Records that this device's human confirmed the displayed SAS matches, and returns the
     * [SasConfirmation] that [onInviterComplete] requires. Only callable once the SAS is available
     * — i.e. after [onInviterConfirm] has verified the inviter's MAC and opened the commitment —
     * so the human gate cannot be skipped by jumping straight to completion.
     */
    fun confirmSas(): SasConfirmation {
        requireStage(JoinerStage.AWAITING_SAS)
        stage = JoinerStage.SAS_CONFIRMED
        return SasConfirmation(this)
    }

    /**
     * Verifies the log and unwraps the master key. Requires the [SasConfirmation] from
     * [confirmSas] — the master key is never accepted without the human gate, so a MITM that
     * substituted its own hello cannot get this device to accept the attacker's chosen key by
     * skipping the confirm step. Success is terminal: the session scrubs its secrets on the way out.
     */
    fun onInviterComplete(complete: InviterComplete, confirmation: SasConfirmation) {
        requireStage(JoinerStage.SAS_CONFIRMED)
        if (confirmation.session !== this) throw PairingException("SAS confirmation belongs to a different session")
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
        stage = JoinerStage.COMPLETED
        destroy()
    }

    /** Every context key recovered from the inviter; throws if pairing has not completed. */
    fun calendarKeys(): EpochKeys = recoveredKeys ?: throw PairingException("Pairing is not complete")

    /** The key currently sealed under; throws if pairing has not completed. */
    fun masterKey(): ByteArray = calendarKeys().currentKey

    /** The verified log received from the inviter; null before [onInviterComplete]. */
    fun membershipLog(): MembershipLog? = membershipLog
}
