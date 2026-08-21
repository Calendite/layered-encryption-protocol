package org.layeredencryption.invite

import dev.diagnostics.Diagnostics
import org.layeredencryption.CryptoProvider
import org.layeredencryption.LepTag
import org.layeredencryption.KeyPair
import org.layeredencryption.XWing
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.pairing.Handshake
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.PairingRole
import org.layeredencryption.pairing.constantTimeEquals
import org.layeredencryption.ProtocolLimits
import org.layeredencryption.ProtocolLock
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.suite.Suite1
import org.layeredencryption.toHexString

/** Invite lifecycle (Async_Invites_Spec.md §2.1). */
enum class AsyncInviteState { PENDING, CLAIMED, APPROVED, REJECTED, EXPIRED }

// ── Wire messages (§2.4) ──────────────────────────────────────────────────────────────────────

/**
 * Posted by the joiner S at `rid_async`; gated on link possession twice: [linkProofMac] is the
 * cheap pre-authentication gate the inviter checks before any expensive cryptography, and
 * [joinerMac] binds the full handshake once the key agreement has run.
 *
 * The constructor validates the protocol-fixed sizes **before** copying (a transport feeding it
 * peer bytes should treat the [IllegalArgumentException] as "invalid message"), and every read
 * returns a copy — the message is an immutable snapshot from construction onward.
 */
class AsyncJoinerResponse(
    kemCiphertext: ByteArray,
    val deviceIdentityS: DeviceIdentity,
    linkProofMac: ByteArray,
    joinerMac: ByteArray,
) {
    init {
        require(kemCiphertext.size == XWing.CIPHERTEXT_SIZE) { "KEM ciphertext must be ${XWing.CIPHERTEXT_SIZE} bytes" }
        require(linkProofMac.size == WIRE_MAC_BYTES) { "linkProofMac must be $WIRE_MAC_BYTES bytes" }
        require(joinerMac.size == WIRE_MAC_BYTES) { "joinerMac must be $WIRE_MAC_BYTES bytes" }
    }

    private val _kemCiphertext = kemCiphertext.copyOf()
    private val _linkProofMac = linkProofMac.copyOf()
    private val _joinerMac = joinerMac.copyOf()

    val kemCiphertext: ByteArray get() = _kemCiphertext.copyOf()
    val linkProofMac: ByteArray get() = _linkProofMac.copyOf()
    val joinerMac: ByteArray get() = _joinerMac.copyOf()
}

/**
 * Emitted by the inviter A **only** from `approve()`: the master key inside a signed membership
 * log. Sizes are validated before the copies are made; reads return copies.
 */
class AsyncDelivery(inviterMac: ByteArray, serialisedMembershipLog: ByteArray) {
    init {
        require(inviterMac.size == WIRE_MAC_BYTES) { "inviterMac must be $WIRE_MAC_BYTES bytes" }
        require(serialisedMembershipLog.size <= ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES) {
            "Membership log of ${serialisedMembershipLog.size} bytes exceeds the ${ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES}-byte limit"
        }
    }

    private val _inviterMac = inviterMac.copyOf()
    private val _serialisedMembershipLog = serialisedMembershipLog.copyOf()

    val inviterMac: ByteArray get() = _inviterMac.copyOf()
    val serialisedMembershipLog: ByteArray get() = _serialisedMembershipLog.copyOf()
}

/** HMAC-SHA256 output: the size of every MAC on the async wire. */
private const val WIRE_MAC_BYTES = 32

/** The outcome of feeding a response to [AsyncInviter.onResponse]. */
sealed interface ResponseOutcome {
    /** First valid response: the invite is now CLAIMED and awaiting the owner's approval. */
    class Claimed(val shortAuthString: String, joinerFingerprint: ByteArray) : ResponseOutcome {
        private val _joinerFingerprint = joinerFingerprint.copyOf()

        /** The fingerprint to show the owner, as a defensive copy. */
        val joinerFingerprint: ByteArray get() = _joinerFingerprint.copyOf()
    }
    /** A later valid response arrived after the invite was already claimed (the real partner sees the race). */
    data object AlreadyClaimed : ResponseOutcome

    /**
     * Another instance that resumed the same durable record won the store's atomic consume: the
     * invite was claimed elsewhere, not here. Distinct from [Invalid] (the response was fine) and
     * from a storage fault (which throws) — this instance is dead and has expired itself.
     */
    data object ConsumedElsewhere : ResponseOutcome
    /** Bad MAC or bad identity binding — dropped without any state change. */
    data object Invalid : ResponseOutcome
    /** The invite had expired. */
    data object Expired : ResponseOutcome
}

/**
 * The inviting device's side of an async invite (Async_Invites_Spec.md §2).
 *
 * `create` publishes a signed bundle + link and holds the invite in `PENDING`. A valid response
 * moves it to `CLAIMED` (surfacing the SAS + joiner fingerprint for the owner). The master key is
 * released **only** on the owner's explicit `approve()` — the approval gate is what makes an
 * asynchronous, unattended invite safe.
 */
class AsyncInviter private constructor(
    private val provider: CryptoProvider,
    private val device: DeviceKeys,
    private val secret: ByteArray,
    private val ridAsync: ByteArray,
    private val inviteXWing: KeyPair,
    private val masterKey: ByteArray,
    val bundle: InviteBundle,
    val link: InviteLink,
    val expiryEpochSeconds: Long,
    private val store: InviteStore?,
    private val namespace: ProtocolNamespace,
) {
    var state: AsyncInviteState = AsyncInviteState.PENDING
        private set

    private var claim: Claim? = null

    /**
     * Serialises response handling. The PENDING check and the claim are separated by a KEM
     * decapsulation, a DH and an HKDF, so without this two responses could both pass the check and
     * the second would overwrite the claim — leaving the owner approving one device's fingerprint
     * and SAS while granting access to another. The approval gate is the whole security argument
     * for unattended invites, so that binding has to hold.
     */
    private val claimLock = ProtocolLock()

    private class Claim(val asyncKey: ByteArray, val transcript: ByteArray, val joiner: DeviceIdentity)

    /**
     * Ingests a joiner response. Only a `PENDING` invite accepts one; the first valid response claims
     * it. Invalid responses are dropped without state change; later valid ones report [ResponseOutcome.AlreadyClaimed].
     *
     * Never throws for peer-supplied input — every malformed or hostile response maps to a
     * [ResponseOutcome]. A *local storage fault* is different: if burning the durable record at
     * claim time throws, that exception propagates with the invite unchanged (still `PENDING`
     * and claimable), because a store being down is not a verdict about the peer.
     *
     * What this cannot do from inside the library: bound how *often* it is called. The transport
     * in front of it should rate-limit each rendezvous and cap concurrent responses, even though
     * a failed response is cheap.
     */
    fun onResponse(response: AsyncJoinerResponse, nowEpochSeconds: Long): ResponseOutcome =
        claimLock.withLock { handleResponse(response, nowEpochSeconds) }

    private fun handleResponse(response: AsyncJoinerResponse, nowEpochSeconds: Long): ResponseOutcome {
        if (state == AsyncInviteState.EXPIRED) return ResponseOutcome.Expired
        if (state != AsyncInviteState.PENDING) return ResponseOutcome.AlreadyClaimed
        if (nowEpochSeconds > expiryEpochSeconds) return expire()

        // Exact sizes before any cryptography: malformed responses cost nothing.
        if (response.kemCiphertext.size != XWing.CIPHERTEXT_SIZE) return ResponseOutcome.Invalid
        if (response.linkProofMac.size != MAC_SIZE) return ResponseOutcome.Invalid
        if (response.joinerMac.size != MAC_SIZE) return ResponseOutcome.Invalid

        // The cheap link-possession gate: one HMAC, verified before the hybrid
        // identity signatures, ML-KEM decapsulation, and X25519 below. A responder who never saw
        // the link stops here without making us spend post-quantum compute.
        val expectedLinkProof = AsyncHandshake.linkProofMac(
            provider, secret, ridAsync, response.kemCiphertext, response.deviceIdentityS, namespace,
        )
        if (!response.linkProofMac.constantTimeEquals(expectedLinkProof)) return ResponseOutcome.Invalid

        // A link holder can still send garbage — a mangled KEM ciphertext, a low-order X25519
        // point — and the provider failures that provokes are protocol-invalid input, not
        // programming errors. They must surface as [ResponseOutcome.Invalid], never as an
        // exception that could tear down a consumer's request handler or service loop.
        val evaluated = try {
            evaluateResponse(response)
        } catch (e: Exception) {
            null
        } ?: return ResponseOutcome.Invalid

        // The single-use gate: publishing a claim requires *winning* the store's atomic consume,
        // which burns the durable record (non-resumable claims). Exactly one instance wins, even
        // when several processes resumed the same record. Losing is not a storage fault — another
        // instance claimed first — so this instance expires itself (terminal scrub; the record is
        // already gone) and reports the loss distinctly. A store *exception* still propagates
        // with nothing changed: no claim, still PENDING.
        //
        // The key derived during evaluation is owned by the session only once the claim is
        // published; every other exit — losing the consume, the store throwing — scrubs it here,
        // so a losing instance holds no usable session key.
        var ownershipTransferred = false
        try {
            if (store != null && !store.consume(ridAsync.toHexString())) {
                transitionTo(AsyncInviteState.EXPIRED)
                return ResponseOutcome.ConsumedElsewhere
            }
            claim = evaluated.claim
            ownershipTransferred = true
            transitionTo(AsyncInviteState.CLAIMED)
            Diagnostics.debug(LepTag.INVITE) { "invite claimed; awaiting the owner's approval" }
            return ResponseOutcome.Claimed(evaluated.shortAuthString, evaluated.joinerFingerprint)
        } finally {
            if (!ownershipTransferred) evaluated.claim.asyncKey.fill(0)
        }
    }

    private class Evaluated(val claim: Claim, val shortAuthString: String, val joinerFingerprint: ByteArray)

    /**
     * The expensive half of response handling: identity binding, KEM, DH, HKDF, handshake MAC.
     *
     * Every derived secret is scrubbed on the way out unless its ownership transfers into the
     * returned [Evaluated] (RT-05): an invalid MAC — or any exception past derivation — must not
     * leave the shared secret, the identity DH, or a rejected async key waiting for the garbage
     * collector.
     */
    private fun evaluateResponse(response: AsyncJoinerResponse): Evaluated? {
        if (!response.deviceIdentityS.verifyBinding(provider, namespace)) {
            Diagnostics.warning(LepTag.INVITE) { "response rejected: joiner identity binding does not verify" }
            return null
        }

        var sharedSecret: ByteArray? = null
        var x25519Secret: ByteArray? = null
        var dh1: ByteArray? = null
        var asyncKey: ByteArray? = null
        var macKey: ByteArray? = null
        var asyncKeyTransferred = false
        try {
            sharedSecret = Suite1.kem.decapsulate(provider, inviteXWing.privateKey, response.kemCiphertext)
            x25519Secret = Suite1.kem.x25519SecretComponent(provider, inviteXWing.privateKey)
            dh1 = AsyncHandshake.contributoryDh(provider, x25519Secret, response.deviceIdentityS.x25519IdentityPublicKey)
            val transcript = AsyncHandshake.transcript(
                ridAsync, expiryEpochSeconds, inviteXWing.publicKey, device.identity, response.kemCiphertext, response.deviceIdentityS, namespace,
            )
            asyncKey = AsyncHandshake.asyncKey(provider, sharedSecret, dh1, transcript, namespace)

            macKey = asyncKey + secret
            val expectedJoinerMac = Handshake.mac(provider, macKey, transcript, PairingRole.JOINER)
            if (!response.joinerMac.constantTimeEquals(expectedJoinerMac)) {
                Diagnostics.warning(LepTag.INVITE) { "response rejected: joiner MAC mismatch — wrong link secret or tampering" }
                return null
            }

            val evaluated = Evaluated(
                claim = Claim(asyncKey, transcript, response.deviceIdentityS),
                shortAuthString = AsyncHandshake.shortAuthString(provider, sharedSecret, dh1, transcript, namespace),
                joinerFingerprint = InviteLink.fingerprintOf(provider, response.deviceIdentityS),
            )
            asyncKeyTransferred = true
            return evaluated
        } finally {
            sharedSecret?.fill(0)
            x25519Secret?.fill(0)
            dh1?.fill(0)
            macKey?.fill(0)
            if (!asyncKeyTransferred) asyncKey?.fill(0)
        }
    }

    /** Releases the master key: the approval gate (§2.1). Only valid from `CLAIMED`. Burns the slot. */
    fun approve(): AsyncDelivery = claimLock.withLock {
        val claim = claim ?: throw PairingException("approve() before a claim")
        if (state != AsyncInviteState.CLAIMED) throw PairingException("approve() not in CLAIMED state")

        val macKey = claim.asyncKey + secret
        val inviterMac = try {
            Handshake.mac(provider, macKey, claim.transcript, PairingRole.INVITER)
        } finally {
            macKey.fill(0)
        }
        val wrappedMasterKey = Suite1.aead.seal(provider, claim.asyncKey, masterKey, aad = claim.joiner.serialise(), namespace = namespace)
        val log = MembershipLog.found(provider, device.identity, device.signingKeyPair, namespace = namespace)
            .append(provider, MembershipOp.ADD, claim.joiner, wrappedMasterKey, signer = device.signingKeyPair, namespace = namespace)

        transitionTo(AsyncInviteState.APPROVED)
        Diagnostics.debug(LepTag.INVITE) { "invite approved: master key released with a founding membership log" }
        AsyncDelivery(inviterMac, log.serialise())
    }

    /**
     * Declines a claimed invite. Burns the slot: the terminal transition scrubs the invite's
     * secrets and store record. Shares [claimLock] with [approve] and [onResponse], so a racing
     * approve/reject resolves to exactly one outcome.
     */
    fun reject(): Unit = claimLock.withLock {
        if (state != AsyncInviteState.CLAIMED) throw PairingException("reject() not in CLAIMED state")
        transitionTo(AsyncInviteState.REJECTED)
    }

    /**
     * The context master key, as a defensive copy. It deliberately survives terminal
     * states: the inviter's context may already hold data under this key, so its custody after
     * the invite ends belongs to the caller, not to this object or the [InviteStore].
     */
    fun masterKey(): ByteArray = claimLock.withLock { masterKey.copyOf() }

    private fun expire(): ResponseOutcome.Expired {
        transitionTo(AsyncInviteState.EXPIRED)
        return ResponseOutcome.Expired
    }

    /**
     * True when a terminal transition could not remove the durable record. The invite itself is
     * already dead — its state is terminal and its secrets are scrubbed — but the store still
     * holds a stale `PENDING` record. Retry via [retryStoreCleanup]. A record that survives
     * repeated retries is what the rollback-protection requirements on [InviteStore] exist for.
     */
    var requiresStoreCleanup: Boolean = false
        private set

    /** Retries the durable-record removal that a failed terminal transition left behind. */
    fun retryStoreCleanup(): Unit = claimLock.withLock {
        if (requiresStoreCleanup) {
            store?.remove(ridAsync.toHexString())
            requiresStoreCleanup = false
        }
    }

    /**
     * The single place state changes, always under [claimLock] and validated against
     * [ALLOWED_TRANSITIONS] — an impossible step is a protocol bug and throws.
     *
     * The storage failure model (LEP-07 retest, issue 7.2): stores can throw, so each transition
     * is ordered to fail safe.
     *
     * - `PENDING → CLAIMED` is published only after the caller has *won* `store.consume()` (see
     *   the claim path in `handleResponse`): claims are non-resumable and single-use across
     *   every instance that resumed the record.
     * - Terminal transitions publish the state first, then scrub the link secret, invite KEM
     *   seed, and claimed session key **unconditionally** (in a `finally`). A store failure
     *   cannot resurrect the invite or lose an [approve] delivery: it is recorded in
     *   [requiresStoreCleanup] instead of thrown. The master key is deliberately kept; see
     *   [masterKey].
     */
    private fun transitionTo(next: AsyncInviteState) {
        if (next !in ALLOWED_TRANSITIONS.getValue(state)) {
            throw PairingException("Illegal invite transition: $state → $next")
        }
        if (next == AsyncInviteState.CLAIMED) {
            state = next // the durable record was consumed by the caller before publishing
            return
        }
        state = next
        try {
            store?.remove(ridAsync.toHexString())
        } catch (e: Exception) {
            requiresStoreCleanup = true
        } finally {
            secret.fill(0)
            inviteXWing.privateKey.fill(0)
            claim?.asyncKey?.fill(0)
            claim = null
        }
    }

    /** Test probe: whether the invite-scoped secrets are zeroed and the claim dropped. */
    internal fun isScrubbed(): Boolean =
        claim == null &&
            secret.all { it == 0.toByte() } &&
            inviteXWing.privateKey.all { it == 0.toByte() }

    private fun toPending() = PendingInvite(
        ridAsync = ridAsync,
        secret = secret,
        inviteXWingPublicKey = inviteXWing.publicKey,
        inviteXWingPrivateKey = inviteXWing.privateKey,
        masterKey = masterKey,
        expiryEpochSeconds = expiryEpochSeconds,
        state = state,
    )

    companion object {
        /**
         * Creates an invite: generates the bundle + link, master key, and holds `PENDING`.
         *
         * The lifetime is bounded **here**, not in UI code: the expiry must lie in the
         * future and at most [MAX_LIFETIME_SECONDS] away. `rid_async` hands the relay an offline
         * verifier for the link secret, so an invite's exposure window is a security parameter the
         * library owns, not a preference.
         */
        fun create(
            provider: CryptoProvider,
            device: DeviceKeys,
            nowEpochSeconds: Long,
            expiryEpochSeconds: Long,
            store: InviteStore? = null,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): AsyncInviter {
            require(expiryEpochSeconds > nowEpochSeconds) { "Invite expiry must be in the future" }
            require(expiryEpochSeconds - nowEpochSeconds <= MAX_LIFETIME_SECONDS) {
                "Invite lifetime must be at most $MAX_LIFETIME_SECONDS seconds"
            }
            val secret = provider.randomBytes(InviteLink.SECRET_SIZE)
            val ridAsync = AsyncRendezvous.id(provider, secret, namespace)
            val inviteXWing = Suite1.kem.generateKeyPair(provider)
            val masterKey = provider.randomBytes(MASTER_KEY_SIZE)
            val bundle = InviteBundle.build(provider, inviteXWing.publicKey, device.identity, expiryEpochSeconds, ridAsync, device.signingKeyPair, namespace)
            val link = InviteLink.create(provider, secret, device.identity)
            val inviter = AsyncInviter(provider, device, secret, ridAsync, inviteXWing, masterKey, bundle, link, expiryEpochSeconds, store, namespace)
            store?.put(inviter.toPending())
            return inviter
        }

        /** The longest an async invite may stay live: seven days. */
        const val MAX_LIFETIME_SECONDS = 7 * 86_400L

        private const val MASTER_KEY_SIZE = 32
        private const val MAC_SIZE = 32

        /** The lifecycle DAG (§2.1): the single source of truth for legal state changes. */
        private val ALLOWED_TRANSITIONS = mapOf(
            AsyncInviteState.PENDING to setOf(AsyncInviteState.CLAIMED, AsyncInviteState.EXPIRED),
            AsyncInviteState.CLAIMED to setOf(AsyncInviteState.APPROVED, AsyncInviteState.REJECTED),
            AsyncInviteState.APPROVED to emptySet(),
            AsyncInviteState.REJECTED to emptySet(),
            AsyncInviteState.EXPIRED to emptySet(),
        )

        /**
         * Restores a `PENDING` invite from its durable record — the other half of the
         * non-resumable-claim policy (LEP-07 retest, issue 7.3): `PENDING` is the *only* state
         * the store ever holds, and this is the only way back in. The bundle is re-signed rather
         * than stored; any valid signature over the same fields verifies, and the link's
         * fingerprint pins the identity, which is unchanged.
         *
         * An expired record is not restored: it is removed from the store and reported, so a
         * dead invite cannot be resurrected by replaying an old snapshot.
         */
        fun resume(
            provider: CryptoProvider,
            device: DeviceKeys,
            pending: PendingInvite,
            nowEpochSeconds: Long,
            store: InviteStore? = null,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): AsyncInviter {
            if (pending.state != AsyncInviteState.PENDING) {
                throw PairingException("Only PENDING invites are resumable, was ${pending.state}")
            }
            if (nowEpochSeconds > pending.expiryEpochSeconds) {
                store?.remove(pending.ridAsyncHex)
                throw PairingException("Invite expired while stored")
            }
            val bundle = InviteBundle.build(
                provider, pending.inviteXWingPublicKey, device.identity, pending.expiryEpochSeconds, pending.ridAsync, device.signingKeyPair, namespace,
            )
            val link = InviteLink.create(provider, pending.secret, device.identity)
            return AsyncInviter(
                provider, device, pending.secret, pending.ridAsync,
                KeyPair(publicKey = pending.inviteXWingPublicKey, privateKey = pending.inviteXWingPrivateKey),
                pending.masterKey, bundle, link, pending.expiryEpochSeconds, store, namespace,
            )
        }
    }
}

/**
 * The joining device's side of an async invite (Async_Invites_Spec.md §2.7).
 *
 * `onBundle` runs the strict verification order — fingerprint pin, identity binding, bundle
 * signature, expiry — before encapsulating and proving link possession via its MAC. After the owner
 * approves, `onDelivery` verifies the log and unwraps the master key.
 */
class AsyncJoiner(
    private val provider: CryptoProvider,
    private val device: DeviceKeys,
    /** Domain-separates every derivation (LEP-10); must match the inviter's. */
    private val namespace: ProtocolNamespace = ProtocolNamespace.Default,
) {
    private var context: Context? = null
    private var recoveredMasterKey: ByteArray? = null

    var shortAuthString: String? = null
        private set

    private class Context(val asyncKey: ByteArray, val expectedInviterMac: ByteArray)

    /** Verifies the bundle (§2.7) and returns the response proving link possession. */
    fun onBundle(link: InviteLink, bundle: InviteBundle, nowEpochSeconds: Long): AsyncJoinerResponse {
        val ridAsync = AsyncRendezvous.id(provider, link.secret, namespace)

        // §2.7 step 2 — anti-directory: a relay that swapped the bundle fails here.
        if (!InviteLink.fingerprintOf(provider, bundle.deviceIdentityA).contentEquals(link.fingerprint)) {
            Diagnostics.warning(LepTag.INVITE) { "bundle rejected: fingerprint does not match the link — a swapped bundle" }
            throw PairingException("Bundle fingerprint does not match the link")
        }
        if (!bundle.deviceIdentityA.verifyBinding(provider, namespace)) {
            Diagnostics.warning(LepTag.INVITE) { "bundle rejected: inviter identity binding does not verify" }
            throw PairingException("Bundle device-identity binding is invalid")
        }
        if (!bundle.verifySignature(provider, ridAsync, namespace)) {
            Diagnostics.warning(LepTag.INVITE) { "bundle rejected: signature does not verify" }
            throw PairingException("Bundle signature is invalid")
        }
        if (nowEpochSeconds > bundle.expiryEpochSeconds + CLOCK_SKEW_SECONDS) {
            Diagnostics.debug(LepTag.INVITE) { "bundle rejected: expired" }
            throw PairingException("Bundle has expired")
        }

        val encapsulation = Suite1.kem.encapsulate(provider, bundle.inviteXWingPublicKey)
        var dh1: ByteArray? = null
        var asyncKey: ByteArray? = null
        var macKey: ByteArray? = null
        var asyncKeyTransferred = false
        try {
            dh1 = AsyncHandshake.contributoryDh(
                provider, device.x25519IdentityPrivateKey, Suite1.kem.x25519PublicComponent(bundle.inviteXWingPublicKey),
            )
            val transcript = AsyncHandshake.transcript(
                ridAsync, bundle.expiryEpochSeconds, bundle.inviteXWingPublicKey, bundle.deviceIdentityA, encapsulation.ciphertext, device.identity, namespace,
            )
            asyncKey = AsyncHandshake.asyncKey(provider, encapsulation.sharedSecret, dh1, transcript, namespace)

            shortAuthString = AsyncHandshake.shortAuthString(provider, encapsulation.sharedSecret, dh1, transcript, namespace)
            macKey = asyncKey + link.secret
            context = Context(
                asyncKey = asyncKey,
                expectedInviterMac = Handshake.mac(provider, macKey, transcript, PairingRole.INVITER),
            )
            asyncKeyTransferred = true
            return AsyncJoinerResponse(
                kemCiphertext = encapsulation.ciphertext,
                deviceIdentityS = device.identity,
                linkProofMac = AsyncHandshake.linkProofMac(provider, link.secret, ridAsync, encapsulation.ciphertext, device.identity, namespace),
                joinerMac = Handshake.mac(provider, macKey, transcript, PairingRole.JOINER),
            )
        } finally {
            // The async key survives only by transferring into the session context; its inputs do
            // not survive the call at all (RT-05). A throw anywhere — the contributory-DH guard,
            // a provider failure mid-derivation — must not leave the KEM secret, the DH output,
            // or an untransferred key behind for the garbage collector.
            encapsulation.sharedSecret.fill(0)
            dh1?.fill(0)
            macKey?.fill(0)
            if (!asyncKeyTransferred) asyncKey?.fill(0)
        }
    }

    /**
     * Verifies the delivery and unwraps the master key.
     *
     * The MAC gate runs first, so the log parser only ever sees bytes from the authenticated
     * inviter. Failures past the gate — a malformed log as much as a failed check — surface as
     * [PairingException], never as a raw parser or provider exception. Success is
     * one-shot: the session context is scrubbed once the key is recovered.
     */
    fun onDelivery(delivery: AsyncDelivery) {
        val context = context ?: throw PairingException("onDelivery() before onBundle()")
        if (!delivery.inviterMac.constantTimeEquals(context.expectedInviterMac)) {
            Diagnostics.warning(LepTag.INVITE) { "delivery rejected: inviter MAC mismatch" }
            throw PairingException("Inviter MAC mismatch")
        }

        recoveredMasterKey = try {
            unwrapMasterKey(context, delivery)
        } catch (e: PairingException) {
            Diagnostics.warning(LepTag.INVITE, throwable = e) { "delivery rejected after the MAC gate" }
            throw e
        } catch (e: Exception) {
            // Raw parser/provider exceptions can embed the bytes they choked on, so the reference
            // goes through the unsafe slot: dropped unless the sink opted in at install time.
            Diagnostics.warning(LepTag.INVITE, unsafeThrowable = e) { "delivery rejected: malformed" }
            throw PairingException("Malformed delivery")
        }
        context.asyncKey.fill(0)
        this.context = null
        Diagnostics.debug(LepTag.INVITE) { "delivery accepted: context master key recovered" }
    }

    private fun unwrapMasterKey(context: Context, delivery: AsyncDelivery): ByteArray {
        val log = MembershipLog.deserialise(delivery.serialisedMembershipLog)
        val verification = log.verify(provider, namespace)
        if (verification !is MembershipVerification.Valid) throw PairingException("Membership log failed verification: $verification")

        val ownKey = device.identity.signingPublicKey
        if (ownKey.toHexString() !in verification.activeMembers) throw PairingException("This device is not in the membership log")

        val entry = log.addEntryFor(ownKey) ?: throw PairingException("No ADD entry for this device")
        val wrapped = entry.wrappedKeys ?: throw PairingException("No wrapped keys for this device")
        return Suite1.aead.open(provider, context.asyncKey, wrapped, aad = device.identity.serialise(), namespace = namespace)
    }

    /** The recovered context master key, as a defensive copy. */
    fun masterKey(): ByteArray = recoveredMasterKey?.copyOf() ?: throw PairingException("Invite is not complete")

    private companion object {
        const val CLOCK_SKEW_SECONDS = 300L
    }
}
