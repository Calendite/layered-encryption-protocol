package org.layeredencryption.invite

import org.layeredencryption.Cascade
import org.layeredencryption.CryptoProvider
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
import org.layeredencryption.ProtocolLock
import org.layeredencryption.toHexString

/** Invite lifecycle (Async_Invites_Spec.md §2.1). */
enum class AsyncInviteState { PENDING, CLAIMED, APPROVED, REJECTED, EXPIRED }

// ── Wire messages (§2.4) ──────────────────────────────────────────────────────────────────────

/**
 * Posted by the joiner S at `rid_async`; gated on link possession twice: [linkProofMac] is the
 * cheap pre-authentication gate the inviter checks before any expensive cryptography, and
 * [joinerMac] binds the full handshake once the key agreement has run.
 *
 * Arrays are copied on construction: what the inviter verifies is this message's own snapshot.
 */
class AsyncJoinerResponse(
    kemCiphertext: ByteArray,
    val deviceIdentityS: DeviceIdentity,
    linkProofMac: ByteArray,
    joinerMac: ByteArray,
) {
    val kemCiphertext: ByteArray = kemCiphertext.copyOf()
    val linkProofMac: ByteArray = linkProofMac.copyOf()
    val joinerMac: ByteArray = joinerMac.copyOf()
}

/** Emitted by the inviter A **only** from `approve()`: the master key inside a signed membership log. */
class AsyncDelivery(inviterMac: ByteArray, serialisedMembershipLog: ByteArray) {
    val inviterMac: ByteArray = inviterMac.copyOf()
    val serialisedMembershipLog: ByteArray = serialisedMembershipLog.copyOf()
}

/** The outcome of feeding a response to [AsyncInviter.onResponse]. */
sealed interface ResponseOutcome {
    /** First valid response: the invite is now CLAIMED and awaiting the owner's approval. */
    data class Claimed(val shortAuthString: String, val joinerFingerprint: ByteArray) : ResponseOutcome
    /** A later valid response arrived after the invite was already claimed (the real partner sees the race). */
    data object AlreadyClaimed : ResponseOutcome
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
            provider, secret, ridAsync, response.kemCiphertext, response.deviceIdentityS,
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

        // The transition burns the durable record before anything is published (non-resumable
        // claims). If the store throws, nothing has changed — no claim, still PENDING — and the
        // storage fault propagates to the caller, which is a different thing than a peer verdict.
        transitionTo(AsyncInviteState.CLAIMED)
        claim = evaluated.claim
        return ResponseOutcome.Claimed(evaluated.shortAuthString, evaluated.joinerFingerprint)
    }

    private class Evaluated(val claim: Claim, val shortAuthString: String, val joinerFingerprint: ByteArray)

    /** The expensive half of response handling: identity binding, KEM, DH, HKDF, handshake MAC. */
    private fun evaluateResponse(response: AsyncJoinerResponse): Evaluated? {
        if (!response.deviceIdentityS.verifyBinding(provider)) return null

        val sharedSecret = XWing.decapsulate(provider, inviteXWing.privateKey, response.kemCiphertext)
        val dh1 = AsyncHandshake.contributoryDh(
            provider, XWing.x25519SecretComponent(provider, inviteXWing.privateKey), response.deviceIdentityS.x25519IdentityPublicKey,
        )
        val transcript = AsyncHandshake.transcript(
            ridAsync, expiryEpochSeconds, inviteXWing.publicKey, device.identity, response.kemCiphertext, response.deviceIdentityS,
        )
        val asyncKey = AsyncHandshake.asyncKey(provider, sharedSecret, dh1, transcript)

        val expectedJoinerMac = Handshake.mac(provider, asyncKey + secret, transcript, PairingRole.JOINER)
        if (!response.joinerMac.constantTimeEquals(expectedJoinerMac)) return null

        return Evaluated(
            claim = Claim(asyncKey, transcript, response.deviceIdentityS),
            shortAuthString = AsyncHandshake.shortAuthString(provider, sharedSecret, dh1, transcript),
            joinerFingerprint = InviteLink.fingerprintOf(provider, response.deviceIdentityS),
        )
    }

    /** Releases the master key: the approval gate (§2.1). Only valid from `CLAIMED`. Burns the slot. */
    fun approve(): AsyncDelivery = claimLock.withLock {
        val claim = claim ?: throw PairingException("approve() before a claim")
        if (state != AsyncInviteState.CLAIMED) throw PairingException("approve() not in CLAIMED state")

        val inviterMac = Handshake.mac(provider, claim.asyncKey + secret, claim.transcript, PairingRole.INVITER)
        val wrappedMasterKey = Cascade.seal(provider, claim.asyncKey, masterKey, aad = claim.joiner.serialise())
        val log = MembershipLog.found(provider, device.identity, device.signingKeyPair)
            .append(provider, MembershipOp.ADD, claim.joiner, wrappedMasterKey, signer = device.signingKeyPair)

        transitionTo(AsyncInviteState.APPROVED)
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
     * - `PENDING → CLAIMED` removes the durable record *before* publishing anything: claims are
     *   non-resumable, so the record is burned first, and a store failure propagates with the
     *   invite unchanged — still fully `PENDING`, durable, and claimable.
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
            store?.remove(ridAsync.toHexString()) // may throw: nothing has been published yet
            state = next
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
        ): AsyncInviter {
            require(expiryEpochSeconds > nowEpochSeconds) { "Invite expiry must be in the future" }
            require(expiryEpochSeconds - nowEpochSeconds <= MAX_LIFETIME_SECONDS) {
                "Invite lifetime must be at most $MAX_LIFETIME_SECONDS seconds"
            }
            val secret = provider.randomBytes(InviteLink.SECRET_SIZE)
            val ridAsync = AsyncRendezvous.id(provider, secret)
            val inviteXWing = XWing.generateKeyPair(provider)
            val masterKey = provider.randomBytes(MASTER_KEY_SIZE)
            val bundle = InviteBundle.build(provider, inviteXWing.publicKey, device.identity, expiryEpochSeconds, ridAsync, device.signingKeyPair)
            val link = InviteLink.create(provider, secret, device.identity)
            val inviter = AsyncInviter(provider, device, secret, ridAsync, inviteXWing, masterKey, bundle, link, expiryEpochSeconds, store)
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
        ): AsyncInviter {
            if (pending.state != AsyncInviteState.PENDING) {
                throw PairingException("Only PENDING invites are resumable, was ${pending.state}")
            }
            if (nowEpochSeconds > pending.expiryEpochSeconds) {
                store?.remove(pending.ridAsyncHex)
                throw PairingException("Invite expired while stored")
            }
            val bundle = InviteBundle.build(
                provider, pending.inviteXWingPublicKey, device.identity, pending.expiryEpochSeconds, pending.ridAsync, device.signingKeyPair,
            )
            val link = InviteLink.create(provider, pending.secret, device.identity)
            return AsyncInviter(
                provider, device, pending.secret, pending.ridAsync,
                KeyPair(publicKey = pending.inviteXWingPublicKey, privateKey = pending.inviteXWingPrivateKey),
                pending.masterKey, bundle, link, pending.expiryEpochSeconds, store,
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
) {
    private var context: Context? = null
    private var recoveredMasterKey: ByteArray? = null

    var shortAuthString: String? = null
        private set

    private class Context(val asyncKey: ByteArray, val expectedInviterMac: ByteArray)

    /** Verifies the bundle (§2.7) and returns the response proving link possession. */
    fun onBundle(link: InviteLink, bundle: InviteBundle, nowEpochSeconds: Long): AsyncJoinerResponse {
        val ridAsync = AsyncRendezvous.id(provider, link.secret)

        // §2.7 step 2 — anti-directory: a relay that swapped the bundle fails here.
        if (!InviteLink.fingerprintOf(provider, bundle.deviceIdentityA).contentEquals(link.fingerprint)) {
            throw PairingException("Bundle fingerprint does not match the link")
        }
        if (!bundle.deviceIdentityA.verifyBinding(provider)) throw PairingException("Bundle device-identity binding is invalid")
        if (!bundle.verifySignature(provider, ridAsync)) throw PairingException("Bundle signature is invalid")
        if (nowEpochSeconds > bundle.expiryEpochSeconds + CLOCK_SKEW_SECONDS) throw PairingException("Bundle has expired")

        val encapsulation = XWing.encapsulate(provider, bundle.inviteXWingPublicKey)
        val dh1 = AsyncHandshake.contributoryDh(
            provider, device.x25519IdentityPrivateKey, XWing.x25519PublicComponent(bundle.inviteXWingPublicKey),
        )
        val transcript = AsyncHandshake.transcript(
            ridAsync, bundle.expiryEpochSeconds, bundle.inviteXWingPublicKey, bundle.deviceIdentityA, encapsulation.ciphertext, device.identity,
        )
        val asyncKey = AsyncHandshake.asyncKey(provider, encapsulation.sharedSecret, dh1, transcript)

        shortAuthString = AsyncHandshake.shortAuthString(provider, encapsulation.sharedSecret, dh1, transcript)
        context = Context(
            asyncKey = asyncKey,
            expectedInviterMac = Handshake.mac(provider, asyncKey + link.secret, transcript, PairingRole.INVITER),
        )
        return AsyncJoinerResponse(
            kemCiphertext = encapsulation.ciphertext,
            deviceIdentityS = device.identity,
            linkProofMac = AsyncHandshake.linkProofMac(provider, link.secret, ridAsync, encapsulation.ciphertext, device.identity),
            joinerMac = Handshake.mac(provider, asyncKey + link.secret, transcript, PairingRole.JOINER),
        )
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
            throw PairingException("Inviter MAC mismatch")
        }

        recoveredMasterKey = try {
            unwrapMasterKey(context, delivery)
        } catch (e: PairingException) {
            throw e
        } catch (e: Exception) {
            throw PairingException("Malformed delivery")
        }
        context.asyncKey.fill(0)
        this.context = null
    }

    private fun unwrapMasterKey(context: Context, delivery: AsyncDelivery): ByteArray {
        val log = MembershipLog.deserialise(delivery.serialisedMembershipLog)
        val verification = log.verify(provider)
        if (verification !is MembershipVerification.Valid) throw PairingException("Membership log failed verification: $verification")

        val ownKey = device.identity.signingPublicKey
        if (ownKey.toHexString() !in verification.activeMembers) throw PairingException("This device is not in the membership log")

        val entry = log.addEntryFor(ownKey) ?: throw PairingException("No ADD entry for this device")
        val wrapped = entry.wrappedKeys ?: throw PairingException("No wrapped keys for this device")
        return Cascade.open(provider, context.asyncKey, wrapped, aad = device.identity.serialise())
    }

    /** The recovered context master key, as a defensive copy. */
    fun masterKey(): ByteArray = recoveredMasterKey?.copyOf() ?: throw PairingException("Invite is not complete")

    private companion object {
        const val CLOCK_SKEW_SECONDS = 300L
    }
}
