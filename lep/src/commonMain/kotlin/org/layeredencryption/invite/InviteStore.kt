package org.layeredencryption.invite

import org.layeredencryption.toHexString

/**
 * The durable summary of a pending async invite (Async_Invites_Spec.md §4.2).
 *
 * These are the bytes needed to *resume* an invite after the inviting app is killed while the
 * partner sleeps: the secret, the invite X-Wing keypair, the context master key to release, the
 * expiry, and the current state — consumed by [AsyncInviter.resume].
 *
 * Only `PENDING` records exist at rest, ever. Claims are **non-resumable**: accepting a response
 * burns the durable record *before* the claim is published, so process death between claim and
 * approval burns the invite rather than persisting a `CLAIMED` state whose claim material
 * (`K_async`, transcript, joiner identity) could not be stored safely anyway. Terminal
 * transitions likewise remove the record and zero the invite-scoped key material.
 * Context-master-key custody after approval is the application's responsibility, outside this
 * store.
 */
class PendingInvite(
    ridAsync: ByteArray,
    secret: ByteArray,
    inviteXWingPublicKey: ByteArray,
    inviteXWingPrivateKey: ByteArray,
    masterKey: ByteArray,
    val expiryEpochSeconds: Long,
    val state: AsyncInviteState,
) {
    // Copied both ways: a record is a snapshot, not a window onto the live invite. Code holding
    // a store result cannot mutate an active invite's secrets, and cannot retain aliases the
    // invite's scrubbing would miss.
    private val _ridAsync = ridAsync.copyOf()
    private val _secret = secret.copyOf()
    private val _inviteXWingPublicKey = inviteXWingPublicKey.copyOf()
    private val _inviteXWingPrivateKey = inviteXWingPrivateKey.copyOf()
    private val _masterKey = masterKey.copyOf()

    val ridAsync: ByteArray get() = _ridAsync.copyOf()
    val secret: ByteArray get() = _secret.copyOf()
    val inviteXWingPublicKey: ByteArray get() = _inviteXWingPublicKey.copyOf()
    val inviteXWingPrivateKey: ByteArray get() = _inviteXWingPrivateKey.copyOf()
    val masterKey: ByteArray get() = _masterKey.copyOf()

    val ridAsyncHex: String get() = _ridAsync.toHexString()
}

/**
 * Persistence for pending invites. Production implementation is hardware-wrapped at rest (design
 * §4.6) and deferred; [InMemoryInviteStore] is the reference implementation used in tests.
 *
 * A production adapter must treat these records as key material: encrypt them under a
 * platform-keystore-wrapped key, authenticate and rollback-protect them, and honour [remove]
 * eagerly — a removed invite's bytes should not survive in the backing storage. It must
 * not write them to backups or logs. Envelope encryption is the preferred deletion story:
 * a unique data key per record, destroyed on removal, so journal pages and backups retain
 * only undecryptable ciphertext.
 *
 * ### Failure model
 * [put] and [remove] MAY throw — real keystores, databases, and disks fail. The library's
 * ordering makes each failure safe: a failed [put] aborts invite creation; a failed [remove] at
 * claim time leaves the invite fully `PENDING` and claimable (the exception propagates); a
 * failed [remove] at a terminal transition never resurrects the invite — the state is already
 * terminal, the secrets already scrubbed, and the failure is surfaced through
 * `AsyncInviter.requiresStoreCleanup` for retry. [remove] MUST be idempotent: removing an
 * absent record is a no-op, not an error.
 */
interface InviteStore {
    fun put(invite: PendingInvite)
    fun get(ridAsyncHex: String): PendingInvite?
    fun all(): List<PendingInvite>
    fun remove(ridAsyncHex: String)
}

class InMemoryInviteStore : InviteStore {
    private val invites = mutableMapOf<String, PendingInvite>()

    override fun put(invite: PendingInvite) {
        invites[invite.ridAsyncHex] = invite
    }

    override fun get(ridAsyncHex: String): PendingInvite? = invites[ridAsyncHex]

    override fun all(): List<PendingInvite> = invites.values.toList()

    override fun remove(ridAsyncHex: String) {
        invites.remove(ridAsyncHex)
    }
}
