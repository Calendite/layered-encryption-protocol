package org.layeredencryption.invite

import org.layeredencryption.toHexString

/**
 * The durable summary of a pending async invite (Async_Invites_Spec.md §4.2).
 *
 * These are the bytes needed to *resume* an invite after the inviting app is killed while the
 * partner sleeps: the secret, the invite X-Wing keypair, the context master key to release, the
 * expiry, and the current state. The live claimed-context (`K_async`, transcript) is deliberately
 * **not** here — durable resume of an in-flight claim is a Phase 2 concern.
 *
 * Only `PENDING` and `CLAIMED` invites exist at rest: a terminal transition (`APPROVED`,
 * `REJECTED`, `EXPIRED`) removes the record and zeroes the invite-scoped key material instead of
 * writing it back. Context-master-key custody after approval is the application's
 * responsibility, outside this store.
 */
class PendingInvite(
    val ridAsync: ByteArray,
    val secret: ByteArray,
    val inviteXWingPublicKey: ByteArray,
    val inviteXWingPrivateKey: ByteArray,
    val masterKey: ByteArray,
    val expiryEpochSeconds: Long,
    val state: AsyncInviteState,
) {
    val ridAsyncHex: String get() = ridAsync.toHexString()
}

/**
 * Persistence for pending invites. Production implementation is hardware-wrapped at rest (design
 * §4.6) and deferred; [InMemoryInviteStore] is the reference implementation used in tests.
 *
 * A production adapter must treat these records as key material: encrypt them under a
 * platform-keystore-wrapped key, authenticate and rollback-protect them, and honour [remove]
 * eagerly — a removed invite's bytes should not survive in the backing storage. It must
 * not write them to backups or logs.
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
