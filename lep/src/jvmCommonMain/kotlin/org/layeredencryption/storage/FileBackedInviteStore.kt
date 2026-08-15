package org.layeredencryption.storage

import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.invite.AsyncInviteState
import org.layeredencryption.invite.InviteStore
import org.layeredencryption.invite.PendingInvite
import java.nio.file.Path

/**
 * The production [InviteStore] (RT-02): pending records plus **permanent tombstones** in one
 * sealed, crash-safe, rollback-evident file (see [SealedStateFile] for the storage discipline).
 *
 * [key] is the 32-byte at-rest key and must come from the platform keystore in production; on
 * Android put [file] (and the witness) under `noBackupFilesDir`, so no backup ever contains
 * state whose restoration would resurrect a burned invite. Every mutation rewrites the whole
 * sealed blob, so a removed invite's secrets do not linger in the file, and consumed ids stay
 * tombstoned across restarts — [put] refuses them permanently. [consume] is the single-winner
 * claim gate, atomic across instances and processes via the engine's file lock.
 */
class FileBackedInviteStore private constructor(
    private val engine: SealedStateFile,
) : InviteStore {

    /**
     * The production constructor: rollback detection is required, not optional — an invite
     * store without a witness silently resurrects consumed invites when a stale snapshot is
     * restored. Storage without detection exists only under its honest name,
     * [withoutRollbackDetection].
     */
    constructor(
        file: Path,
        provider: CryptoProvider,
        key: ByteArray,
        witness: RevisionWitness,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ) : this(SealedStateFile(file, provider, key, STORE_KIND, witness, namespace))

    companion object {
        /**
         * A store whose rollback protection is somebody else's job — a platform without a second
         * storage location, or a test. Restoring a stale snapshot of this store resurrects
         * consumed invites without detection; the name is the consent form.
         */
        fun withoutRollbackDetection(
            file: Path,
            provider: CryptoProvider,
            key: ByteArray,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): FileBackedInviteStore =
            FileBackedInviteStore(SealedStateFile(file, provider, key, STORE_KIND, witness = null, namespace = namespace))

        private const val STORE_KIND = "invite-store"
        private const val MAX_FIELD = 4096
    }

    private class State(
        val records: LinkedHashMap<String, PendingInvite>,
        val tombstones: LinkedHashSet<String>,
    )

    override fun put(invite: PendingInvite): Unit = engine.transact { loaded, commit ->
        val state = parse(loaded.state)
        check(invite.ridAsyncHex !in state.tombstones) {
            "Invite ${invite.ridAsyncHex} was consumed; a stale snapshot cannot resurrect it"
        }
        state.records[invite.ridAsyncHex] = invite
        commit(serialise(state))
    }

    override fun get(ridAsyncHex: String): PendingInvite? = engine.transact { loaded, _ ->
        parse(loaded.state).records[ridAsyncHex]
    }

    override fun all(): List<PendingInvite> = engine.transact { loaded, _ ->
        parse(loaded.state).records.values.toList()
    }

    override fun consume(ridAsyncHex: String): Boolean = engine.transact { loaded, commit ->
        val state = parse(loaded.state)
        val won = state.records.remove(ridAsyncHex) != null
        if (won) {
            state.tombstones += ridAsyncHex
            commit(serialise(state))
        }
        won
    }

    override fun remove(ridAsyncHex: String): Unit = engine.transact { loaded, commit ->
        val state = parse(loaded.state)
        if (state.records.remove(ridAsyncHex) != null) {
            commit(serialise(state)) // cleanup only: removal never clears a tombstone
        }
    }

    private fun parse(bytes: ByteArray?): State {
        val state = State(LinkedHashMap(), LinkedHashSet())
        if (bytes == null) return state
        try {
            val reader = FrameReader(bytes)
            repeat(u32FromBytes(reader.readBytes(4))) {
                val invite = PendingInvite(
                    ridAsync = reader.readBytes(MAX_FIELD),
                    secret = reader.readBytes(MAX_FIELD),
                    inviteXWingPublicKey = reader.readBytes(MAX_FIELD),
                    inviteXWingPrivateKey = reader.readBytes(MAX_FIELD),
                    masterKey = reader.readBytes(MAX_FIELD),
                    expiryEpochSeconds = u64FromBytes(reader.readBytes(8)),
                    state = AsyncInviteState.valueOf(reader.readBytes(MAX_FIELD).decodeToString()),
                )
                state.records[invite.ridAsyncHex] = invite
            }
            repeat(u32FromBytes(reader.readBytes(4))) {
                state.tombstones += reader.readBytes(MAX_FIELD).decodeToString()
            }
            require(!reader.hasRemaining()) { "Trailing bytes after the tombstones" }
        } catch (e: Exception) {
            throw StoreCorruptionException("Invite-store state failed to parse", e)
        }
        return state
    }

    private fun serialise(state: State): ByteArray {
        val writer = FrameWriter().putBytes(u32ToBytes(state.records.size))
        for (invite in state.records.values) {
            writer.putBytes(invite.ridAsync)
                .putBytes(invite.secret)
                .putBytes(invite.inviteXWingPublicKey)
                .putBytes(invite.inviteXWingPrivateKey)
                .putBytes(invite.masterKey)
                .putBytes(u64ToBytes(invite.expiryEpochSeconds))
                .putBytes(invite.state.name.encodeToByteArray())
        }
        writer.putBytes(u32ToBytes(state.tombstones.size))
        for (tombstone in state.tombstones) writer.putBytes(tombstone.encodeToByteArray())
        return writer.toByteArray()
    }

}
