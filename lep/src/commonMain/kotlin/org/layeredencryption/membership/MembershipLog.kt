package org.layeredencryption.membership

import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.CryptoProvider
import org.layeredencryption.HybridSignature
import org.layeredencryption.KeyPair
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.toHexString

/** Membership operations (docs/Protocol.md §4.7). */
enum class MembershipOp(val code: Int) {
    ADD(1),
    REVOKE(2),
    ;

    companion object {
        fun fromCode(code: Int): MembershipOp =
            entries.firstOrNull { it.code == code } ?: throw IllegalArgumentException("Unknown membership op: $code")
    }
}

/**
 * What two versions of a log turned out to be, once compared.
 *
 * [Forked] is the interesting one, and deliberately does not resolve itself. It says which branch
 * to build on and where the two parted company, and leaves the caller to decide what to do about
 * the entries on the losing side, because the right answer differs by operation: a lost removal
 * must be re-asserted, a lost addition is better reported than silently re-applied.
 */
sealed interface Reconciliation {
    /** Not the same calendar: not one shared entry, not even genesis. Never adopt. */
    data object Unrelated : Reconciliation

    /** Byte-identical. */
    data object Same : Reconciliation

    /** Theirs is ours with more on the end; adopt it. */
    data object TheyExtendUs : Reconciliation

    /** Ours is theirs with more on the end; keep ours and offer it. */
    data object WeExtendThem : Reconciliation

    /** Both appended after [sharedPrefix]. [theirsWins] is the deterministic tie-break. */
    data class Forked(val sharedPrefix: Int, val theirsWins: Boolean) : Reconciliation
}

/**
 * One entry in the append-only membership log (docs/Protocol.md §4.7):
 * `{ prev_hash, op, device_identity, wrapped_keys?, sig }`, every entry signed by a device that was
 * already a member. The subject is a full [DeviceIdentity] (Async_Invites_Spec.md §3), so its
 * Ed25519↔X25519 binding is verifiable from the log alone. [wrappedKeys] carries the context keys
 * wrapped for a newly-added device.
 */
class MembershipEntry(
    val previousHash: ByteArray,
    val op: MembershipOp,
    val deviceIdentity: DeviceIdentity,
    val wrappedKeys: ByteArray?,
    val signerPublicKey: ByteArray,
    val signature: ByteArray,
) {
    /** The signed-over bytes (everything except the signature itself). */
    internal fun unsignedBytes(namespace: ProtocolNamespace = ProtocolNamespace.Default): ByteArray = FrameWriter()
        .putBytes(namespace.label(SUFFIX))
        .putBytes(previousHash)
        .putByte(op.code)
        .putBytes(deviceIdentity.serialise())
        .putBytes(wrappedKeys ?: EMPTY)
        .putBytes(signerPublicKey)
        .toByteArray()

    /** This entry's hash, which the next entry chains to via its `previousHash`. */
    internal fun hash(provider: CryptoProvider): ByteArray = provider.sha256(unsignedBytes() + signature)

    internal fun serialise(): ByteArray = FrameWriter()
        .putBytes(previousHash)
        .putByte(op.code)
        .putBytes(deviceIdentity.serialise())
        .putBytes(wrappedKeys ?: EMPTY)
        .putByte(if (wrappedKeys == null) 0 else 1)
        .putBytes(signerPublicKey)
        .putBytes(signature)
        .toByteArray()

    internal companion object {
        val GENESIS_PREVIOUS_HASH = ByteArray(32)
        private const val SUFFIX = ProtocolLabels.MEMBERSHIP
        private val EMPTY = ByteArray(0)

        internal fun deserialise(reader: FrameReader): MembershipEntry {
            val previousHash = reader.readBytes()
            require(previousHash.size == GENESIS_PREVIOUS_HASH.size) { "previousHash must be a SHA-256 hash" }
            val op = MembershipOp.fromCode(reader.readByte())
            val deviceIdentity = DeviceIdentity.deserialise(reader.readBytes())
            val wrappedBytes = reader.readBytes()
            val wrappedFlag = reader.readByte()
            // A canonical flag, strictly: any other byte, or absent-but-nonempty, would let two
            // different serialisations parse to the same logical entry and desynchronise the
            // byte-compared paths (prefix comparison, hashes).
            require(wrappedFlag == 0 || wrappedFlag == 1) { "wrappedKeys flag must be 0 or 1" }
            require(wrappedFlag == 1 || wrappedBytes.isEmpty()) { "Absent wrappedKeys must be empty" }
            val signerPublicKey = reader.readBytes()
            require(signerPublicKey.size == HybridSignature.PUBLIC_KEY_SIZE) { "Signer key has wrong size" }
            val signature = reader.readBytes()
            require(signature.size == HybridSignature.SIGNATURE_SIZE) { "Signature has wrong size" }
            return MembershipEntry(
                previousHash = previousHash,
                op = op,
                deviceIdentity = deviceIdentity,
                wrappedKeys = if (wrappedFlag == 1) wrappedBytes else null,
                signerPublicKey = signerPublicKey,
                signature = signature,
            )
        }
    }
}

/** The result of verifying a log: either the current active-member set, or a reason it is invalid. */
sealed interface MembershipVerification {
    /** [activeMembers] is the set of active devices' Ed25519 public keys (hex). */
    data class Valid(val activeMembers: Set<String>) : MembershipVerification
    data class Invalid(val reason: String, val entryIndex: Int) : MembershipVerification
}

/**
 * An append-only, hash-chained, Ed25519-signed device list (docs/Protocol.md §4.7).
 *
 * A compromised relay must not be able to inject "new device added": every entry chains to the hash
 * of the previous one and is signed by a device that was already an active member (the genesis entry
 * self-signs the founder). Each entry's subject [DeviceIdentity] binding is verified too, so a swapped
 * X25519 identity key is caught. Clients [verify] the whole chain before honouring any membership.
 * The log is immutable — mutating operations return a new [MembershipLog].
 */
class MembershipLog private constructor(val entries: List<MembershipEntry>) {

    /** The hash of the latest entry — what the next appended entry chains to. */
    fun head(provider: CryptoProvider): ByteArray = entries.last().hash(provider)

    /** Appends a signed [op] over [deviceIdentity], chained to the current head and signed by [signer]. */
    fun append(
        provider: CryptoProvider,
        op: MembershipOp,
        deviceIdentity: DeviceIdentity,
        wrappedKeys: ByteArray?,
        signer: KeyPair,
    ): MembershipLog = MembershipLog(
        entries + signEntry(provider, head(provider), op, deviceIdentity, wrappedKeys, signer),
    )

    /**
     * The identity of every currently active member, in the order they were added.
     *
     * Read from the entry that added each one, which is the only place a full identity appears. It
     * is needed by name rather than by key hex because rotating the context key means encapsulating
     * to each remaining member's KEM key, and a hex id is not something you can encrypt to.
     */
    fun activeIdentities(provider: CryptoProvider): List<DeviceIdentity> {
        val active = linkedMapOf<String, DeviceIdentity>()
        for (entry in entries) {
            val key = entry.deviceIdentity.signingPublicKey.toHexString()
            when (entry.op) {
                MembershipOp.ADD -> active[key] = entry.deviceIdentity
                MembershipOp.REVOKE -> active.remove(key)
            }
        }
        return active.values.toList()
    }

    /**
     * Removes [removed] and rotates the context key to [newMasterKey] in a single signed entry.
     *
     * Rotation is not a nicety. Without it a revoke is a gesture: the person walks away still
     * holding the key, and because the relay slot is derived from that key they can carry on
     * reading the mailbox for as long as they care to. Rotating is what turns "they stop seeing
     * your events" into a statement about cryptography.
     *
     * The new key is sealed once per remaining member, to their identity's KEM key, and the entry
     * carries all those copies. The removed device is simply not one of the recipients, so the
     * entry that ejects them is also the entry they cannot read.
     */
    fun revoke(
        provider: CryptoProvider,
        removed: DeviceIdentity,
        newMasterKey: ByteArray,
        signer: KeyPair,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): MembershipLog {
        val removedKey = removed.signingPublicKey.toHexString()
        val remaining = activeIdentities(provider).filterNot {
            it.signingPublicKey.toHexString() == removedKey
        }
        // Only degenerate if it empties the calendar, which means revoking yourself as the sole
        // member. Leaving yourself alone in it is allowed here: whether a one-member calendar
        // should instead be dissolved is a product question, not one the log should decide.
        require(remaining.isNotEmpty()) { "A revoke that empties the calendar is a dissolve" }
        return append(
            provider = provider,
            op = MembershipOp.REVOKE,
            deviceIdentity = removed,
            wrappedKeys = WrappedKeys.wrapFor(provider, remaining, newMasterKey, namespace),
            signer = signer,
        )
    }

    /**
     * Every rotated context key this log hands [device], oldest first.
     *
     * One per revoke entry addressed to them, so the result lines up with epochs 1, 2, 3 and so on;
     * epoch 0 came from pairing. A device that was not a recipient of some rotation contributes
     * nothing at that position, which is why the caller reconciles by count rather than assuming
     * the list is complete.
     */
    fun rotatedKeysFor(
        provider: CryptoProvider,
        device: DeviceKeys,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): List<ByteArray> = entries
        .filter { it.op == MembershipOp.REVOKE }
        .mapNotNull { entry ->
            entry.wrappedKeys?.let { WrappedKeys.unwrapFor(provider, it, device, namespace) }
        }

    /**
     * The founding entry's hash, or null for an empty log.
     *
     * The one value in a calendar that is fixed for its whole life: entries are only ever appended,
     * so entry zero and its hash never move. That makes it the right thing to name the calendar
     * after, unlike the master key, which has to change whenever somebody is removed.
     */
    fun genesisHash(provider: CryptoProvider): ByteArray? = entries.firstOrNull()?.hash(provider)

    /**
     * How this log relates to [other].
     *
     * Membership changes are rare and human-initiated, so two devices appending at once is unusual
     * but not impossible: two people removing somebody within a sync window of each other, or one
     * adding while another removes. Refusing to reconcile leaves them permanently disagreeing about
     * who is in the calendar, which is worse than any merge.
     */
    fun reconcile(other: MembershipLog): Reconciliation {
        val shared = commonPrefixLength(other)
        val oursAfter = entries.size - shared
        val theirsAfter = other.entries.size - shared
        return when {
            // Genesis is what names a calendar. Agreeing on nothing at all does not mean the two
            // diverged, it means they were never the same calendar, and treating that as a fork
            // would let a stranger's log replace this one wholesale.
            shared == 0 -> Reconciliation.Unrelated
            oursAfter == 0 && theirsAfter == 0 -> Reconciliation.Same
            oursAfter == 0 -> Reconciliation.TheyExtendUs
            theirsAfter == 0 -> Reconciliation.WeExtendThem
            else -> Reconciliation.Forked(
                sharedPrefix = shared,
                theirsWins = theirsWins(other, shared),
            )
        }
    }

    /** How many leading entries the two logs agree on, byte for byte. */
    fun commonPrefixLength(other: MembershipLog): Int {
        val limit = minOf(entries.size, other.entries.size)
        var shared = 0
        while (shared < limit &&
            entries[shared].serialise().contentEquals(other.entries[shared].serialise())
        ) {
            shared++
        }
        return shared
    }

    /**
     * Which side of a fork to build on: the longer branch, ties broken by the lower head hash.
     *
     * The rule only has to be deterministic and the same everywhere, so that two devices holding
     * the same pair of branches choose the same winner without exchanging a word about it. Longer
     * first because it preserves more of what people actually asked for.
     */
    private fun theirsWins(other: MembershipLog, shared: Int): Boolean {
        val ours = entries.size
        val theirs = other.entries.size
        if (theirs != ours) return theirs > ours
        val ourHead = entries.last().serialise().toHexString()
        val theirHead = other.entries.last().serialise().toHexString()
        return theirHead < ourHead
    }

    /** The entries this log has beyond the first [shared] of them. */
    fun entriesAfter(shared: Int): List<MembershipEntry> = entries.drop(shared)

    /**
     * Whether [other] is this log with more entries added to the end.
     *
     * Membership has to travel: if one device adds a third person, every other device must learn
     * about them or it will refuse their sync connection as a stranger. A hash-chained log makes
     * that decidable without a merge algorithm, because a longer chain sharing our entire prefix
     * can only have been built on top of what we already hold.
     *
     * Deliberately strict. A chain that is longer but *diverges* is a fork, which means two devices
     * appended concurrently, and picking a winner here would silently discard somebody's change.
     * That returns false and the caller keeps its own, so the disagreement stays visible instead of
     * being resolved by whoever synced last.
     */
    fun isExtendedBy(other: MembershipLog): Boolean {
        if (other.entries.size <= entries.size) return false
        return entries.indices.all { index ->
            entries[index].serialise().contentEquals(other.entries[index].serialise())
        }
    }

    /**
     * Verifies the full chain: each entry chains to the previous hash, its signature is valid, its
     * subject identity binding is valid, and its signer was an active member *before* the entry was
     * applied (genesis self-signs). Returns the resulting active-member set, or the first failure.
     */
    fun verify(provider: CryptoProvider): MembershipVerification {
        // An empty log has no genesis and therefore no founder; every other method here assumes
        // entry zero exists. Calling it valid-with-no-members would let a wiped log verify.
        if (entries.isEmpty()) return MembershipVerification.Invalid("Empty log has no genesis entry", 0)

        val members = mutableSetOf<String>()
        var expectedPrevious = MembershipEntry.GENESIS_PREVIOUS_HASH

        entries.forEachIndexed { index, entry ->
            if (!entry.previousHash.contentEquals(expectedPrevious)) {
                return MembershipVerification.Invalid("Broken hash chain", index)
            }
            if (!entry.deviceIdentity.verifyBinding(provider)) {
                return MembershipVerification.Invalid("Invalid device-identity binding", index)
            }
            if (!HybridSignature.verify(provider, entry.signerPublicKey, entry.unsignedBytes(), entry.signature)) {
                return MembershipVerification.Invalid("Invalid signature", index)
            }
            val authorisationFailure = checkAuthorisation(index, entry, members)
            if (authorisationFailure != null) return MembershipVerification.Invalid(authorisationFailure, index)

            applyOp(entry, members)
            expectedPrevious = entry.hash(provider)
        }
        return MembershipVerification.Valid(members.toSet())
    }

    /** Finds the entry that added the device with [signingPublicKey], if any (to read its wrapped keys). */
    fun addEntryFor(signingPublicKey: ByteArray): MembershipEntry? = entries.firstOrNull {
        it.op == MembershipOp.ADD && it.deviceIdentity.signingPublicKey.contentEquals(signingPublicKey)
    }

    fun serialise(): ByteArray {
        val writer = FrameWriter()
        for (entry in entries) writer.putBytes(entry.serialise())
        return writer.toByteArray()
    }

    private fun checkAuthorisation(index: Int, entry: MembershipEntry, members: Set<String>): String? {
        if (index == 0) {
            if (entry.op != MembershipOp.ADD) return "Genesis entry must be ADD"
            if (!entry.signerPublicKey.contentEquals(entry.deviceIdentity.signingPublicKey)) {
                return "Genesis entry must self-sign the founder"
            }
            return null
        }
        if (entry.signerPublicKey.toHexString() !in members) return "Signer is not an active member"
        if (entry.op == MembershipOp.REVOKE && entry.deviceIdentity.signingPublicKey.toHexString() !in members) {
            return "Revoking a non-member"
        }
        return null
    }

    private fun applyOp(entry: MembershipEntry, members: MutableSet<String>) {
        val deviceKey = entry.deviceIdentity.signingPublicKey.toHexString()
        when (entry.op) {
            MembershipOp.ADD -> members.add(deviceKey)
            MembershipOp.REVOKE -> members.remove(deviceKey)
        }
    }

    companion object {
        /** Founds a log: a single self-signed genesis ADD for the founding device. */
        fun found(
            provider: CryptoProvider,
            founder: DeviceIdentity,
            signer: KeyPair,
            wrappedKeys: ByteArray? = null,
        ): MembershipLog = MembershipLog(
            listOf(signEntry(provider, MembershipEntry.GENESIS_PREVIOUS_HASH, MembershipOp.ADD, founder, wrappedKeys, signer)),
        )

        /** Far beyond any real device list; the bound is what stops 16 MB of confetti becoming 16 MB of list. */
        private const val MAX_ENTRIES = 10_000

        fun deserialise(data: ByteArray): MembershipLog {
            val reader = FrameReader(data)
            val entries = mutableListOf<MembershipEntry>()
            while (reader.hasRemaining()) {
                require(entries.size < MAX_ENTRIES) { "Membership log exceeds $MAX_ENTRIES entries" }
                val entryReader = FrameReader(reader.readBytes())
                val entry = MembershipEntry.deserialise(entryReader)
                entryReader.expectEnd()
                entries.add(entry)
            }
            return MembershipLog(entries)
        }

        private fun signEntry(
            provider: CryptoProvider,
            previousHash: ByteArray,
            op: MembershipOp,
            deviceIdentity: DeviceIdentity,
            wrappedKeys: ByteArray?,
            signer: KeyPair,
        ): MembershipEntry {
            val unsigned = MembershipEntry(previousHash, op, deviceIdentity, wrappedKeys, signer.publicKey, ByteArray(0)).unsignedBytes()
            return MembershipEntry(
                previousHash = previousHash,
                op = op,
                deviceIdentity = deviceIdentity,
                wrappedKeys = wrappedKeys,
                signerPublicKey = signer.publicKey,
                signature = HybridSignature.sign(provider, signer.privateKey, unsigned),
            )
        }
    }
}
