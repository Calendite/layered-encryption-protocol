package org.layeredencryption.membership

import org.layeredencryption.CryptoProvider
import org.layeredencryption.KeyPair
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.identity.DeviceIdentity
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
 * One entry in the append-only membership log (docs/Protocol.md §4.7):
 * `{ prev_hash, op, device_identity, wrapped_keys?, sig }`, every entry signed by a device that was
 * already a member. The subject is a full [DeviceIdentity] (Async_Invites_Spec.md §3), so its
 * Ed25519↔X25519 binding is verifiable from the log alone. [wrappedKeys] carries the calendar keys
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
    internal fun unsignedBytes(): ByteArray = FrameWriter()
        .putBytes(LABEL)
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
        private val LABEL = "calendite/v1/membership".encodeToByteArray()
        private val EMPTY = ByteArray(0)

        internal fun deserialise(reader: FrameReader): MembershipEntry {
            val previousHash = reader.readBytes()
            val op = MembershipOp.fromCode(reader.readByte())
            val deviceIdentity = DeviceIdentity.deserialise(reader.readBytes())
            val wrappedBytes = reader.readBytes()
            val hasWrapped = reader.readByte() == 1
            val signerPublicKey = reader.readBytes()
            val signature = reader.readBytes()
            return MembershipEntry(
                previousHash = previousHash,
                op = op,
                deviceIdentity = deviceIdentity,
                wrappedKeys = if (hasWrapped) wrappedBytes else null,
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
     * Verifies the full chain: each entry chains to the previous hash, its signature is valid, its
     * subject identity binding is valid, and its signer was an active member *before* the entry was
     * applied (genesis self-signs). Returns the resulting active-member set, or the first failure.
     */
    fun verify(provider: CryptoProvider): MembershipVerification {
        val members = mutableSetOf<String>()
        var expectedPrevious = MembershipEntry.GENESIS_PREVIOUS_HASH

        entries.forEachIndexed { index, entry ->
            if (!entry.previousHash.contentEquals(expectedPrevious)) {
                return MembershipVerification.Invalid("Broken hash chain", index)
            }
            if (!entry.deviceIdentity.verifyBinding(provider)) {
                return MembershipVerification.Invalid("Invalid device-identity binding", index)
            }
            if (!provider.ed25519Verify(entry.signerPublicKey, entry.unsignedBytes(), entry.signature)) {
                return MembershipVerification.Invalid("Invalid signature", index)
            }
            val authorisationFailure = checkAuthorisation(index, entry, members)
            if (authorisationFailure != null) return MembershipVerification.Invalid(authorisationFailure, index)

            applyOp(entry, members)
            expectedPrevious = entry.hash(provider)
        }
        return MembershipVerification.Valid(members.toSet())
    }

    /** Finds the entry that added the device with [ed25519PublicKey], if any (to read its wrapped keys). */
    fun addEntryFor(ed25519PublicKey: ByteArray): MembershipEntry? = entries.firstOrNull {
        it.op == MembershipOp.ADD && it.deviceIdentity.ed25519PublicKey.contentEquals(ed25519PublicKey)
    }

    fun serialise(): ByteArray {
        val writer = FrameWriter()
        for (entry in entries) writer.putBytes(entry.serialise())
        return writer.toByteArray()
    }

    private fun checkAuthorisation(index: Int, entry: MembershipEntry, members: Set<String>): String? {
        if (index == 0) {
            if (entry.op != MembershipOp.ADD) return "Genesis entry must be ADD"
            if (!entry.signerPublicKey.contentEquals(entry.deviceIdentity.ed25519PublicKey)) {
                return "Genesis entry must self-sign the founder"
            }
            return null
        }
        if (entry.signerPublicKey.toHexString() !in members) return "Signer is not an active member"
        if (entry.op == MembershipOp.REVOKE && entry.deviceIdentity.ed25519PublicKey.toHexString() !in members) {
            return "Revoking a non-member"
        }
        return null
    }

    private fun applyOp(entry: MembershipEntry, members: MutableSet<String>) {
        val deviceKey = entry.deviceIdentity.ed25519PublicKey.toHexString()
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

        fun deserialise(data: ByteArray): MembershipLog {
            val reader = FrameReader(data)
            val entries = mutableListOf<MembershipEntry>()
            while (reader.hasRemaining()) {
                entries.add(MembershipEntry.deserialise(FrameReader(reader.readBytes())))
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
                signature = provider.ed25519Sign(signer.privateKey, unsigned),
            )
        }
    }
}
