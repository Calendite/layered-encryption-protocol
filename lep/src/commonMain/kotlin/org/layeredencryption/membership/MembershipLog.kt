package org.layeredencryption.membership

import dev.diagnostics.Diagnostics
import org.layeredencryption.LepTag
import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolLimits
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.CryptoProvider
import org.layeredencryption.HybridSignature
import org.layeredencryption.KeyPair
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.suite.ProtocolSuite
import org.layeredencryption.suite.Suite1
import org.layeredencryption.suite.SuiteId
import org.layeredencryption.suite.SuiteRegistry
import org.layeredencryption.suite.SuiteResolver
import org.layeredencryption.toHexString

/** Membership operations (docs/Protocol.md §4.7). */
enum class MembershipOp(val code: Int) {
    ADD(1),
    REVOKE(2),

    /**
     * A context-key rotation with no membership change: the entry's subject is the signer itself
     * and its wrapped keys carry a fresh context key sealed to every active member. Exists because
     * rotation otherwise only travels on [REVOKE], yet fork resolution can drop a key-holder with
     * nobody left to revoke — a member added on the losing branch received wrapped keys there but
     * was never a member of the winning branch. Also serves as a standalone rekey primitive.
     */
    ROTATE(3),

    /**
     * An atomic cryptographic-suite transition (the migration brief §5): the entry's subject is
     * the signer, and its payload ([SuiteUpgradePayload]) binds the old and new suite ids, the
     * exact transition epoch, and a fresh context key wrapped for every retained member under
     * the **new** suite — the suite change and the rotation are one signed entry, so no valid
     * log prefix can show one without the other. Entries after it verify under the new suite;
     * an application that does not know the new suite fails closed on the whole log (by design:
     * a device must update before its context upgrades). Transitions are monotonic in suite id.
     */
    SUITE_UPGRADE(4),
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

    /**
     * The other log fails verification — a broken chain, a bad signature, or an invalid
     * transition such as the re-ADD padding LEP-03 exploits. Distinct from [Unrelated] (a
     * stranger's valid calendar) so a consumer can tell forged/tampered history apart from an
     * honest mismatch. Never adopt.
     */
    data object InvalidBranch : Reconciliation

    /** Byte-identical. */
    data object Same : Reconciliation

    /** Theirs is ours with more on the end; adopt it. */
    data object TheyExtendUs : Reconciliation

    /** Ours is theirs with more on the end; keep ours and offer it. */
    data object WeExtendThem : Reconciliation

    /**
     * Both branches appended after [sharedPrefix]. [theirsWins] is the deterministic winner
     * (removal precedence, then length, then true entry hash — see [MembershipLog.reconcile]).
     *
     * **Do not adopt either branch from this outcome directly** — call
     * [MembershipLog.resolveFork], which enforces the security consequences and returns the log
     * actually safe to adopt. Adopting the raw winner leaves [revokedMembers] active when their
     * revocation was on the losing branch, keeps any additions a condemned member smuggled into
     * the winning tail, and rotates no keys. This outcome is classification, not resolution.
     *
     * [revokedMembers] is the union of members revoked in *either* divergent tail, by signing-key
     * hex: whichever branch wins, these devices are revoked and must stay revoked, so a removal
     * on the losing branch can never be silently dropped by adopting the winner.
     */
    data class Forked(
        val sharedPrefix: Int,
        val theirsWins: Boolean,
        val revokedMembers: Set<String>,
    ) : Reconciliation
}

/**
 * The outcome of [MembershipLog.resolveFork]: a fork turned into one log that is safe to adopt,
 * or a reason no resolution is possible for this caller.
 */
sealed interface ForkResolution {
    /**
     * The fork is resolved: adopt [log] and nothing else. If [newMasterKey] is non-null the
     * context key was rotated **exactly one epoch** — resolution's revocations carry no
     * rotations of their own, so `epochKeys.withNextEpoch(newMasterKey)` and adopting via
     * [MembershipLog.rotatedKeysFor] land every surviving device on the same epoch number,
     * whichever path it takes. Null means the fork changed nothing that key material depends
     * on (typically two devices' concurrent resolutions of the same fork converging) and the
     * winner was adopted as-is.
     *
     * [revoked] is everyone resolution itself revoked: union members still active on the winning
     * branch plus condemned-sponsor additions. [lostAdditions] is members added on the losing
     * branch whose addition did not survive — they were dropped, not revoked, and re-inviting
     * them is the application's (or a human's) call. Failing towards fewer members is the safe
     * direction.
     */
    class Resolved(
        val log: MembershipLog,
        val newMasterKey: ByteArray?,
        val revoked: Set<String>,
        val lostAdditions: Set<String>,
    ) : ForkResolution

    /** Not actually a fork: the plain [reconciliation] outcome for the caller to handle normally. */
    class NotForked(val reconciliation: Reconciliation) : ForkResolution

    /**
     * The resolver has no authority to resolve: it is itself revoked in the fork union, condemned
     * as a tainted addition, or absent from the winning branch (added only on the losing side).
     * Removal precedence is honoured even when the revocation was spurious — a device in this
     * position does not resolve forks, it gets re-invited.
     */
    data object ResolverExcluded : ForkResolution
}

/**
 * One entry in the append-only membership log (docs/Protocol.md §4.7):
 * `{ prev_hash, op, device_identity, wrapped_keys?, sig }`, every entry signed by a device that was
 * already a member. The subject is a full [DeviceIdentity] (Async_Invites_Spec.md §3), so its
 * Ed25519↔X25519 binding is verifiable from the log alone. [wrappedKeys] carries the context keys
 * wrapped for a newly-added device.
 */
class MembershipEntry(
    previousHash: ByteArray,
    val op: MembershipOp,
    val deviceIdentity: DeviceIdentity,
    wrappedKeys: ByteArray?,
    signerPublicKey: ByteArray,
    signature: ByteArray,
) {
    // Copied both ways: a verified entry cannot be mutated by whoever built or read it.
    private val _previousHash = previousHash.copyOf()
    private val _wrappedKeys = wrappedKeys?.copyOf()
    private val _signerPublicKey = signerPublicKey.copyOf()
    private val _signature = signature.copyOf()

    val previousHash: ByteArray get() = _previousHash.copyOf()
    val wrappedKeys: ByteArray? get() = _wrappedKeys?.copyOf()
    val signerPublicKey: ByteArray get() = _signerPublicKey.copyOf()
    val signature: ByteArray get() = _signature.copyOf()

    internal val hasWrappedKeys: Boolean get() = _wrappedKeys != null

    /** The signed-over bytes (everything except the signature itself). */
    internal fun unsignedBytes(namespace: ProtocolNamespace = ProtocolNamespace.Default): ByteArray = FrameWriter()
        .putBytes(namespace.label(SUFFIX))
        .putBytes(_previousHash)
        .putByte(op.code)
        .putBytes(deviceIdentity.serialise())
        .putBytes(_wrappedKeys ?: EMPTY)
        .putBytes(_signerPublicKey)
        .toByteArray()

    /** This entry's hash, which the next entry chains to via its `previousHash`. */
    internal fun hash(provider: CryptoProvider, namespace: ProtocolNamespace = ProtocolNamespace.Default): ByteArray =
        provider.sha256(unsignedBytes(namespace) + _signature)

    internal fun serialise(): ByteArray = FrameWriter()
        .putBytes(_previousHash)
        .putByte(op.code)
        .putBytes(deviceIdentity.serialise())
        .putBytes(_wrappedKeys ?: EMPTY)
        .putByte(if (_wrappedKeys == null) 0 else 1)
        .putBytes(_signerPublicKey)
        .putBytes(_signature)
        .toByteArray()

    internal companion object {
        val GENESIS_PREVIOUS_HASH = ByteArray(32)
        private const val SUFFIX = ProtocolLabels.MEMBERSHIP
        private val EMPTY = ByteArray(0)

        /**
         * Parses one entry. The identity field is self-describing (its own version, suite, and
         * sizes); the signer key and signature are sized by [era] — the suite of the era the
         * entry sits in, tracked by the log-level walk, because entries are signed under the
         * era's suite, not the subject identity's. A null [era] is the genesis entry, whose
         * own identity *defines* the founding era (the genesis self-signs the founder, so its
         * signer suite is its identity's).
         */
        internal fun deserialise(reader: FrameReader, resolver: SuiteResolver, era: ProtocolSuite?): MembershipEntry {
            val previousHash = reader.readBytes(GENESIS_PREVIOUS_HASH.size)
            require(previousHash.size == GENESIS_PREVIOUS_HASH.size) { "previousHash must be a SHA-256 hash" }
            val op = MembershipOp.fromCode(reader.readByte())
            val deviceIdentity = DeviceIdentity.deserialise(reader.readBytes(DeviceIdentity.MAX_SERIALISED_BYTES), resolver)
            val signerSuite = era ?: resolver.require(deviceIdentity.suiteId)
            val wrappedBytes = reader.readBytes(ProtocolLimits.MAX_WRAPPED_KEYS_BYTES)
            val wrappedFlag = reader.readByte()
            // A canonical flag, strictly: any other byte, or absent-but-nonempty, would let two
            // different serialisations parse to the same logical entry and desynchronise the
            // byte-compared paths (prefix comparison, hashes).
            require(wrappedFlag == 0 || wrappedFlag == 1) { "wrappedKeys flag must be 0 or 1" }
            require(wrappedFlag == 1 || wrappedBytes.isEmpty()) { "Absent wrappedKeys must be empty" }
            val signerPublicKey = reader.readBytes(signerSuite.signature.publicKeySize)
            require(signerPublicKey.size == signerSuite.signature.publicKeySize) { "Signer key has wrong size" }
            val signature = reader.readBytes(signerSuite.signature.signatureSize)
            require(signature.size == signerSuite.signature.signatureSize) { "Signature has wrong size" }
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
class MembershipLog private constructor(entries: List<MembershipEntry>) {

    // A structural snapshot: Kotlin's read-only List is an interface, not a guarantee, so the
    // supplied backing collection is copied on construction and never handed back out — a caller
    // down-casting [entries] to MutableList mutates its own copy, not a verified log.
    private val entriesSnapshot: List<MembershipEntry> = entries.toList()

    val entries: List<MembershipEntry> get() = entriesSnapshot.toList()

    /** The hash of the latest entry — what the next appended entry chains to. */
    fun head(provider: CryptoProvider, namespace: ProtocolNamespace = ProtocolNamespace.Default): ByteArray =
        entriesSnapshot.last().hash(provider, namespace)

    /**
     * Appends a signed [op] over [deviceIdentity], chained to the current head and signed by
     * [signer] — under the suite of the log's current era: entries after a [MembershipOp.SUITE_UPGRADE]
     * are signed (and verified) under the upgraded suite. For a Suite-1-only log this is the
     * frozen legacy path, byte for byte.
     */
    fun append(
        provider: CryptoProvider,
        op: MembershipOp,
        deviceIdentity: DeviceIdentity,
        wrappedKeys: ByteArray?,
        signer: KeyPair,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): MembershipLog = MembershipLog(
        entriesSnapshot + signEntry(
            provider, head(provider, namespace), op, deviceIdentity, wrappedKeys, signer, namespace,
            suite = currentEraSuite(resolver),
        ),
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
                MembershipOp.ROTATE, MembershipOp.SUITE_UPGRADE -> Unit
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
        resolver: SuiteResolver = SuiteRegistry,
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
            wrappedKeys = WrappedKeys.wrapForEra(provider, currentEraSuite(resolver), remaining, newMasterKey, namespace),
            signer = signer,
            namespace = namespace,
            resolver = resolver,
        )
    }

    /**
     * Rotates the context key to [newMasterKey] with no membership change: a self-signed [MembershipOp.ROTATE]
     * entry carrying the new key sealed to every active member, the signer included.
     *
     * This is what fork resolution ends with — a rotation that excludes people who were never
     * members of this branch but hold key material anyway (an addition on a losing branch) has
     * nobody to [revoke]. It is also the standalone rekey: periodic rotation or post-compromise
     * recovery without inventing a revocation to carry it.
     */
    fun rotate(
        provider: CryptoProvider,
        newMasterKey: ByteArray,
        signer: DeviceKeys,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): MembershipLog = append(
        provider = provider,
        op = MembershipOp.ROTATE,
        deviceIdentity = signer.identity,
        wrappedKeys = WrappedKeys.wrapForEra(provider, currentEraSuite(resolver), activeIdentities(provider), newMasterKey, namespace),
        signer = signer.signingKeyPair,
        namespace = namespace,
        resolver = resolver,
    )

    /**
     * Appends the atomic suite transition (the migration brief §5): one [MembershipOp.SUITE_UPGRADE]
     * entry that rotates the context key to [newMasterKey] — wrapped for every active member
     * under [newSuite] — and moves the log's era forward. The entry itself is signed under the
     * *old* suite: the upgrade is authorised by the regime being left; everything after it is
     * signed and verified under [newSuite].
     *
     * Policy note (deliberately not enforceable here): every device that will remain active
     * should already run software that knows [newSuite], because a device that does not fails
     * closed on the whole log afterwards. Revoke the stragglers first — a keyless revocation
     * batch may terminate in this entry, making "remove the non-upgraded, then upgrade" one
     * atomic epoch.
     */
    fun upgradeSuite(
        provider: CryptoProvider,
        newSuite: ProtocolSuite,
        newMasterKey: ByteArray,
        signer: DeviceKeys,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): MembershipLog {
        val current = currentEraSuite(resolver)
        require(resolver.contains(newSuite.id)) { "The target suite ${newSuite.id} is not registered" }
        require(newSuite.id.value > current.id.value) {
            "Suite transitions are monotonic: ${newSuite.id} does not follow ${current.id}"
        }
        require(newMasterKey.size == WrappedKeys.CONTEXT_KEY_BYTES) {
            "The context key is ${WrappedKeys.CONTEXT_KEY_BYTES} bytes"
        }
        val payload = SuiteUpgradePayload(
            oldSuite = current.id,
            newSuite = newSuite.id,
            transitionEpoch = epochCount() + 1,
            wrappedKeys = WrappedKeys.wrapForEra(provider, newSuite, activeIdentities(provider), newMasterKey, namespace),
        )
        return append(
            provider = provider,
            op = MembershipOp.SUITE_UPGRADE,
            deviceIdentity = signer.identity,
            wrappedKeys = payload.serialise(),
            signer = signer.signingKeyPair,
            namespace = namespace,
            resolver = resolver,
        )
    }

    /**
     * Every rotated context key this log hands [device], oldest first.
     *
     * One per rotation-carrying entry ([MembershipOp.REVOKE] or [MembershipOp.ROTATE]) addressed
     * to them, so the result lines up with epochs 1, 2, 3 and so on; epoch 0 came from pairing. A
     * device that was not a recipient of some rotation contributes nothing at that position, which
     * is why the caller reconciles by count rather than assuming the list is complete.
     */
    fun rotatedKeysFor(
        provider: CryptoProvider,
        device: DeviceKeys,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): List<ByteArray> {
        val keys = mutableListOf<ByteArray>()
        var era = resolver.require(entriesSnapshot.first().deviceIdentity.suiteId)
        for (entry in entriesSnapshot) {
            when (entry.op) {
                MembershipOp.REVOKE, MembershipOp.ROTATE ->
                    entry.wrappedKeys
                        ?.let { WrappedKeys.unwrapForEra(provider, era, it, device, namespace) }
                        ?.let { keys += it }
                MembershipOp.SUITE_UPGRADE -> {
                    // On a verified log this always parses and resolves; anything else
                    // contributes nothing, consistent with reconciling by count.
                    val payload = entry.wrappedKeys?.let { SuiteUpgradePayload.parse(it) } ?: continue
                    if (!resolver.contains(payload.newSuite)) continue
                    val newEra = resolver.require(payload.newSuite)
                    WrappedKeys.unwrapForEra(provider, newEra, payload.wrappedKeys, device, namespace)
                        ?.let { keys += it }
                    era = newEra
                }
                MembershipOp.ADD -> Unit
            }
        }
        return keys
    }

    /**
     * The founding entry's hash, or null for an empty log.
     *
     * The one value in a calendar that is fixed for its whole life: entries are only ever appended,
     * so entry zero and its hash never move. That makes it the right thing to name the calendar
     * after, unlike the master key, which has to change whenever somebody is removed.
     */
    fun genesisHash(provider: CryptoProvider, namespace: ProtocolNamespace = ProtocolNamespace.Default): ByteArray? =
        entriesSnapshot.firstOrNull()?.hash(provider, namespace)

    /**
     * How this log relates to [other].
     *
     * Membership changes are rare and human-initiated, so two devices appending at once is unusual
     * but not impossible: two people removing somebody within a sync window of each other, or one
     * adding while another removes. Refusing to reconcile leaves them permanently disagreeing about
     * who is in the calendar, which is worse than any merge.
     *
     * Both logs are **verified first** (LEP-03): reconciling against unverified history is what
     * let a forged/padded branch influence the outcome, so an invalid [other] returns
     * [Reconciliation.InvalidBranch] and is never adopted. This log is assumed already verified by
     * its holder; it is re-verified here so the API cannot be misused with an unchecked receiver.
     */
    fun reconcile(
        provider: CryptoProvider,
        other: MembershipLog,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): Reconciliation {
        if (verify(provider, namespace, resolver) !is MembershipVerification.Valid) return Reconciliation.InvalidBranch
        if (other.verify(provider, namespace, resolver) !is MembershipVerification.Valid) return Reconciliation.InvalidBranch

        val shared = commonPrefixLength(other)
        val oursAfter = entriesSnapshot.size - shared
        val theirsAfter = other.entriesSnapshot.size - shared
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
                theirsWins = theirsWins(provider, other, shared, namespace),
                revokedMembers = revokedInTail(shared) + other.revokedInTail(shared),
            )
        }
    }

    /**
     * Resolves a fork with [other] into one log that is safe to adopt (RT-01).
     *
     * [reconcile] classifies; this enforces. The winning branch is chosen by the usual
     * deterministic rule, then every security consequence the classification only *reported* is
     * appended as real, signed entries by [resolver]:
     *
     * 1. **The revocation union is enforced.** Every member revoked in either divergent tail who
     *    is still active on the winning branch is revoked, in sorted-key order so concurrent
     *    resolvers produce the same operations.
     * 2. **Condemned sponsors lose their additions.** A winning-tail `ADD` whose signer is being
     *    revoked by the fork — directly or transitively, a puppet sponsoring a puppet — is
     *    revoked too. This is what stops a padded branch's sock-puppet members outliving the
     *    attacker who added them. Additions sponsored by surviving members are kept.
     * 3. **Key material rotates exactly once.** If resolution revoked anyone, or a losing-tail
     *    addition held wrapped keys and did not survive, the log ends with a single [rotate]
     *    whose fresh key is sealed only to post-resolution members — the resolution `REVOKE`s
     *    themselves carry no keys, so one fork costs one epoch however many members it removes.
     *    A fork that changed nothing adopts the winner with no rotation, which is what lets two
     *    devices' concurrent resolutions converge instead of rotating forever.
     *
     * Returns [ForkResolution.ResolverExcluded] when [resolver] is condemned by the fork or absent
     * from the winning branch: a device with no post-resolution membership has no authority, it
     * gets re-invited. Anything [reconcile] classifies as not-a-fork comes back as
     * [ForkResolution.NotForked] with the classification to handle normally — [Reconciliation.InvalidBranch]
     * and [Reconciliation.Unrelated] keep their never-adopt meaning.
     */
    fun resolveFork(
        provider: CryptoProvider,
        other: MembershipLog,
        resolver: DeviceKeys,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        suites: SuiteResolver = SuiteRegistry,
    ): ForkResolution {
        val outcome = reconcile(provider, other, namespace, suites)
        if (outcome !is Reconciliation.Forked) return ForkResolution.NotForked(outcome)

        Diagnostics.debug(LepTag.MEMBERSHIP) {
            "fork: shared prefix ${outcome.sharedPrefix}, ${entriesSnapshot.size - outcome.sharedPrefix} ours vs " +
                "${other.entriesSnapshot.size - outcome.sharedPrefix} theirs, union of ${outcome.revokedMembers.size} revocation(s)"
        }
        val winner = if (outcome.theirsWins) other else this
        val loser = if (outcome.theirsWins) this else other

        // The union, closed over sponsorship: a winning-tail ADD signed by anyone already
        // condemned condemns its subject. One chronological pass is transitive closure, because a
        // puppet can only sponsor after the entry that added it.
        val condemned = outcome.revokedMembers.toMutableSet()
        for (entry in winner.entriesAfter(outcome.sharedPrefix)) {
            if (entry.op == MembershipOp.ADD && entry.signerPublicKey.toHexString() in condemned) {
                condemned += entry.deviceIdentity.signingPublicKey.toHexString()
            }
        }

        val winnerActive = (winner.verify(provider, namespace, suites) as MembershipVerification.Valid).activeMembers
        val resolverHex = resolver.identity.signingPublicKey.toHexString()
        if (resolverHex in condemned || resolverHex !in winnerActive) {
            Diagnostics.warning(LepTag.MEMBERSHIP) { "fork resolution: this device is condemned or absent from the winner — no authority, re-pairing required" }
            return ForkResolution.ResolverExcluded
        }

        // The resolver survives every step below (it is not condemned), so no revocation can
        // empty the calendar. Sorted order keeps concurrent resolvers byte-comparable in intent.
        //
        // Resolution revocations deliberately carry no rotation of their own: the single ROTATE
        // below does all the key work, so resolving a fork advances **exactly one epoch** however
        // many members it removes. Per-revocation rotations here would advance the log by more
        // epochs than [ForkResolution.Resolved.newMasterKey] accounts for, and honest devices
        // updating by different means would disagree on epoch numbering. No envelope is ever
        // sealed between these entries — the resolved log is constructed and adopted atomically —
        // so no interim epoch is ever missed.
        val identityByHex = winner.activeIdentities(provider).associateBy { it.signingPublicKey.toHexString() }
        val toRevoke = condemned.filter { it in winnerActive }.sorted()
        var resolved = winner
        for (hex in toRevoke) {
            resolved = resolved.append(
                provider = provider,
                op = MembershipOp.REVOKE,
                deviceIdentity = identityByHex.getValue(hex),
                wrappedKeys = null,
                signer = resolver.signingKeyPair,
                namespace = namespace,
                resolver = suites,
            )
        }

        // Computed arithmetically, not by re-verifying: mid-construction the log deliberately
        // fails verification — a keyless batch is only valid once its rotation lands.
        val resolvedActive = winnerActive - toRevoke.toSet()
        val loserTailAdds = loser.entriesAfter(outcome.sharedPrefix)
            .filter { it.op == MembershipOp.ADD }
            .map { it.deviceIdentity.signingPublicKey.toHexString() }
        // Dropped losing-tail additions received wrapped keys when they were added, so they force
        // a rotation even when there was nobody to revoke. The reported set excludes members the
        // fork itself revoked: their removal was asked for, not lost.
        val droppedKeyHolders = loserTailAdds.any { it !in resolvedActive }
        val lostAdditions = loserTailAdds
            .filter { it !in resolvedActive && it !in outcome.revokedMembers }
            .toSet()

        var newMasterKey: ByteArray? = null
        if (toRevoke.isNotEmpty() || droppedKeyHolders) {
            newMasterKey = provider.randomBytes(WrappedKeys.CONTEXT_KEY_BYTES)
            resolved = resolved.rotate(provider, newMasterKey, resolver, namespace, suites)
        }
        Diagnostics.debug(LepTag.MEMBERSHIP) {
            "fork resolved: ${toRevoke.size} revoked, ${lostAdditions.size} addition(s) lost, " +
                if (newMasterKey != null) "rotated one epoch" else "no rotation needed"
        }
        return ForkResolution.Resolved(
            log = resolved,
            newMasterKey = newMasterKey,
            revoked = toRevoke.toSet(),
            lostAdditions = lostAdditions,
        )
    }

    /** Members revoked in this log's divergent tail (after the first [shared] entries), by key hex. */
    private fun revokedInTail(shared: Int): Set<String> =
        entriesSnapshot.drop(shared)
            .filter { it.op == MembershipOp.REVOKE }
            .map { it.deviceIdentity.signingPublicKey.toHexString() }
            .toSet()

    /** How many leading entries the two logs agree on, byte for byte. */
    fun commonPrefixLength(other: MembershipLog): Int {
        val limit = minOf(entriesSnapshot.size, other.entriesSnapshot.size)
        var shared = 0
        while (shared < limit &&
            entriesSnapshot[shared].serialise().contentEquals(other.entriesSnapshot[shared].serialise())
        ) {
            shared++
        }
        return shared
    }

    /**
     * Which side of a fork to build on. **Removals win** (LEP-03), then length, then a true
     * entry hash:
     *
     * 1. **More revocations first.** The branch whose tail revokes more members wins outright.
     *    This is what defeats padding: a device forking to escape its own revocation appends
     *    `ADD`s (which revoke nobody), so its branch scores zero removals and loses to the shorter
     *    branch carrying the `REVOKE`, however long the padding. "Most entries wins" is
     *    deliberately *not* the primary key — that was the defect.
     * 2. **Then length**, when both tails revoke equally — it preserves more of what people asked
     *    for, and can no longer be used to bury a revocation.
     * 3. **Then the lower head hash**, an actual `SHA-256` of the final entry (the previous code
     *    compared serialised entry *bytes* while claiming to compare hashes; now it matches).
     *
     * The rule only has to be deterministic and identical everywhere: two devices holding the same
     * pair of branches choose the same winner without exchanging a word. Every comparison is a
     * total order over symmetric quantities, so exactly one side sees "theirs wins".
     */
    private fun theirsWins(provider: CryptoProvider, other: MembershipLog, shared: Int, namespace: ProtocolNamespace): Boolean {
        val ourRevokes = revokedInTail(shared).size
        val theirRevokes = other.revokedInTail(shared).size
        if (theirRevokes != ourRevokes) return theirRevokes > ourRevokes

        val ours = entriesSnapshot.size
        val theirs = other.entriesSnapshot.size
        if (theirs != ours) return theirs > ours

        val ourHead = entriesSnapshot.last().hash(provider, namespace).toHexString()
        val theirHead = other.entriesSnapshot.last().hash(provider, namespace).toHexString()
        return theirHead < ourHead
    }

    /** The entries this log has beyond the first [shared] of them. */
    fun entriesAfter(shared: Int): List<MembershipEntry> = entriesSnapshot.drop(shared)

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
        if (other.entriesSnapshot.size <= entriesSnapshot.size) return false
        return entriesSnapshot.indices.all { index ->
            entriesSnapshot[index].serialise().contentEquals(other.entriesSnapshot[index].serialise())
        }
    }

    /**
     * Verifies the full chain: each entry chains to the previous hash, its signature is valid, its
     * subject identity binding is valid, and its signer was an active member *before* the entry was
     * applied (genesis self-signs). Returns the resulting active-member set, or the first failure.
     *
     * **Keyless revocations are only valid inside a terminated batch** (the `6ddd7e4` retest,
     * finding 1): a keyless `REVOKE` may be followed only by another keyless `REVOKE` or by the
     * `ROTATE` that excludes everyone the batch removed, and a log may not end mid-batch. An
     * append-only log's weakness is that a *prefix* of it is also a correctly signed log — so an
     * untrusted relay could otherwise truncate a resolved fork just before its rotation and
     * deliver a state where a member reads as revoked while everyone keeps sealing under the key
     * that member still holds. Making the truncated prefix unverifiable makes suppression an
     * availability problem again instead of a confidentiality one, and it makes a standalone
     * keyless revocation — ejection with no cryptographic exclusion — impossible to present as a
     * valid state at all.
     */
    fun verify(
        provider: CryptoProvider,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): MembershipVerification {
        // An empty log has no genesis and therefore no founder; every other method here assumes
        // entry zero exists. Calling it valid-with-no-members would let a wiped log verify.
        if (entriesSnapshot.isEmpty()) return MembershipVerification.Invalid("Empty log has no genesis entry", 0)

        val members = mutableSetOf<String>()
        var expectedPrevious = MembershipEntry.GENESIS_PREVIOUS_HASH
        var inKeylessBatch = false
        // The genesis identity defines the founding suite — a context can be founded under any
        // registered suite. SUITE_UPGRADE entries move the era forward, and each historical
        // entry verifies under the suite that was active when it was made.
        val foundingSuiteId = entriesSnapshot.first().deviceIdentity.suiteId
        if (!resolver.contains(foundingSuiteId)) {
            return MembershipVerification.Invalid("Unknown founding suite ${foundingSuiteId.value}", 0)
        }
        var activeSuite = resolver.require(foundingSuiteId)
        var epoch = 0

        entriesSnapshot.forEachIndexed { index, entry ->
            if (!entry.previousHash.contentEquals(expectedPrevious)) {
                return MembershipVerification.Invalid("Broken hash chain", index)
            }
            // Identity bindings are artifacts of identity *creation* and verify under the
            // identity's own (self-described) suite; entry signatures are live per-era
            // operations and route through the active suite.
            if (!resolver.contains(entry.deviceIdentity.suiteId)) {
                return MembershipVerification.Invalid("Unknown identity suite ${entry.deviceIdentity.suiteId.value}", index)
            }
            if (!entry.deviceIdentity.verifyBinding(provider, namespace, resolver)) {
                return MembershipVerification.Invalid("Invalid device-identity binding", index)
            }
            if (!activeSuite.signature.verify(provider, entry.signerPublicKey, entry.unsignedBytes(namespace), entry.signature)) {
                return MembershipVerification.Invalid("Invalid signature", index)
            }
            if (inKeylessBatch &&
                !(entry.op == MembershipOp.REVOKE && !entry.hasWrappedKeys) &&
                entry.op != MembershipOp.ROTATE &&
                entry.op != MembershipOp.SUITE_UPGRADE
            ) {
                return MembershipVerification.Invalid("A keyless revocation batch must terminate in its rotation", index)
            }
            val authorisationFailure = checkAuthorisation(index, entry, members, activeSuite)
            if (authorisationFailure != null) {
                Diagnostics.debug(LepTag.MEMBERSHIP) { "log invalid at entry $index: $authorisationFailure" }
                return MembershipVerification.Invalid(authorisationFailure, index)
            }
            var nextSuite: ProtocolSuite? = null
            if (entry.op == MembershipOp.SUITE_UPGRADE) {
                val upgrade = checkSuiteUpgrade(entry, members, activeSuite, epoch, resolver)
                val failure = upgrade.failure
                if (failure != null) {
                    Diagnostics.debug(LepTag.MEMBERSHIP) { "log invalid at entry $index: $failure" }
                    return MembershipVerification.Invalid(failure, index)
                }
                nextSuite = upgrade.newSuite
            }

            applyOp(entry, members)
            if (advancesEpoch(entry)) epoch += 1
            nextSuite?.let { activeSuite = it }
            inKeylessBatch = entry.op == MembershipOp.REVOKE && !entry.hasWrappedKeys
            expectedPrevious = entry.hash(provider, namespace)
        }
        if (inKeylessBatch) {
            return MembershipVerification.Invalid(
                "Log ends in an unterminated keyless revocation — truncated before its rotation",
                entriesSnapshot.lastIndex,
            )
        }
        return MembershipVerification.Valid(members.toSet())
    }

    /** Finds the entry that added the device with [signingPublicKey], if any (to read its wrapped keys). */
    fun addEntryFor(signingPublicKey: ByteArray): MembershipEntry? = entriesSnapshot.firstOrNull {
        it.op == MembershipOp.ADD && it.deviceIdentity.signingPublicKey.contentEquals(signingPublicKey)
    }

    fun serialise(): ByteArray {
        val writer = FrameWriter()
        for (entry in entries) writer.putBytes(entry.serialise())
        return writer.toByteArray()
    }

    private fun checkAuthorisation(index: Int, entry: MembershipEntry, members: Set<String>, activeSuite: ProtocolSuite): String? {
        if (index == 0) {
            if (entry.op != MembershipOp.ADD) return "Genesis entry must be ADD"
            if (!entry.signerPublicKey.contentEquals(entry.deviceIdentity.signingPublicKey)) {
                return "Genesis entry must self-sign the founder"
            }
            return null
        }
        if (entry.signerPublicKey.toHexString() !in members) return "Signer is not an active member"
        val subject = entry.deviceIdentity.signingPublicKey.toHexString()
        when (entry.op) {
            // No-op transitions are rejected, not silently absorbed into the member set. A
            // re-ADD of an active member is the padding primitive LEP-03 exploits: a device
            // about to be revoked forks and appends signed ADD(self) entries to out-grow the
            // branch carrying its revocation. Making the transition itself invalid means such a
            // branch never verifies, so it can never reach reconciliation.
            MembershipOp.ADD -> if (subject in members) return "Re-adding an active member"
            // A keyed revocation must rotate to exactly the survivors: omitting an active member
            // would leave them a member the log vouches for who can never read another epoch — a
            // silent membership/key partition — and including the revoked subject (or a stranger)
            // would hand the new key to precisely who the entry exists to exclude. Keyless
            // revocations stay legal: fork resolution batches its removals under one rotation.
            MembershipOp.REVOKE -> {
                if (subject !in members) return "Revoking a non-member"
                if (entry.hasWrappedKeys) {
                    checkRecipients(entry, members - subject, "Revocation", activeSuite)?.let { return it }
                }
            }
            // A rotation names its own signer as subject — there is no third party to speak
            // about — and one that carries no keys rotates to nobody, which would let an entry
            // masquerade as a rekey while quietly orphaning every member.
            MembershipOp.ROTATE -> {
                if (subject != entry.signerPublicKey.toHexString()) return "Rotation subject must be its signer"
                if (!entry.hasWrappedKeys) return "Rotation must carry wrapped keys"
                checkRecipients(entry, members, "Rotation", activeSuite)?.let { return it }
            }
            // Like ROTATE, an upgrade speaks only for its signer; the payload rules — old/new
            // suite, transition epoch, fresh keys for exactly the retained members — live in
            // [checkSuiteUpgrade], which needs the walk's suite and epoch state.
            MembershipOp.SUITE_UPGRADE -> {
                if (subject != entry.signerPublicKey.toHexString()) return "Suite upgrade subject must be its signer"
            }
        }
        return null
    }

    private class UpgradeCheck(val newSuite: ProtocolSuite?, val failure: String?)

    /**
     * The complete [MembershipOp.SUITE_UPGRADE] payload rule set (the migration brief §5): the
     * payload parses under its version gate; it names the era it is leaving; the target suite is
     * known here (a verifier that does not know it fails the whole log — update before the
     * context upgrades); transitions are strictly monotonic in id — a downgrade is never an
     * ordinary operation; the claimed transition epoch matches the chain walk; and the fresh
     * key is wrapped, under the new suite, for exactly the members retained at this point — so
     * no valid prefix can show the suite changed while omitting anyone's key.
     */
    private fun checkSuiteUpgrade(
        entry: MembershipEntry,
        members: Set<String>,
        activeSuite: ProtocolSuite,
        epochsSoFar: Int,
        resolver: SuiteResolver,
    ): UpgradeCheck {
        fun fail(reason: String) = UpgradeCheck(null, reason)
        val wrapped = entry.wrappedKeys ?: return fail("Suite upgrade is missing its payload")
        val payload = SuiteUpgradePayload.parse(wrapped) ?: return fail("Suite upgrade carries a malformed payload")
        if (payload.oldSuite != activeSuite.id) return fail("Suite upgrade names the wrong current suite")
        if (!resolver.contains(payload.newSuite)) return fail("Suite upgrade targets an unknown suite")
        if (payload.newSuite.value <= payload.oldSuite.value) {
            return fail("Suite transitions are monotonic — downgrade or same-suite upgrade rejected")
        }
        if (payload.transitionEpoch != epochsSoFar + 1) return fail("Suite upgrade transition epoch does not match the chain")
        val newSuite = resolver.require(payload.newSuite)
        val recipients = WrappedKeys.recipientsOrNullForEra(newSuite, payload.wrappedKeys)
            ?: return fail("Suite upgrade carries malformed wrapped keys")
        if (recipients.size != recipients.toSet().size) return fail("Suite upgrade wraps a duplicate recipient")
        if (recipients.toSet() != members) {
            return fail("Suite upgrade must wrap the key for exactly the active members")
        }
        return UpgradeCheck(newSuite, null)
    }

    /**
     * The wrapped-key recipient rule for rotation-carrying entries: exactly the [expected] member
     * set, no omissions, no extras, no duplicates, and the blob must parse — with the era's
     * suite sizes. `ADD` entries are deliberately outside this rule — their payload is a Cascade
     * blob for the added device (the async approval path), not a [WrappedKeys] bundle.
     */
    private fun checkRecipients(entry: MembershipEntry, expected: Set<String>, what: String, suite: ProtocolSuite): String? {
        val wrapped = entry.wrappedKeys ?: return "$what is missing its wrapped keys"
        val recipients = WrappedKeys.recipientsOrNullForEra(suite, wrapped) ?: return "$what carries malformed wrapped keys"
        if (recipients.size != recipients.toSet().size) return "$what wraps a duplicate recipient"
        if (recipients.toSet() != expected) {
            return "$what must wrap the key for exactly the active members it leaves behind"
        }
        return null
    }

    private fun applyOp(entry: MembershipEntry, members: MutableSet<String>) {
        val deviceKey = entry.deviceIdentity.signingPublicKey.toHexString()
        when (entry.op) {
            MembershipOp.ADD -> members.add(deviceKey)
            MembershipOp.REVOKE -> members.remove(deviceKey)
            MembershipOp.ROTATE, MembershipOp.SUITE_UPGRADE -> Unit
        }
    }

    /** Keyed revocations, rotations, and suite upgrades each advance the context one epoch. */
    private fun advancesEpoch(entry: MembershipEntry): Boolean = when (entry.op) {
        MembershipOp.ADD -> false
        MembershipOp.REVOKE -> entry.hasWrappedKeys
        MembershipOp.ROTATE, MembershipOp.SUITE_UPGRADE -> true
    }

    private fun epochCount(): Int = entriesSnapshot.count { advancesEpoch(it) }

    /**
     * The suite of the log's current era: the genesis identity's suite until a SUITE_UPGRADE,
     * then that entry's target. Builder-side only — verification tracks the era through its own
     * validated walk. Throws on a corrupt upgrade entry or an unknown target: builders must
     * not guess.
     */
    private fun currentEraSuite(resolver: SuiteResolver): ProtocolSuite {
        var suite = resolver.require(entriesSnapshot.first().deviceIdentity.suiteId)
        for (entry in entriesSnapshot) {
            if (entry.op != MembershipOp.SUITE_UPGRADE) continue
            val payload = entry.wrappedKeys?.let { SuiteUpgradePayload.parse(it) }
                ?: throw IllegalArgumentException("Corrupt suite-upgrade entry")
            suite = resolver.require(payload.newSuite)
        }
        return suite
    }

    /**
     * The context's `startEpoch → suiteId` schedule (the migration brief §6), derived from the
     * verified log — a suite transition is a membership event and an epoch boundary, never a
     * device-local setting. Null when the log does not verify: an unverified schedule would be
     * an attacker-chosen one.
     */
    fun suiteSchedule(
        provider: CryptoProvider,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): SuiteSchedule? {
        if (verify(provider, namespace, resolver) !is MembershipVerification.Valid) return null
        val eras = mutableListOf(SuiteSchedule.Era(0, entriesSnapshot.first().deviceIdentity.suiteId))
        var epoch = 0
        for (entry in entriesSnapshot) {
            if (entry.op == MembershipOp.SUITE_UPGRADE) {
                val payload = entry.wrappedKeys?.let { SuiteUpgradePayload.parse(it) } ?: return null
                eras += SuiteSchedule.Era(epoch + 1, payload.newSuite)
            }
            if (advancesEpoch(entry)) epoch += 1
        }
        return SuiteSchedule(eras)
    }

    companion object {
        /** Founds a log: a single self-signed genesis ADD for the founding device. */
        fun found(
            provider: CryptoProvider,
            founder: DeviceIdentity,
            signer: KeyPair,
            wrappedKeys: ByteArray? = null,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): MembershipLog = MembershipLog(
            listOf(signEntry(provider, MembershipEntry.GENESIS_PREVIOUS_HASH, MembershipOp.ADD, founder, wrappedKeys, signer, namespace)),
        )

        /** Far beyond any real device list; the bound is what stops 16 MB of confetti becoming 16 MB of list. */
        private const val MAX_ENTRIES = 10_000

        fun deserialise(data: ByteArray, resolver: SuiteResolver = SuiteRegistry): MembershipLog {
            require(data.size <= ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES) {
                "Membership log of ${data.size} bytes exceeds the ${ProtocolLimits.MAX_MEMBERSHIP_LOG_BYTES}-byte limit"
            }
            val reader = FrameReader(data)
            val entries = mutableListOf<MembershipEntry>()
            // The parse walks eras structurally, mirroring verify(): the genesis identity
            // defines the founding suite, and each SUITE_UPGRADE payload moves it — so signer
            // keys and signatures keep exact per-era size checks even though identities are
            // variable-size and self-describing.
            var era: ProtocolSuite? = null
            while (reader.hasRemaining()) {
                require(entries.size < MAX_ENTRIES) { "Membership log exceeds $MAX_ENTRIES entries" }
                val entryReader = FrameReader(reader.readBytes())
                val entry = MembershipEntry.deserialise(entryReader, resolver, era)
                entryReader.expectEnd()
                entries.add(entry)
                if (era == null) era = resolver.require(entry.deviceIdentity.suiteId)
                if (entry.op == MembershipOp.SUITE_UPGRADE) {
                    val payload = entry.wrappedKeys?.let { SuiteUpgradePayload.parse(it) }
                        ?: throw IllegalArgumentException("Suite upgrade carries a malformed payload")
                    require(resolver.contains(payload.newSuite)) { "Unknown suite ${payload.newSuite.value}" }
                    era = resolver.require(payload.newSuite)
                }
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
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
            suite: ProtocolSuite = Suite1,
        ): MembershipEntry {
            val unsigned = MembershipEntry(previousHash, op, deviceIdentity, wrappedKeys, signer.publicKey, ByteArray(0)).unsignedBytes(namespace)
            return MembershipEntry(
                previousHash = previousHash,
                op = op,
                deviceIdentity = deviceIdentity,
                wrappedKeys = wrappedKeys,
                signerPublicKey = signer.publicKey,
                signature = suite.signature.sign(provider, signer.privateKey, unsigned),
            )
        }
    }
}
