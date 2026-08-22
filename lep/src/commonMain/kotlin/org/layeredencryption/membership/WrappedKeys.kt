package org.layeredencryption.membership

import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolLimits
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.decodeUtf8Strict
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.suite.ProtocolSuite
import org.layeredencryption.toHexString

/**
 * A secret sealed separately for each member of a context, carried in one membership entry.
 *
 * This exists for rotation. Removing somebody has to replace the context key, which means handing
 * the replacement to everybody who remains. There is no shared per-pair key to do that with once
 * pairing is over, so each recipient gets their own copy, encapsulated to the long-term
 * [DeviceIdentity.xWingPublicKey] in their identity.
 *
 * ```
 * for each recipient R:
 *   (ct, ss) = suite.kem.encapsulate(R.kem_pk)
 *   wk       = HKDF(ss, salt = none, info = "<vendor>/v2/member-key-wrap" ‖ suiteId, 32)
 *   sealed   = suite.aead(wk, secret, aad = R.serialise())
 *
 * blob = framed( for each R: framed(memberId) ‖ framed(ct) ‖ framed(sealed) )
 * ```
 *
 * Everything is sized and routed by the era's suite, with the binary suite id in the wrap-key
 * derivation, so a copy wrapped for one suite can never silently unwrap under another.
 *
 * Three things worth naming:
 *
 * **It is hybrid, deliberately.** The identity also carries a classical X25519 key, and wrapping
 * under that would have been simpler and shorter. It would also have meant a recorded rotation
 * falls to a quantum adversary, which would put back the exact hole the rest of the protocol
 * spends so much to avoid. A rotation is long-lived material: it is written into a log that is
 * replicated and kept.
 *
 * **The recipient's identity is the associated data.** A copy sealed for one member cannot be
 * replayed at another, even by somebody who can rewrite the log, because the tag covers who it
 * was for.
 *
 * **A member reads only their own copy.** [unwrapFor] finds the entry addressed to the caller and
 * ignores the rest, which it could not open anyway.
 */
object WrappedKeys {

    private const val WRAP_KEY_SIZE = 32
    private const val LENGTH_PREFIX = 4

    /** The one thing this construction wraps in this protocol: a 32-byte context master key. */
    const val CONTEXT_KEY_BYTES = 32

    /**
     * The exact serialised size of one recipient's copy under [suite], or an
     * [IllegalArgumentException] if the suite declares sizes that cannot describe a real
     * construction. Computed in [Long] and range-checked: a suite is data, and a hostile or
     * buggy one must not be able to overflow a size calculation into a small positive number.
     */
    internal fun copyBytes(suite: ProtocolSuite): Int {
        val memberIdHex = suite.signature.publicKeySize.toLong() * 2
        val ciphertext = suite.kem.ciphertextSize.toLong()
        val sealed = suite.aead.sealedSize(CONTEXT_KEY_BYTES).toLong()
        require(memberIdHex > 0 && ciphertext > 0 && sealed > 0) {
            "Suite ${suite.id.value} declares a non-positive field size"
        }
        val total = 3L * LENGTH_PREFIX + memberIdHex + ciphertext + sealed
        require(total in 1..Int.MAX_VALUE.toLong()) { "Suite ${suite.id.value} copy size is out of range" }
        return total.toInt()
    }

    /**
     * How many recipients one wrapped-keys blob can hold under [suite] before it exceeds
     * [ProtocolLimits.MAX_WRAPPED_KEYS_BYTES] — the single source of truth shared by the
     * encoder's preflight and the decoder's bound, so the two can never disagree about what
     * fits (LEP-R4). Membership is separately capped at [ProtocolLimits.MAX_ACTIVE_MEMBERS],
     * which must stay below this for every supported suite.
     */
    fun maxRecipients(suite: ProtocolSuite, budget: Int = ProtocolLimits.MAX_WRAPPED_KEYS_BYTES): Int {
        require(budget > 0) { "The wrapped-keys budget must be positive" }
        return budget / copyBytes(suite)
    }

    /** Seals [secret] once per recipient under [suite]. Recipients are identified by signing-key hex. */
    fun wrapFor(
        provider: CryptoProvider,
        suite: ProtocolSuite,
        recipients: List<DeviceIdentity>,
        secret: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray {
        require(secret.size == CONTEXT_KEY_BYTES) { "WrappedKeys wraps the $CONTEXT_KEY_BYTES-byte context key" }
        val ids = recipients.map { it.signingPublicKey.toHexString() }
        require(ids.toSet().size == ids.size) { "Duplicate recipient in wrap list" }
        // Preflight before the first encapsulation (LEP-R4): an output this parser would refuse
        // is worth nothing, and discovering that after N post-quantum KEM operations wastes the
        // work and hands an attacker a compute amplifier.
        val capacity = maxRecipients(suite)
        require(recipients.size <= capacity) {
            "A suite-${suite.id.value} wrapped-keys blob holds at most $capacity recipients, was ${recipients.size}"
        }
        val writer = FrameWriter()
        for (recipient in recipients) {
            val encapsulation = suite.kem.encapsulate(provider, recipient.xWingPublicKey)
            val wrapKey = wrapKey(provider, suite, encapsulation.sharedSecret, namespace)
            writer.putBytes(recipient.signingPublicKey.toHexString().encodeToByteArray())
            writer.putBytes(encapsulation.ciphertext)
            writer.putBytes(suite.aead.seal(provider, wrapKey, secret, aad = recipient.serialise(), namespace = namespace))
        }
        return writer.toByteArray().also {
            // The preflight above should make this unreachable; it is asserted anyway because a
            // blob the decoder refuses is an unrecoverable context, not a recoverable error.
            check(it.size <= ProtocolLimits.MAX_WRAPPED_KEYS_BYTES) {
                "Wrapped-keys blob of ${it.size} bytes exceeds its budget despite preflight"
            }
        }
    }

    /**
     * Recovers the secret sealed for [device], or null if there is none or it will not open.
     *
     * Null covers both "this rotation was not addressed to me", which happens to a device that was
     * revoked by it, and "the blob is malformed". Neither is worth an exception: the caller's next
     * move is the same either way, which is to carry on without that epoch.
     */
    fun unwrapFor(
        provider: CryptoProvider,
        suite: ProtocolSuite,
        blob: ByteArray,
        device: DeviceKeys,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray? = runCatching {
        val copies = parse(suite, blob)
        val own = device.identity.signingPublicKey.toHexString()
        val mine = copies.firstOrNull { it.memberId == own } ?: return@runCatching null
        val sharedSecret = suite.kem.decapsulate(provider, device.xWingPrivateKey, mine.kemCiphertext)
        val wrapKey = wrapKey(provider, suite, sharedSecret, namespace)
        suite.aead.open(provider, wrapKey, mine.sealed, aad = device.identity.serialise(), namespace = namespace)
    }.getOrNull()

    /** Which members a blob carries a copy for, without opening any of them. */
    fun recipientsOf(suite: ProtocolSuite, blob: ByteArray): List<String> =
        runCatching { parse(suite, blob).map { it.memberId } }.getOrDefault(emptyList())

    /**
     * Like [recipientsOf], but a malformed blob is null rather than an empty list — verification
     * needs to tell "no recipients" apart from "unparseable", because both must fail and for
     * different stated reasons.
     */
    internal fun recipientsOrNull(suite: ProtocolSuite, blob: ByteArray): List<String>? =
        runCatching { parse(suite, blob).map { it.memberId } }.getOrNull()

    private class Copy(val memberId: String, val kemCiphertext: ByteArray, val sealed: ByteArray)

    /**
     * Parses and validates the **complete** blob before anything is decrypted, with sizes from
     * [suite]: strict lowercase-hex identifiers of the exact signing-key length, unique
     * recipients, an exact KEM ciphertext size for every copy (not only the caller's), and one
     * canonical sealed-copy length. A duplicate or malformed copy *after* the caller's own
     * therefore fails the whole blob — a currently-authorised malicious member cannot sign a
     * non-canonical structure that different consumers would read differently.
     */
    private fun parse(suite: ProtocolSuite, blob: ByteArray): List<Copy> {
        // The same total budget on every path — direct callers included, not only blobs that
        // arrived inside a membership entry.
        require(blob.size <= ProtocolLimits.MAX_WRAPPED_KEYS_BYTES) {
            "Wrapped-keys blob of ${blob.size} bytes exceeds the ${ProtocolLimits.MAX_WRAPPED_KEYS_BYTES}-byte limit"
        }
        val memberIdHexLength = suite.signature.publicKeySize * 2
        val ciphertextSize = suite.kem.ciphertextSize
        val sealedBytes = suite.aead.sealedSize(CONTEXT_KEY_BYTES)
        // Derived from the same byte budget as the encoder's preflight, so the count limit and
        // the total limit cannot disagree.
        val maxRecipients = maxRecipients(suite)
        val reader = FrameReader(blob)
        val copies = mutableListOf<Copy>()
        val seen = mutableSetOf<String>()
        while (reader.hasRemaining()) {
            require(copies.size < maxRecipients) { "More than $maxRecipients wrapped copies" }
            val memberId = reader.readBytes(memberIdHexLength).decodeUtf8Strict()
            require(memberId.length == memberIdHexLength) { "Member id must be $memberIdHexLength characters" }
            require(memberId.all { it in '0'..'9' || it in 'a'..'f' }) { "Member id must be lowercase hex" }
            require(seen.add(memberId)) { "Duplicate wrapped-copy recipient" }
            val kemCiphertext = reader.readBytes(ciphertextSize)
            require(kemCiphertext.size == ciphertextSize) { "Wrapped-copy KEM ciphertext has wrong size" }
            val sealed = reader.readBytes(sealedBytes)
            require(sealed.size == sealedBytes) { "Sealed copy must be exactly $sealedBytes bytes" }
            copies += Copy(memberId, kemCiphertext, sealed)
        }
        return copies
    }

    private fun wrapKey(
        provider: CryptoProvider,
        suite: ProtocolSuite,
        sharedSecret: ByteArray,
        namespace: ProtocolNamespace,
    ): ByteArray = provider.hkdfSha256(
        ikm = sharedSecret,
        salt = null,
        info = namespace.label(ProtocolLabels.MEMBER_KEY_WRAP_SUITED) + suite.id.toWireBytes(),
        length = WRAP_KEY_SIZE,
    )
}
