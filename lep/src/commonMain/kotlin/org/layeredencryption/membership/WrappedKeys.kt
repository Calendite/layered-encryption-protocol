package org.layeredencryption.membership

import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.HybridSignature
import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolLimits
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.XWing
import org.layeredencryption.decodeUtf8Strict
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.suite.ProtocolSuite
import org.layeredencryption.suite.Suite1
import org.layeredencryption.suite.SuiteId
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
 *   (ct, ss) = XWing.encapsulate(R.xwing_pk)
 *   wk       = HKDF(ss, salt = none, info = "<vendor>/v1/member-key-wrap", 32)
 *   sealed   = Cascade(wk, secret, aad = R.serialise())
 *
 * blob = framed( for each R: framed(memberId) ‖ framed(ct) ‖ framed(sealed) )
 * ```
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

    /** The signing public key as lowercase hex: 2 characters per byte. */
    private const val MEMBER_ID_HEX_LENGTH = HybridSignature.PUBLIC_KEY_SIZE * 2

    /**
     * The exact size of one sealed copy — the cascade output for a 32-byte plaintext:
     * `n1(12) ‖ n2(12) ‖ chacha(32 + tag 16) sealed by gcm(+ tag 16)`. Because the wrapped
     * secret has one length, the sealed field has one canonical length, checked exactly.
     */
    internal const val SEALED_BYTES = 12 + 12 + CONTEXT_KEY_BYTES + 16 + 16

    /** One copy's exact serialised size: three length-prefixed fields. */
    private const val COPY_BYTES =
        LENGTH_PREFIX + MEMBER_ID_HEX_LENGTH + LENGTH_PREFIX + XWing.CIPHERTEXT_SIZE + LENGTH_PREFIX + SEALED_BYTES

    /**
     * Derived from the byte budget, so the count limit and the total limit cannot disagree:
     * the most copies that can physically fit in [ProtocolLimits.MAX_WRAPPED_KEYS_BYTES].
     */
    private const val MAX_RECIPIENTS = ProtocolLimits.MAX_WRAPPED_KEYS_BYTES / COPY_BYTES

    /** Seals [secret] once per recipient. Recipients are identified by their signing key hex. */
    fun wrapFor(
        provider: CryptoProvider,
        recipients: List<DeviceIdentity>,
        secret: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray {
        require(secret.size == CONTEXT_KEY_BYTES) { "WrappedKeys wraps the $CONTEXT_KEY_BYTES-byte context key" }
        require(recipients.size <= MAX_RECIPIENTS) { "More than $MAX_RECIPIENTS recipients" }
        val ids = recipients.map { it.signingPublicKey.toHexString() }
        require(ids.toSet().size == ids.size) { "Duplicate recipient in wrap list" }
        val writer = FrameWriter()
        for (recipient in recipients) {
            val encapsulation = Suite1.kem.encapsulate(provider, recipient.xWingPublicKey)
            val wrapKey = wrapKey(provider, encapsulation.sharedSecret, namespace)
            writer.putBytes(recipient.signingPublicKey.toHexString().encodeToByteArray())
            writer.putBytes(encapsulation.ciphertext)
            writer.putBytes(Suite1.aead.seal(provider, wrapKey, secret, aad = recipient.serialise(), namespace = namespace))
        }
        return writer.toByteArray()
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
        blob: ByteArray,
        device: DeviceKeys,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray? = runCatching {
        val copies = parse(blob)
        val own = device.identity.signingPublicKey.toHexString()
        val mine = copies.firstOrNull { it.memberId == own } ?: return@runCatching null

        val sharedSecret = Suite1.kem.decapsulate(provider, device.xWingPrivateKey, mine.kemCiphertext)
        val wrapKey = wrapKey(provider, sharedSecret, namespace)
        Suite1.aead.open(provider, wrapKey, mine.sealed, aad = device.identity.serialise(), namespace = namespace)
    }.getOrNull()

    /** Which members a blob carries a copy for, without opening any of them. */
    fun recipientsOf(blob: ByteArray): List<String> =
        runCatching { parse(blob).map { it.memberId } }.getOrDefault(emptyList())

    /**
     * Like [recipientsOf], but a malformed blob is null rather than an empty list — verification
     * needs to tell "no recipients" apart from "unparseable", because both must fail and for
     * different stated reasons.
     */
    internal fun recipientsOrNull(blob: ByteArray): List<String>? =
        runCatching { parse(blob).map { it.memberId } }.getOrNull()

    private class Copy(val memberId: String, val kemCiphertext: ByteArray, val sealed: ByteArray)

    /**
     * Parses and validates the **complete** blob before anything is decrypted: strict
     * lowercase-hex identifiers of the exact signing-key length, unique recipients, an exact KEM
     * ciphertext size for every copy (not only the caller's), and bounded sealed payloads. A
     * duplicate or malformed copy *after* the caller's own therefore fails the whole blob — a
     * currently-authorised malicious member cannot sign a non-canonical structure that different
     * consumers would read differently.
     */
    private fun parse(blob: ByteArray): List<Copy> {
        // The same total budget on every path — direct callers included, not only blobs that
        // arrived inside a membership entry.
        require(blob.size <= ProtocolLimits.MAX_WRAPPED_KEYS_BYTES) {
            "Wrapped-keys blob of ${blob.size} bytes exceeds the ${ProtocolLimits.MAX_WRAPPED_KEYS_BYTES}-byte limit"
        }
        val reader = FrameReader(blob)
        val copies = mutableListOf<Copy>()
        val seen = mutableSetOf<String>()
        while (reader.hasRemaining()) {
            require(copies.size < MAX_RECIPIENTS) { "More than $MAX_RECIPIENTS wrapped copies" }
            val memberId = reader.readBytes(MEMBER_ID_HEX_LENGTH).decodeUtf8Strict()
            require(memberId.length == MEMBER_ID_HEX_LENGTH) { "Member id must be $MEMBER_ID_HEX_LENGTH characters" }
            require(memberId.all { it in '0'..'9' || it in 'a'..'f' }) { "Member id must be lowercase hex" }
            require(seen.add(memberId)) { "Duplicate wrapped-copy recipient" }
            val kemCiphertext = reader.readBytes(XWing.CIPHERTEXT_SIZE)
            require(kemCiphertext.size == XWing.CIPHERTEXT_SIZE) { "Wrapped-copy KEM ciphertext has wrong size" }
            val sealed = reader.readBytes(SEALED_BYTES)
            require(sealed.size == SEALED_BYTES) { "Sealed copy must be exactly $SEALED_BYTES bytes" }
            copies += Copy(memberId, kemCiphertext, sealed)
        }
        return copies
    }

    private fun wrapKey(
        provider: CryptoProvider,
        sharedSecret: ByteArray,
        namespace: ProtocolNamespace,
    ): ByteArray = provider.hkdfSha256(
        ikm = sharedSecret,
        salt = null,
        info = namespace.label(ProtocolLabels.MEMBER_KEY_WRAP),
        length = WRAP_KEY_SIZE,
    )

    // ── Era-aware paths (Phase 1 crypto agility) ──────────────────────────────────────────────
    //
    // A Suite 1 era uses the frozen v1 construction above, byte for byte. A later era — after a
    // SUITE_UPGRADE — uses the same per-recipient structure with sizes taken from the era's
    // suite and the wrap key derived under "v2/member-key-wrap" with the binary suite id in the
    // info, so a copy wrapped for one suite can never silently unwrap under another.

    internal fun wrapForEra(
        provider: CryptoProvider,
        suite: ProtocolSuite,
        recipients: List<DeviceIdentity>,
        secret: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray {
        if (suite.id == SuiteId.LEP_HYBRID_2026) return wrapFor(provider, recipients, secret, namespace)
        require(secret.size == CONTEXT_KEY_BYTES) { "WrappedKeys wraps the $CONTEXT_KEY_BYTES-byte context key" }
        val ids = recipients.map { it.signingPublicKey.toHexString() }
        require(ids.toSet().size == ids.size) { "Duplicate recipient in wrap list" }
        val writer = FrameWriter()
        for (recipient in recipients) {
            val encapsulation = suite.kem.encapsulate(provider, recipient.xWingPublicKey)
            val wrapKey = suitedWrapKey(provider, suite, encapsulation.sharedSecret, namespace)
            writer.putBytes(recipient.signingPublicKey.toHexString().encodeToByteArray())
            writer.putBytes(encapsulation.ciphertext)
            writer.putBytes(suite.aead.seal(provider, wrapKey, secret, aad = recipient.serialise(), namespace = namespace))
        }
        return writer.toByteArray()
    }

    internal fun unwrapForEra(
        provider: CryptoProvider,
        suite: ProtocolSuite,
        blob: ByteArray,
        device: DeviceKeys,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray? {
        if (suite.id == SuiteId.LEP_HYBRID_2026) return unwrapFor(provider, blob, device, namespace)
        return runCatching {
            val copies = parseForSuite(suite, blob)
            val own = device.identity.signingPublicKey.toHexString()
            val mine = copies.firstOrNull { it.memberId == own } ?: return@runCatching null
            val sharedSecret = suite.kem.decapsulate(provider, device.xWingPrivateKey, mine.kemCiphertext)
            val wrapKey = suitedWrapKey(provider, suite, sharedSecret, namespace)
            suite.aead.open(provider, wrapKey, mine.sealed, aad = device.identity.serialise(), namespace = namespace)
        }.getOrNull()
    }

    /** Like [recipientsOrNull], parameterised by the era's suite; null on anything malformed. */
    internal fun recipientsOrNullForEra(suite: ProtocolSuite, blob: ByteArray): List<String>? {
        if (suite.id == SuiteId.LEP_HYBRID_2026) return recipientsOrNull(blob)
        return runCatching { parseForSuite(suite, blob).map { it.memberId } }.getOrNull()
    }

    /** The suited parse: identical rules to [parse], sizes from the era's suite. */
    private fun parseForSuite(suite: ProtocolSuite, blob: ByteArray): List<Copy> {
        require(blob.size <= ProtocolLimits.MAX_WRAPPED_KEYS_BYTES) {
            "Wrapped-keys blob of ${blob.size} bytes exceeds the ${ProtocolLimits.MAX_WRAPPED_KEYS_BYTES}-byte limit"
        }
        val memberIdHexLength = suite.signature.publicKeySize * 2
        val ciphertextSize = suite.kem.ciphertextSize
        val sealedBytes = suite.aead.sealedSize(CONTEXT_KEY_BYTES)
        val copyBytes = LENGTH_PREFIX + memberIdHexLength + LENGTH_PREFIX + ciphertextSize + LENGTH_PREFIX + sealedBytes
        val maxRecipients = ProtocolLimits.MAX_WRAPPED_KEYS_BYTES / copyBytes
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

    private fun suitedWrapKey(
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
