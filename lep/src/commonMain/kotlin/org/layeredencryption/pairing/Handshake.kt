package org.layeredencryption.pairing

import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameWriter

/** The two roles in a pairing. The inviter shows the code; the joiner types it in. */
enum class PairingRole(internal val label: ByteArray) {
    INVITER("inviter".encodeToByteArray()),
    JOINER("joiner".encodeToByteArray()),
}

/**
 * The canonical handshake transcript — the exact bytes both devices agree they exchanged
 * (docs/Protocol.md §6.3). It binds the X-Wing public key, both device identities, and the KEM
 * ciphertext into every downstream derivation (K_handshake, the MAC, the SAS), so a MITM who
 * swapped any of them produces a different transcript and cannot survive authentication.
 */
class PairingTranscript(
    inviterXWingPublicKey: ByteArray,
    inviterDeviceIdentity: ByteArray,
    kemCiphertext: ByteArray,
    joinerDeviceIdentity: ByteArray,
    sasCommitment: ByteArray,
    /** Carried here so every derivation from this transcript uses the same labels. */
    val namespace: ProtocolNamespace = ProtocolNamespace.Default,
    /**
     * Present only in the negotiated flow: switches [bytes] to the v2 construction, which binds
     * the selected suite id and the raw offer/accept frames ahead of the classic fields — so the
     * code-keyed MACs computed over this transcript authenticate the negotiation itself. Null is
     * the legacy Suite 1 flow, byte for byte (fixture-guarded).
     */
    internal val negotiated: NegotiatedSuiteContext? = null,
) {
    // Copied both ways: a transcript that keyed a MAC cannot be edited into a different one.
    private val _inviterXWingPublicKey = inviterXWingPublicKey.copyOf()
    private val _inviterDeviceIdentity = inviterDeviceIdentity.copyOf()
    private val _kemCiphertext = kemCiphertext.copyOf()
    private val _joinerDeviceIdentity = joinerDeviceIdentity.copyOf()
    private val _sasCommitment = sasCommitment.copyOf()

    val inviterXWingPublicKey: ByteArray get() = _inviterXWingPublicKey.copyOf()
    val inviterDeviceIdentity: ByteArray get() = _inviterDeviceIdentity.copyOf()
    val kemCiphertext: ByteArray get() = _kemCiphertext.copyOf()
    val joinerDeviceIdentity: ByteArray get() = _joinerDeviceIdentity.copyOf()

    /**
     * The inviter's SAS commitment, sent in its hello and bound in here so both MACs cover it.
     * A relay that swapped the commitment would change the transcript and fail the MACs.
     */
    val sasCommitment: ByteArray get() = _sasCommitment.copyOf()

    fun bytes(): ByteArray = if (negotiated == null) {
        FrameWriter()
            .putBytes(namespace.label(SUFFIX))
            .putBytes(_inviterXWingPublicKey)
            .putBytes(_inviterDeviceIdentity)
            .putBytes(_kemCiphertext)
            .putBytes(_joinerDeviceIdentity)
            .putBytes(_sasCommitment)
            .toByteArray()
    } else {
        // The raw offer/accept frames, byte for byte as sent/received — never re-encodings.
        // Tampering with either frame in flight makes the two ends' transcripts disagree, so
        // both code-keyed MACs fail: this is what turns the provisional negotiation checks
        // into an authenticated negotiation (the migration brief §3).
        FrameWriter()
            .putBytes(namespace.label(SUFFIX_NEGOTIATED))
            .putBytes(negotiated.suite.id.toWireBytes())
            .putBytes(negotiated.offerFrame)
            .putBytes(negotiated.acceptFrame)
            .putBytes(_inviterXWingPublicKey)
            .putBytes(_inviterDeviceIdentity)
            .putBytes(_kemCiphertext)
            .putBytes(_joinerDeviceIdentity)
            .putBytes(_sasCommitment)
            .toByteArray()
    }

    private companion object {
        const val SUFFIX = ProtocolLabels.TRANSCRIPT
        const val SUFFIX_NEGOTIATED = ProtocolLabels.TRANSCRIPT_NEGOTIATED
    }
}

/**
 * The two independent authentication locks derived from a completed X-Wing exchange
 * (docs/Protocol.md §4.5):
 *
 * 1. [transcriptMac] — a **code-keyed** MAC. Only a party that knows the pairing code can produce
 *    the matching MAC, so a MITM without the code fails the handshake outright.
 * 2. [shortAuthString] — the 6-digit **SAS** humans compare, catching a MITM who somehow learned
 *    the code but sits between the two devices (their shared secrets would differ).
 */
object Handshake {

    private const val KEY_SIZE = 32
    private const val SAS_ENTROPY_BYTES = 8
    private const val SAS_MODULUS = 1_000_000L
    private const val SAS_DIGITS = 6
    private const val SAS_GROUP = 3

    private const val SUFFIX_PAIRING = ProtocolLabels.PAIRING
    private const val SUFFIX_PAIRING_NEGOTIATED = ProtocolLabels.PAIRING_NEGOTIATED
    private const val SUFFIX_SAS_NEGOTIATED = ProtocolLabels.SAS_NEGOTIATED
    private const val SUFFIX_CODE_SECRET = ProtocolLabels.CODE_SECRET
    private const val SUFFIX_SAS_COMMITMENT = ProtocolLabels.SAS_COMMITMENT
    private val SAS_INFO = "sas".encodeToByteArray()

    /** 32 bytes: the nonce only has to be unguessable until it is revealed one message later. */
    const val SAS_NONCE_SIZE = 32

    /** A fresh SAS nonce for an inviter to commit to. */
    fun sasNonce(provider: CryptoProvider): ByteArray = provider.randomBytes(SAS_NONCE_SIZE)

    /**
     * `SHA-256("<vendor>/v2/sas-commitment" ‖ nonce)` — the inviter publishes this in its hello,
     * before it can see anything the joiner chooses, and reveals the nonce one message later.
     *
     * This is what stops the SAS being ground. Without it the joiner moves last: it picks the KEM
     * ciphertext *after* seeing the inviter's public key, so it can re-encapsulate offline until
     * the resulting SAS equals any value it wants. That is not theoretical — measured against this
     * library it takes about 39 seconds on eight threads to hit a chosen 6-digit target, well
     * inside the code's lifetime, which would let a machine in the middle show both people
     * identical digits.
     *
     * With the commitment, neither side can grind: the joiner cannot compute any candidate SAS
     * because the nonce is still hidden, and the inviter is bound to a nonce it chose before it
     * saw the ciphertext.
     */
    fun sasCommitment(
        provider: CryptoProvider,
        sasNonce: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray = provider.sha256(namespace.label(SUFFIX_SAS_COMMITMENT) + sasNonce)

    /** Whether [sasNonce] opens [commitment]. The joiner must check this before trusting a SAS. */
    fun opensSasCommitment(
        provider: CryptoProvider,
        commitment: ByteArray,
        sasNonce: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): Boolean = sasCommitment(provider, sasNonce, namespace).constantTimeEquals(commitment)

    /**
     * `K_handshake = HKDF(ss, transcript, "calendite/v1/pairing")` — delivers the wrapped keys
     * once. In the negotiated flow the info becomes `"calendite/v1/pairing-negotiated" ‖ suiteId`:
     * the selected suite rides in the derivation itself, not only in the transcript salt.
     */
    fun handshakeKey(
        provider: CryptoProvider,
        sharedSecret: ByteArray,
        transcript: PairingTranscript,
    ): ByteArray {
        val info = transcript.negotiated
            ?.let { transcript.namespace.label(SUFFIX_PAIRING_NEGOTIATED) + it.suite.id.toWireBytes() }
            ?: transcript.namespace.label(SUFFIX_PAIRING)
        return provider.hkdfSha256(ikm = sharedSecret, salt = transcript.bytes(), info = info, length = KEY_SIZE)
    }

    /** Derives the code-secret bound into the transcript MAC from the canonical pairing code. */
    fun codeSecret(
        provider: CryptoProvider,
        canonicalCode: String,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray =
        provider.hkdfSha256(ikm = canonicalCode.encodeToByteArray(), salt = null, info = namespace.label(SUFFIX_CODE_SECRET), length = KEY_SIZE)

    /** `HMAC(K_handshake ‖ code-secret, transcript ‖ role)` (§4.5). */
    fun transcriptMac(
        provider: CryptoProvider,
        handshakeKey: ByteArray,
        codeSecret: ByteArray,
        transcript: PairingTranscript,
        role: PairingRole,
    ): ByteArray {
        val keyMaterial = handshakeKey + codeSecret
        try {
            return mac(provider, keyMaterial, transcript.bytes(), role)
        } finally {
            keyMaterial.fill(0)
        }
    }

    /**
     * Shared low-level MAC used by both the live and async paths: `HMAC(keyMaterial, transcript ‖ role)`
     * (§4.5 / Async_Invites_Spec.md §2.6). The caller supplies the composed key material.
     */
    fun mac(provider: CryptoProvider, keyMaterial: ByteArray, transcriptBytes: ByteArray, role: PairingRole): ByteArray =
        provider.hmacSha256(keyMaterial, transcriptBytes + role.label)

    /**
     * `SAS = HKDF(ss, transcript ‖ sasNonce, "sas") mod 10⁶` as 6 digits grouped 3-3, e.g. `418 902`.
     * Reduced byte-by-byte to avoid overflow and sign issues.
     *
     * [sasNonce] is the value the inviter committed to in its hello (see [sasCommitment]). Binding
     * it in here is what makes the digits unpredictable at the moment the joiner has to choose its
     * ciphertext, and therefore what makes them worth comparing.
     */
    fun shortAuthString(
        provider: CryptoProvider,
        sharedSecret: ByteArray,
        transcript: PairingTranscript,
        sasNonce: ByteArray,
    ): String {
        val info = transcript.negotiated
            ?.let { transcript.namespace.label(SUFFIX_SAS_NEGOTIATED) + it.suite.id.toWireBytes() }
            ?: SAS_INFO
        val entropy = provider.hkdfSha256(ikm = sharedSecret, salt = transcript.bytes() + sasNonce, info = info, length = SAS_ENTROPY_BYTES)
        var value = 0L
        for (byte in entropy) value = (value * 256 + (byte.toInt() and 0xFF)) % SAS_MODULUS
        entropy.fill(0)
        return formatSas(value)
    }

    /** Formats a reduced numeric SAS value as 6 digits grouped 3-3. Shared by both paths. */
    fun formatSas(value: Long): String {
        val digits = value.toString().padStart(SAS_DIGITS, '0')
        return digits.substring(0, SAS_GROUP) + " " + digits.substring(SAS_GROUP)
    }
}

/** Constant-time-ish equality for MAC comparison (length + full-scan, no early exit on mismatch). */
internal fun ByteArray.constantTimeEquals(other: ByteArray): Boolean {
    if (this.size != other.size) return false
    var diff = 0
    for (i in indices) diff = diff or (this[i].toInt() xor other[i].toInt())
    return diff == 0
}
