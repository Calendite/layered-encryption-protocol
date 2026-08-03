package org.layeredencryption.pairing

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
    val inviterXWingPublicKey: ByteArray,
    val inviterDeviceIdentity: ByteArray,
    val kemCiphertext: ByteArray,
    val joinerDeviceIdentity: ByteArray,
) {
    fun bytes(): ByteArray = FrameWriter()
        .putBytes(LABEL)
        .putBytes(inviterXWingPublicKey)
        .putBytes(inviterDeviceIdentity)
        .putBytes(kemCiphertext)
        .putBytes(joinerDeviceIdentity)
        .toByteArray()

    private companion object {
        val LABEL = "calendite/v1/transcript".encodeToByteArray()
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

    private val PAIRING_INFO = "calendite/v1/pairing".encodeToByteArray()
    private val CODE_SECRET_INFO = "calendite/v1/code-secret".encodeToByteArray()
    private val SAS_INFO = "sas".encodeToByteArray()

    /** `K_handshake = HKDF(ss, transcript, "calendite/v1/pairing")` — delivers the wrapped keys once. */
    fun handshakeKey(provider: CryptoProvider, sharedSecret: ByteArray, transcript: PairingTranscript): ByteArray =
        provider.hkdfSha256(ikm = sharedSecret, salt = transcript.bytes(), info = PAIRING_INFO, length = KEY_SIZE)

    /** Derives the code-secret bound into the transcript MAC from the canonical pairing code. */
    fun codeSecret(provider: CryptoProvider, canonicalCode: String): ByteArray =
        provider.hkdfSha256(ikm = canonicalCode.encodeToByteArray(), salt = null, info = CODE_SECRET_INFO, length = KEY_SIZE)

    /** `HMAC(K_handshake ‖ code-secret, transcript ‖ role)` (§4.5). */
    fun transcriptMac(
        provider: CryptoProvider,
        handshakeKey: ByteArray,
        codeSecret: ByteArray,
        transcript: PairingTranscript,
        role: PairingRole,
    ): ByteArray = mac(provider, handshakeKey + codeSecret, transcript.bytes(), role)

    /**
     * Shared low-level MAC used by both the live and async paths: `HMAC(keyMaterial, transcript ‖ role)`
     * (§4.5 / Async_Invites_Spec.md §2.6). The caller supplies the composed key material.
     */
    fun mac(provider: CryptoProvider, keyMaterial: ByteArray, transcriptBytes: ByteArray, role: PairingRole): ByteArray =
        provider.hmacSha256(keyMaterial, transcriptBytes + role.label)

    /**
     * `SAS = HKDF(ss, transcript, "sas") mod 10⁶` as 6 digits grouped 3-3, e.g. `418 902` (§4.5).
     * Reduced byte-by-byte to avoid overflow and sign issues.
     */
    fun shortAuthString(provider: CryptoProvider, sharedSecret: ByteArray, transcript: PairingTranscript): String {
        val entropy = provider.hkdfSha256(ikm = sharedSecret, salt = transcript.bytes(), info = SAS_INFO, length = SAS_ENTROPY_BYTES)
        var value = 0L
        for (byte in entropy) value = (value * 256 + (byte.toInt() and 0xFF)) % SAS_MODULUS
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
