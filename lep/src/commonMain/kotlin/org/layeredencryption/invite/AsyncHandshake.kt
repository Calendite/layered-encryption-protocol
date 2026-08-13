package org.layeredencryption.invite

import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameWriter
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.longToBigEndian8
import org.layeredencryption.pairing.Handshake
import org.layeredencryption.pairing.PairingException

/**
 * Async-invite key derivation (Async_Invites_Spec.md §2.5–§2.6).
 *
 * The X-Wing combiner is untouched — `ss` comes out of it verbatim. The identity DH `dh1` is chained
 * in *afterwards* (Noise-style), and every public value + the ciphertext is bound via [transcript]
 * in the HKDF `info`, so this doesn't reintroduce the naive-concat hazard the combiner vow guards
 * against. Chaining an extra secret into an already-strong key is monotone.
 *
 * ```
 * transcript = framed("calendite/v1/transcript-async" ‖ rid_async ‖ expiry
 *                     ‖ inviteXWingPublicKey ‖ deviceIdentityA ‖ kemCiphertext ‖ deviceIdentityS)
 * K_async    = HKDF( ikm = ss ‖ dh1, salt = "calendite/v1/pairing-async", info = transcript, 32 )
 * ```
 */
object AsyncHandshake {

    private const val KEY_SIZE = 32
    private const val SAS_ENTROPY_BYTES = 4
    private const val SAS_MODULUS = 1_000_000L

    private const val SUFFIX_TRANSCRIPT = ProtocolLabels.TRANSCRIPT_ASYNC
    private const val SUFFIX_PAIRING = ProtocolLabels.PAIRING_ASYNC
    private const val SUFFIX_LINK_AUTH = ProtocolLabels.ASYNC_LINK_AUTH
    private val SAS_INFO = "sas".encodeToByteArray()

    /**
     * The cheap link-possession MAC over a response's public fields (LEP-01 / LEP-06):
     *
     * ```
     * linkProofMac = HMAC-SHA256( secret,
     *                             framed("calendite/v1/async-link-auth" ‖ rid_async
     *                                    ‖ kemCiphertext ‖ deviceIdentityS) )
     * ```
     *
     * The inviter verifies this single HMAC **before** identity-signature verification, ML-KEM
     * decapsulation, and X25519, so a stranger who never saw the link cannot make it spend
     * post-quantum compute. It proves link possession only; the full-handshake `joinerMac`
     * (keyed by `K_async ‖ secret`) still gates the actual claim.
     */
    fun linkProofMac(
        provider: CryptoProvider,
        secret: ByteArray,
        ridAsync: ByteArray,
        kemCiphertext: ByteArray,
        deviceIdentityS: DeviceIdentity,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray = provider.hmacSha256(
        secret,
        FrameWriter()
            .putBytes(namespace.label(SUFFIX_LINK_AUTH))
            .putBytes(ridAsync)
            .putBytes(kemCiphertext)
            .putBytes(deviceIdentityS.serialise())
            .toByteArray(),
    )

    fun transcript(
        ridAsync: ByteArray,
        expiryEpochSeconds: Long,
        inviteXWingPublicKey: ByteArray,
        deviceIdentityA: DeviceIdentity,
        kemCiphertext: ByteArray,
        deviceIdentityS: DeviceIdentity,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray = FrameWriter()
        .putBytes(namespace.label(SUFFIX_TRANSCRIPT))
        .putBytes(ridAsync)
        .putBytes(longToBigEndian8(expiryEpochSeconds))
        .putBytes(inviteXWingPublicKey)
        .putBytes(deviceIdentityA.serialise())
        .putBytes(kemCiphertext)
        .putBytes(deviceIdentityS.serialise())
        .toByteArray()

    /** `K_async = HKDF(ss ‖ dh1, "calendite/v1/pairing-async", transcript, 32)`. */
    fun asyncKey(
        provider: CryptoProvider,
        sharedSecret: ByteArray,
        dh1: ByteArray,
        transcript: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray =
        provider.hkdfSha256(
            ikm = sharedSecret + dh1,
            salt = namespace.label(SUFFIX_PAIRING),
            info = transcript,
            length = KEY_SIZE,
        )

    /** `SAS = uint32BE(HKDF(ss ‖ dh1, salt, transcript ‖ "sas", 4)) mod 10⁶`, 6 digits grouped 3-3 (§2.6). */
    fun shortAuthString(
        provider: CryptoProvider,
        sharedSecret: ByteArray,
        dh1: ByteArray,
        transcript: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): String {
        val out = provider.hkdfSha256(
            ikm = sharedSecret + dh1,
            salt = namespace.label(SUFFIX_PAIRING),
            info = transcript + SAS_INFO,
            length = SAS_ENTROPY_BYTES,
        )
        val value = ((out[0].toLong() and 0xFF) shl 24) or
            ((out[1].toLong() and 0xFF) shl 16) or
            ((out[2].toLong() and 0xFF) shl 8) or
            (out[3].toLong() and 0xFF)
        return Handshake.formatSas(value % SAS_MODULUS)
    }

    /**
     * Computes the `dh1` identity DH with a contributory-behaviour guard (§2.5).
     *
     * Two backstops: audited X25519 implementations (Bouncy Castle) already *fail closed* on a
     * low-order peer key by throwing; we map that to a [PairingException]. And should an
     * implementation instead return an all-zero secret, [requireContributory] rejects it. Either way
     * a peer key that contributes nothing can never yield a usable `dh1`.
     */
    fun contributoryDh(provider: CryptoProvider, privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        val dh1 = try {
            provider.x25519(privateKey, peerPublicKey)
        } catch (e: Exception) {
            throw PairingException("X25519 dh1 failed — non-contributory or invalid peer key")
        }
        return requireContributory(dh1)
    }

    /** RFC 7748 contributory guard: an all-zero result means the peer contributed nothing — reject. */
    fun requireContributory(dh1: ByteArray): ByteArray {
        if (dh1.all { it.toInt() == 0 }) throw PairingException("Non-contributory X25519 dh1 (all-zero) — rejected")
        return dh1
    }
}
