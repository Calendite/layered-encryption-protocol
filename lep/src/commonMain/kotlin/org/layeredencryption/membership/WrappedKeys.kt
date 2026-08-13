package org.layeredencryption.membership

import org.layeredencryption.Cascade
import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.XWing
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
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

    /** Seals [secret] once per recipient. Recipients are identified by their signing key hex. */
    fun wrapFor(
        provider: CryptoProvider,
        recipients: List<DeviceIdentity>,
        secret: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
    ): ByteArray {
        val writer = FrameWriter()
        for (recipient in recipients) {
            val encapsulation = XWing.encapsulate(provider, recipient.xWingPublicKey)
            val wrapKey = wrapKey(provider, encapsulation.sharedSecret, namespace)
            writer.putBytes(recipient.signingPublicKey.toHexString().encodeToByteArray())
            writer.putBytes(encapsulation.ciphertext)
            writer.putBytes(Cascade.seal(provider, wrapKey, secret, aad = recipient.serialise(), namespace = namespace))
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
        val own = device.identity.signingPublicKey.toHexString()
        val reader = FrameReader(blob)
        while (reader.hasRemaining()) {
            val memberId = reader.readBytes().decodeToString()
            val kemCiphertext = reader.readBytes()
            val sealed = reader.readBytes()
            if (memberId != own) continue

            val sharedSecret = XWing.decapsulate(provider, device.xWingPrivateKey, kemCiphertext)
            val wrapKey = wrapKey(provider, sharedSecret, namespace)
            return@runCatching Cascade.open(
                provider, wrapKey, sealed, aad = device.identity.serialise(), namespace = namespace,
            )
        }
        null
    }.getOrNull()

    /** Which members a blob carries a copy for, without opening any of them. */
    fun recipientsOf(blob: ByteArray): List<String> = runCatching {
        val recipients = mutableListOf<String>()
        val reader = FrameReader(blob)
        while (reader.hasRemaining()) {
            recipients += reader.readBytes().decodeToString()
            reader.readBytes()
            reader.readBytes()
        }
        recipients.toList()
    }.getOrDefault(emptyList())

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
}
