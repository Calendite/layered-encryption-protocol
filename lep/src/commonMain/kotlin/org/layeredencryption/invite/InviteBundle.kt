package org.layeredencryption.invite

import org.layeredencryption.CryptoProvider
import org.layeredencryption.KeyPair
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.longToBigEndian8

/**
 * The signed pre-published bundle the inviter posts at `rid_async` (Async_Invites_Spec.md §2.4).
 *
 * ```
 * { inviteXWingPublicKey, deviceIdentityA, expiry (uint64 BE epoch seconds), sigA }
 * sigA = Ed25519_A over framed("calendite/v1/invite-bundle" ‖ rid_async ‖ expiry
 *                              ‖ inviteXWingPublicKey ‖ deviceIdentityA)
 * ```
 *
 * The signature is pinned by the fingerprint carried out-of-band in the link: a relay that swaps the
 * bundle produces a different identity whose fingerprint won't match (§2.7). Adopting PQXDH's
 * pre-published-bundle mechanism, rejecting its directory trust model.
 */
class InviteBundle(
    val inviteXWingPublicKey: ByteArray,
    val deviceIdentityA: DeviceIdentity,
    val expiryEpochSeconds: Long,
    val signature: ByteArray,
) {
    /** Verifies `sigA` over the §2.4 payload, binding in the recomputed [ridAsync]. */
    fun verifySignature(provider: CryptoProvider, ridAsync: ByteArray): Boolean =
        provider.ed25519Verify(deviceIdentityA.ed25519PublicKey, signedPayload(ridAsync, expiryEpochSeconds, inviteXWingPublicKey, deviceIdentityA), signature)

    fun serialise(): ByteArray = FrameWriter()
        .putBytes(inviteXWingPublicKey)
        .putBytes(deviceIdentityA.serialise())
        .putBytes(longToBigEndian8(expiryEpochSeconds))
        .putBytes(signature)
        .toByteArray()

    companion object {
        private val LABEL = "calendite/v1/invite-bundle".encodeToByteArray()

        /** Builds and signs a bundle for the given invite key, identity, expiry, and rendezvous id. */
        fun build(
            provider: CryptoProvider,
            inviteXWingPublicKey: ByteArray,
            deviceIdentityA: DeviceIdentity,
            expiryEpochSeconds: Long,
            ridAsync: ByteArray,
            signer: KeyPair,
        ): InviteBundle {
            val signature = provider.ed25519Sign(
                signer.privateKey,
                signedPayload(ridAsync, expiryEpochSeconds, inviteXWingPublicKey, deviceIdentityA),
            )
            return InviteBundle(inviteXWingPublicKey, deviceIdentityA, expiryEpochSeconds, signature)
        }

        fun deserialise(bytes: ByteArray): InviteBundle {
            val reader = FrameReader(bytes)
            val inviteXWingPublicKey = reader.readBytes()
            val deviceIdentityA = DeviceIdentity.deserialise(reader.readBytes())
            val expiry = bigEndian8ToLong(reader.readBytes())
            val signature = reader.readBytes()
            return InviteBundle(inviteXWingPublicKey, deviceIdentityA, expiry, signature)
        }

        private fun signedPayload(
            ridAsync: ByteArray,
            expiryEpochSeconds: Long,
            inviteXWingPublicKey: ByteArray,
            deviceIdentityA: DeviceIdentity,
        ): ByteArray = FrameWriter()
            .putBytes(LABEL)
            .putBytes(ridAsync)
            .putBytes(longToBigEndian8(expiryEpochSeconds))
            .putBytes(inviteXWingPublicKey)
            .putBytes(deviceIdentityA.serialise())
            .toByteArray()

        private fun bigEndian8ToLong(bytes: ByteArray): Long {
            require(bytes.size == 8) { "Expected 8-byte expiry, was ${bytes.size}" }
            var value = 0L
            for (byte in bytes) value = (value shl 8) or (byte.toLong() and 0xFF)
            return value
        }
    }
}
