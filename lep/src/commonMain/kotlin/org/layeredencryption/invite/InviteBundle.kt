package org.layeredencryption.invite

import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.longToBigEndian8
import org.layeredencryption.suite.SuiteId
import org.layeredencryption.suite.SuiteRegistry
import org.layeredencryption.suite.SuiteResolver

/**
 * The signed pre-published bundle the inviter posts at `rid_async` (Async_Invites_Spec.md §2.4),
 * self-describing and suite-bound (the migration brief §4):
 *
 * ```
 * framed( formatVersion(1)=0x02 ‖ suiteId(2 BE) ‖ inviteKemPublicKey
 *         ‖ deviceIdentityA ‖ expiry (8 BE epoch seconds) ‖ sigA )
 * sigA = suite signing over framed("<vendor>/v3/invite-bundle" ‖ formatVersion ‖ suiteId
 *                                  ‖ rid_async ‖ expiry ‖ inviteKemPublicKey ‖ deviceIdentityA)
 * ```
 *
 * The inviter's identity is a [DeviceIdentity] whose suite equals the bundle's by construction,
 * so no decoded or built bundle can ever disagree with itself. The signature covers the format
 * version, the suite, the recipient-relevant material, and the expiry, and it verifies under
 * the bundle's suite — pinned by the fingerprint carried out-of-band in the link, so a relay
 * that swaps the bundle produces a different identity whose fingerprint won't match (§2.7); a
 * relay that downgrades the suite is caught by the joiner's link-vs-bundle equality check.
 * Adopting PQXDH's pre-published-bundle mechanism, rejecting its directory trust model.
 */
class InviteBundle(
    inviteXWingPublicKey: ByteArray,
    val deviceIdentityA: DeviceIdentity,
    val expiryEpochSeconds: Long,
    signature: ByteArray,
) {
    private val _inviteXWingPublicKey = inviteXWingPublicKey.copyOf()
    private val _signature = signature.copyOf()

    val inviteXWingPublicKey: ByteArray get() = _inviteXWingPublicKey.copyOf()
    val signature: ByteArray get() = _signature.copyOf()

    /** The bundle's suite — always the identity's; the two cannot disagree by construction. */
    val suiteId: SuiteId get() = deviceIdentityA.suiteId

    fun serialise(): ByteArray = FrameWriter()
        .putBytes(byteArrayOf(FORMAT_VERSION.toByte()))
        .putBytes(suiteId.toWireBytes())
        .putBytes(_inviteXWingPublicKey)
        .putBytes(deviceIdentityA.serialise())
        .putBytes(longToBigEndian8(expiryEpochSeconds))
        .putBytes(_signature)
        .toByteArray()

    /** Verifies `sigA` under the bundle's suite, binding in the recomputed [ridAsync]. */
    fun verifySignature(
        provider: CryptoProvider,
        ridAsync: ByteArray,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): Boolean = resolver.require(suiteId).signature.verify(
        provider,
        deviceIdentityA.signingPublicKey,
        signedPayload(suiteId, ridAsync, expiryEpochSeconds, _inviteXWingPublicKey, deviceIdentityA, namespace),
        _signature,
    )

    companion object {
        const val FORMAT_VERSION = 2

        private const val VERSION_BYTES = 1
        private const val SUITE_ID_BYTES = 2
        private const val EXPIRY_BYTES = 8

        /** Builds and signs a suited bundle; the suite is the inviter identity's own. */
        fun build(
            provider: CryptoProvider,
            inviteXWingPublicKey: ByteArray,
            deviceKeysA: DeviceKeys,
            expiryEpochSeconds: Long,
            ridAsync: ByteArray,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
            resolver: SuiteResolver = SuiteRegistry,
        ): InviteBundle {
            val identity = deviceKeysA.identity
            val suite = resolver.require(identity.suiteId)
            require(inviteXWingPublicKey.size == suite.kem.publicKeySize) {
                "The invite KEM key must be a suite-${suite.id.value} public key"
            }
            val signature = suite.signature.sign(
                provider,
                deviceKeysA.signingPrivateKey,
                signedPayload(suite.id, ridAsync, expiryEpochSeconds, inviteXWingPublicKey, identity, namespace),
            )
            return InviteBundle(inviteXWingPublicKey, identity, expiryEpochSeconds, signature)
        }

        /**
         * Strict: version gate first, then the suite must resolve (fail closed), then every
         * field at its exact per-suite size — the embedded identity through its own fail-closed
         * decoder, and its suite must equal the bundle's — then full consumption. Every failure
         * is an [IllegalArgumentException].
         */
        fun deserialise(bytes: ByteArray, resolver: SuiteResolver = SuiteRegistry): InviteBundle {
            val reader = FrameReader(bytes)
            val version = reader.readBytes(VERSION_BYTES)
            require(version.size == VERSION_BYTES && version[0].toInt() == FORMAT_VERSION) {
                "Unsupported bundle format version"
            }
            val suiteBytes = reader.readBytes(SUITE_ID_BYTES)
            require(suiteBytes.size == SUITE_ID_BYTES) { "Suite id must be $SUITE_ID_BYTES bytes" }
            val suiteId = SuiteId((((suiteBytes[0].toInt() and 0xFF) shl 8) or (suiteBytes[1].toInt() and 0xFF)).toUShort())
            require(resolver.contains(suiteId)) { "Unknown suite ${suiteId.value}" }
            val suite = resolver.require(suiteId)
            val inviteXWingPublicKey = reader.readBytes(suite.kem.publicKeySize)
            require(inviteXWingPublicKey.size == suite.kem.publicKeySize) { "Invite KEM key has wrong size" }
            val deviceIdentityA = DeviceIdentity.deserialise(
                reader.readBytes(DeviceIdentity.serialisedSize(suite)), resolver,
            )
            require(deviceIdentityA.suiteId == suiteId) { "Bundle and identity suites disagree" }
            val expiryBytes = reader.readBytes(EXPIRY_BYTES)
            require(expiryBytes.size == EXPIRY_BYTES) { "Expiry must be $EXPIRY_BYTES bytes" }
            var expiry = 0L
            for (byte in expiryBytes) expiry = (expiry shl 8) or (byte.toLong() and 0xFF)
            val signature = reader.readBytes(suite.signature.signatureSize)
            require(signature.size == suite.signature.signatureSize) { "Bundle signature has wrong size" }
            reader.expectEnd()
            return InviteBundle(inviteXWingPublicKey, deviceIdentityA, expiry, signature)
        }

        private fun signedPayload(
            suiteId: SuiteId,
            ridAsync: ByteArray,
            expiryEpochSeconds: Long,
            inviteXWingPublicKey: ByteArray,
            deviceIdentityA: DeviceIdentity,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): ByteArray = FrameWriter()
            .putBytes(namespace.label(ProtocolLabels.INVITE_BUNDLE_SUITED))
            .putBytes(byteArrayOf(FORMAT_VERSION.toByte()))
            .putBytes(suiteId.toWireBytes())
            .putBytes(ridAsync)
            .putBytes(longToBigEndian8(expiryEpochSeconds))
            .putBytes(inviteXWingPublicKey)
            .putBytes(deviceIdentityA.serialise())
            .toByteArray()
    }
}
