package org.layeredencryption.identity

import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.HybridSignature
import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.suite.Suite1
import org.layeredencryption.suite.SuiteRegistry
import org.layeredencryption.suite.SuiteResolver

/**
 * The continuity proof between a device's legacy identity and its suited replacement (the
 * migration brief §2): without one, a replacement identity is indistinguishable from an
 * unrelated new device.
 *
 * ```
 * KeyTransition     = framed( formatVersion(1)=0x01 ‖ oldIdentity(v1) ‖ newIdentity(v2)
 *                             ‖ signatureByOld ‖ signatureByNew )
 * transitionMessage = framed( "<vendor>/v1/key-transition" ‖ oldIdentity ‖ newIdentity )
 * ```
 *
 * Both signatures cover the same message: the old identity's signing key attests "this new
 * identity succeeds me" (under Suite 1 — every v1 identity is a Suite 1 artifact), and the new
 * identity's signing key attests "I hold the successor's keys" (under the new identity's own
 * suite). [verify] additionally checks both identities' own bindings, so a transition can only
 * link two internally-consistent identities whose private keys were both in hand.
 *
 * This is a standalone, verifiable artifact. Consuming it inside membership verification —
 * replacing a member's identity mid-log — arrives with the suite-sized membership-entry format
 * when a second real suite ships; the SUITE_UPGRADE payload reserves that slot.
 */
class KeyTransition(
    val oldIdentity: DeviceIdentity,
    val newIdentity: DeviceIdentityV2,
    signatureByOld: ByteArray,
    signatureByNew: ByteArray,
) {
    private val _signatureByOld = signatureByOld.copyOf()
    private val _signatureByNew = signatureByNew.copyOf()

    val signatureByOld: ByteArray get() = _signatureByOld.copyOf()
    val signatureByNew: ByteArray get() = _signatureByNew.copyOf()

    fun serialise(): ByteArray = FrameWriter()
        .putBytes(byteArrayOf(FORMAT_VERSION.toByte()))
        .putBytes(oldIdentity.serialise())
        .putBytes(newIdentity.serialise())
        .putBytes(_signatureByOld)
        .putBytes(_signatureByNew)
        .toByteArray()

    /**
     * True only when the whole chain of custody holds: both identities' own bindings verify
     * (old under Suite 1, new under its own suite), and both transition signatures verify over
     * the same message under their respective suites.
     */
    fun verify(
        provider: CryptoProvider,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): Boolean {
        if (!oldIdentity.verifyBinding(provider, namespace)) return false
        if (!newIdentity.verifyBinding(provider, namespace, resolver)) return false
        val message = transitionMessage(oldIdentity, newIdentity, namespace)
        if (!Suite1.signature.verify(provider, oldIdentity.signingPublicKey, message, _signatureByOld)) return false
        val newSuite = resolver.require(newIdentity.suiteId)
        return newSuite.signature.verify(provider, newIdentity.signingPublicKey, message, _signatureByNew)
    }

    companion object {
        const val FORMAT_VERSION = 1

        private const val VERSION_BYTES = 1

        /** Signs the transition with both private keys — possession of both is the whole point. */
        fun create(
            provider: CryptoProvider,
            oldKeys: DeviceKeys,
            newKeys: DeviceKeysV2,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
            resolver: SuiteResolver = SuiteRegistry,
        ): KeyTransition {
            val message = transitionMessage(oldKeys.identity, newKeys.identity, namespace)
            return KeyTransition(
                oldIdentity = oldKeys.identity,
                newIdentity = newKeys.identity,
                signatureByOld = Suite1.signature.sign(provider, oldKeys.signingPrivateKey, message),
                signatureByNew = resolver.require(newKeys.identity.suiteId).signature
                    .sign(provider, newKeys.signingPrivateKey, message),
            )
        }

        /**
         * Strict: version gate first, the old identity at its one legal v1 size, the new
         * identity through the fail-closed v2 decoder (unknown suites die there), signatures at
         * their per-suite sizes, full consumption. Every failure is an [IllegalArgumentException].
         */
        fun deserialise(bytes: ByteArray, resolver: SuiteResolver = SuiteRegistry): KeyTransition {
            val reader = FrameReader(bytes)
            val version = reader.readBytes(VERSION_BYTES)
            require(version.size == VERSION_BYTES && version[0].toInt() == FORMAT_VERSION) {
                "Unsupported key-transition format version"
            }
            val oldIdentity = DeviceIdentity.deserialise(reader.readBytes(DeviceIdentity.SERIALISED_SIZE))
            val newBytes = reader.readBytes(MAX_IDENTITY_BYTES)
            val newIdentity = DeviceIdentityV2.deserialise(newBytes, resolver)
            val newSuite = resolver.require(newIdentity.suiteId)
            val signatureByOld = reader.readBytes(HybridSignature.SIGNATURE_SIZE)
            require(signatureByOld.size == HybridSignature.SIGNATURE_SIZE) { "Old-identity signature has wrong size" }
            val signatureByNew = reader.readBytes(newSuite.signature.signatureSize)
            require(signatureByNew.size == newSuite.signature.signatureSize) { "New-identity signature has wrong size" }
            reader.expectEnd()
            return KeyTransition(oldIdentity, newIdentity, signatureByOld, signatureByNew)
        }

        /** Generous bound on a v2 identity blob; real sizes are a few kilobytes per suite. */
        private const val MAX_IDENTITY_BYTES = 64 * 1024

        internal fun transitionMessage(
            oldIdentity: DeviceIdentity,
            newIdentity: DeviceIdentityV2,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): ByteArray = FrameWriter()
            .putBytes(namespace.label(ProtocolLabels.KEY_TRANSITION))
            .putBytes(oldIdentity.serialise())
            .putBytes(newIdentity.serialise())
            .toByteArray()
    }
}
