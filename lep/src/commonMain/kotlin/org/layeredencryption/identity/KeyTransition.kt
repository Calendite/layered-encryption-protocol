package org.layeredencryption.identity

import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.suite.SuiteRegistry
import org.layeredencryption.suite.SuiteResolver

/**
 * The continuity proof between a device's identity and its replacement (the migration brief
 * §2): without one, a replacement identity is indistinguishable from an unrelated new device.
 *
 * ```
 * KeyTransition     = framed( formatVersion(1)=0x01 ‖ oldIdentity ‖ newIdentity
 *                             ‖ signatureByOld ‖ signatureByNew )
 * transitionMessage = framed( "<vendor>/v1/key-transition" ‖ oldIdentity ‖ newIdentity )
 * ```
 *
 * Both signatures cover the same message: the old identity's signing key attests "this new
 * identity succeeds me", and the new identity's signing key attests "I hold the successor's
 * keys" — each under its identity's **own** suite (identities are self-describing). [verify]
 * additionally checks both identities' own bindings, so a transition can only link two
 * internally-consistent identities whose private keys were both in hand. Cross-suite
 * transitions carry a device into a new era; same-suite transitions are identity re-keying.
 *
 * This is a standalone, verifiable artifact. Consuming it inside membership verification —
 * replacing a member's identity mid-log — arrives with a later payload version; the
 * SUITE_UPGRADE payload reserves that slot.
 */
class KeyTransition(
    val oldIdentity: DeviceIdentity,
    val newIdentity: DeviceIdentity,
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
     * under their own suites, and both transition signatures verify over the same message —
     * the old leg under the old identity's suite, the new leg under the new identity's.
     */
    fun verify(
        provider: CryptoProvider,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): Boolean {
        if (!oldIdentity.verifyBinding(provider, namespace, resolver)) return false
        if (!newIdentity.verifyBinding(provider, namespace, resolver)) return false
        val message = transitionMessage(oldIdentity, newIdentity, namespace)
        val oldSuite = resolver.require(oldIdentity.suiteId)
        if (!oldSuite.signature.verify(provider, oldIdentity.signingPublicKey, message, _signatureByOld)) return false
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
            newKeys: DeviceKeys,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
            resolver: SuiteResolver = SuiteRegistry,
        ): KeyTransition {
            val message = transitionMessage(oldKeys.identity, newKeys.identity, namespace)
            return KeyTransition(
                oldIdentity = oldKeys.identity,
                newIdentity = newKeys.identity,
                signatureByOld = resolver.require(oldKeys.identity.suiteId).signature
                    .sign(provider, oldKeys.signingPrivateKey, message),
                signatureByNew = resolver.require(newKeys.identity.suiteId).signature
                    .sign(provider, newKeys.signingPrivateKey, message),
            )
        }

        /**
         * Strict: version gate first, both identities through the fail-closed self-describing
         * decoder (unknown suites die there), signatures at their per-suite sizes, full
         * consumption. Every failure is an [IllegalArgumentException].
         */
        fun deserialise(bytes: ByteArray, resolver: SuiteResolver = SuiteRegistry): KeyTransition {
            val reader = FrameReader(bytes)
            val version = reader.readBytes(VERSION_BYTES)
            require(version.size == VERSION_BYTES && version[0].toInt() == FORMAT_VERSION) {
                "Unsupported key-transition format version"
            }
            val oldIdentity = DeviceIdentity.deserialise(reader.readBytes(DeviceIdentity.MAX_SERIALISED_BYTES), resolver)
            val newIdentity = DeviceIdentity.deserialise(reader.readBytes(DeviceIdentity.MAX_SERIALISED_BYTES), resolver)
            val oldSuite = resolver.require(oldIdentity.suiteId)
            val newSuite = resolver.require(newIdentity.suiteId)
            val signatureByOld = reader.readBytes(oldSuite.signature.signatureSize)
            require(signatureByOld.size == oldSuite.signature.signatureSize) { "Old-identity signature has wrong size" }
            val signatureByNew = reader.readBytes(newSuite.signature.signatureSize)
            require(signatureByNew.size == newSuite.signature.signatureSize) { "New-identity signature has wrong size" }
            reader.expectEnd()
            return KeyTransition(oldIdentity, newIdentity, signatureByOld, signatureByNew)
        }

        internal fun transitionMessage(
            oldIdentity: DeviceIdentity,
            newIdentity: DeviceIdentity,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): ByteArray = FrameWriter()
            .putBytes(namespace.label(ProtocolLabels.KEY_TRANSITION))
            .putBytes(oldIdentity.serialise())
            .putBytes(newIdentity.serialise())
            .toByteArray()
    }
}
