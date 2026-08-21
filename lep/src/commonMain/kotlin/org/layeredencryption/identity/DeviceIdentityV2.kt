package org.layeredencryption.identity

import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.suite.ProtocolSuite
import org.layeredencryption.suite.SuiteId
import org.layeredencryption.suite.SuiteRegistry
import org.layeredencryption.suite.SuiteResolver

/**
 * The versioned device identity (the migration brief §2): the same three long-term keys as
 * [DeviceIdentity], now carrying a format version and the suite they belong to, with every field
 * sized by that suite:
 *
 * ```
 * DeviceIdentityV2 = framed( formatVersion(1)=0x02 ‖ suiteId(2 BE)
 *                            ‖ signing_pk ‖ x25519_ik_pk(32) ‖ kem_pk ‖ bindingSig )
 * bindingSig       = suite signing over framed("<vendor>/v4/device-identity"
 *                                              ‖ formatVersion ‖ suiteId
 *                                              ‖ signing_pk ‖ x25519_ik_pk ‖ kem_pk)
 * ```
 *
 * The binding signature verifies under the identity's **own** suite — an identity is an artifact
 * of the suite that minted it, which is exactly why v1 identities (no version, no suite field)
 * stay Suite 1 artifacts forever and their decoder is kept indefinitely. The binding message
 * covers the version and suite id as well as the complete key set, so none of them can be
 * spliced (see [DeviceIdentity]'s class doc for why the signing key itself must be covered).
 *
 * A v2 identity under Suite 1 is legal and useful: it is the self-describing form of an
 * unchanged construction, and [DeviceKeysV2.rebind] mints one from existing v1 key material.
 */
class DeviceIdentityV2(
    val suiteId: SuiteId,
    signingPublicKey: ByteArray,
    x25519IdentityPublicKey: ByteArray,
    xWingPublicKey: ByteArray,
    bindingSignature: ByteArray,
) {
    // Copied on construction and on every read, like every verified artifact in this module.
    private val _signingPublicKey = signingPublicKey.copyOf()
    private val _x25519IdentityPublicKey = x25519IdentityPublicKey.copyOf()
    private val _xWingPublicKey = xWingPublicKey.copyOf()
    private val _bindingSignature = bindingSignature.copyOf()

    val signingPublicKey: ByteArray get() = _signingPublicKey.copyOf()
    val x25519IdentityPublicKey: ByteArray get() = _x25519IdentityPublicKey.copyOf()
    val xWingPublicKey: ByteArray get() = _xWingPublicKey.copyOf()
    val bindingSignature: ByteArray get() = _bindingSignature.copyOf()

    fun serialise(): ByteArray = FrameWriter()
        .putBytes(byteArrayOf(FORMAT_VERSION.toByte()))
        .putBytes(suiteId.toWireBytes())
        .putBytes(_signingPublicKey)
        .putBytes(_x25519IdentityPublicKey)
        .putBytes(_xWingPublicKey)
        .putBytes(_bindingSignature)
        .toByteArray()

    /** Verifies the binding under the identity's own suite, both signature legs required. */
    fun verifyBinding(
        provider: CryptoProvider,
        namespace: ProtocolNamespace = ProtocolNamespace.Default,
        resolver: SuiteResolver = SuiteRegistry,
    ): Boolean = resolver.require(suiteId).signature.verify(
        provider,
        _signingPublicKey,
        bindingMessage(suiteId, _signingPublicKey, _x25519IdentityPublicKey, _xWingPublicKey, namespace),
        _bindingSignature,
    )

    companion object {
        const val FORMAT_VERSION = 2

        private const val VERSION_BYTES = 1
        private const val SUITE_ID_BYTES = 2
        private const val X25519_KEY_SIZE = 32
        private const val LENGTH_PREFIX = 4

        /** The one legal serialised size for an identity of [suite] — every field is fixed-width. */
        fun serialisedSize(suite: ProtocolSuite): Int =
            LENGTH_PREFIX + VERSION_BYTES +
                LENGTH_PREFIX + SUITE_ID_BYTES +
                LENGTH_PREFIX + suite.signature.publicKeySize +
                LENGTH_PREFIX + X25519_KEY_SIZE +
                LENGTH_PREFIX + suite.kem.publicKeySize +
                LENGTH_PREFIX + suite.signature.signatureSize

        /**
         * Strict: version gate first, then the suite must resolve (an identity under a suite
         * this build does not know is unreadable by design, never guessed at), then every field
         * at its exact per-suite size, then full consumption. Every failure is an
         * [IllegalArgumentException].
         */
        fun deserialise(bytes: ByteArray, resolver: SuiteResolver = SuiteRegistry): DeviceIdentityV2 {
            val reader = FrameReader(bytes)
            val version = reader.readBytes(VERSION_BYTES)
            require(version.size == VERSION_BYTES && version[0].toInt() == FORMAT_VERSION) {
                "Unsupported identity format version"
            }
            val suiteBytes = reader.readBytes(SUITE_ID_BYTES)
            require(suiteBytes.size == SUITE_ID_BYTES) { "Suite id must be $SUITE_ID_BYTES bytes" }
            val suiteId = SuiteId((((suiteBytes[0].toInt() and 0xFF) shl 8) or (suiteBytes[1].toInt() and 0xFF)).toUShort())
            require(resolver.contains(suiteId)) { "Unknown suite ${suiteId.value}" }
            val suite = resolver.require(suiteId)
            require(bytes.size == serialisedSize(suite)) {
                "A suite-${suiteId.value} identity is exactly ${serialisedSize(suite)} bytes, was ${bytes.size}"
            }
            val signingPublicKey = reader.readBytes(suite.signature.publicKeySize)
            require(signingPublicKey.size == suite.signature.publicKeySize) { "Signing key has wrong size" }
            val x25519IdentityPublicKey = reader.readBytes(X25519_KEY_SIZE)
            require(x25519IdentityPublicKey.size == X25519_KEY_SIZE) { "X25519 identity key has wrong size" }
            val xWingPublicKey = reader.readBytes(suite.kem.publicKeySize)
            require(xWingPublicKey.size == suite.kem.publicKeySize) { "KEM key has wrong size" }
            val bindingSignature = reader.readBytes(suite.signature.signatureSize)
            require(bindingSignature.size == suite.signature.signatureSize) { "Binding signature has wrong size" }
            reader.expectEnd()
            return DeviceIdentityV2(suiteId, signingPublicKey, x25519IdentityPublicKey, xWingPublicKey, bindingSignature)
        }

        internal fun bindingMessage(
            suiteId: SuiteId,
            signingPublicKey: ByteArray,
            x25519IdentityPublicKey: ByteArray,
            xWingPublicKey: ByteArray,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): ByteArray = FrameWriter()
            .putBytes(namespace.label(ProtocolLabels.DEVICE_IDENTITY_SUITED))
            .putBytes(byteArrayOf(FORMAT_VERSION.toByte()))
            .putBytes(suiteId.toWireBytes())
            .putBytes(signingPublicKey)
            .putBytes(x25519IdentityPublicKey)
            .putBytes(xWingPublicKey)
            .toByteArray()
    }
}

/**
 * A device's full v2 identity: the public [DeviceIdentityV2] plus the private halves. Never
 * serialised, mirroring [DeviceKeys]'s custody rules (copies both ways, [destroy] scrubs).
 */
class DeviceKeysV2(
    val identity: DeviceIdentityV2,
    signingPrivateKey: ByteArray,
    x25519IdentityPrivateKey: ByteArray,
    xWingPrivateKey: ByteArray,
) {
    private val _signingPrivateKey = signingPrivateKey.copyOf()
    private val _x25519IdentityPrivateKey = x25519IdentityPrivateKey.copyOf()
    private val _xWingPrivateKey = xWingPrivateKey.copyOf()

    private var destroyed = false

    val signingPrivateKey: ByteArray get() = guarded(_signingPrivateKey)
    val x25519IdentityPrivateKey: ByteArray get() = guarded(_x25519IdentityPrivateKey)
    val xWingPrivateKey: ByteArray get() = guarded(_xWingPrivateKey)

    /** Zeroes the private keys; later private-key reads throw. Idempotent, best-effort. */
    fun destroy() {
        destroyed = true
        _signingPrivateKey.fill(0)
        _x25519IdentityPrivateKey.fill(0)
        _xWingPrivateKey.fill(0)
    }

    private fun guarded(key: ByteArray): ByteArray {
        check(!destroyed) { "DeviceKeysV2 has been destroyed" }
        return key.copyOf()
    }

    companion object {
        /** Fresh suite-appropriate keys, bound under [suite] at generation. */
        fun generate(
            provider: CryptoProvider,
            suite: ProtocolSuite,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): DeviceKeysV2 {
            val signing = suite.signature.generateKeyPair(provider)
            val identityDh = provider.x25519GenerateKeyPair()
            val kem = suite.kem.generateKeyPair(provider)
            val bindingSignature = suite.signature.sign(
                provider,
                signing.privateKey,
                DeviceIdentityV2.bindingMessage(suite.id, signing.publicKey, identityDh.publicKey, kem.publicKey, namespace),
            )
            return DeviceKeysV2(
                identity = DeviceIdentityV2(suite.id, signing.publicKey, identityDh.publicKey, kem.publicKey, bindingSignature),
                signingPrivateKey = signing.privateKey,
                x25519IdentityPrivateKey = identityDh.privateKey,
                xWingPrivateKey = kem.privateKey,
            )
        }

        /**
         * The same key material as [keys], re-bound in v2 form under [suite]. Legal only for a
         * suite whose key shapes match Suite 1's (the keys *are* Suite 1 keys); moving to a
         * differently-shaped suite means fresh keys via [generate] plus a
         * [KeyTransition] for continuity.
         */
        fun rebind(
            provider: CryptoProvider,
            keys: DeviceKeys,
            suite: ProtocolSuite,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): DeviceKeysV2 {
            val identity = keys.identity
            require(
                identity.signingPublicKey.size == suite.signature.publicKeySize &&
                    identity.xWingPublicKey.size == suite.kem.publicKeySize,
            ) { "Suite ${suite.id.value} key shapes differ from this device's keys — generate fresh keys instead" }
            val bindingSignature = suite.signature.sign(
                provider,
                keys.signingPrivateKey,
                DeviceIdentityV2.bindingMessage(
                    suite.id, identity.signingPublicKey, identity.x25519IdentityPublicKey, identity.xWingPublicKey, namespace,
                ),
            )
            return DeviceKeysV2(
                identity = DeviceIdentityV2(
                    suite.id, identity.signingPublicKey, identity.x25519IdentityPublicKey,
                    identity.xWingPublicKey, bindingSignature,
                ),
                signingPrivateKey = keys.signingPrivateKey,
                x25519IdentityPrivateKey = keys.x25519IdentityPrivateKey,
                xWingPrivateKey = keys.xWingPrivateKey,
            )
        }
    }
}
