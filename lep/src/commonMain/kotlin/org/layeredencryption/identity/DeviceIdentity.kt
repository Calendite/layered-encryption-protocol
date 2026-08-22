package org.layeredencryption.identity

import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.CryptoProvider
import org.layeredencryption.KeyPair
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.suite.ProtocolSuite
import org.layeredencryption.suite.Suite1
import org.layeredencryption.suite.SuiteId
import org.layeredencryption.suite.SuiteRegistry
import org.layeredencryption.suite.SuiteResolver

/**
 * A device's long-term identity (Async_Invites_Spec.md §3) — self-describing since the
 * pre-release format consolidation: the wire form names its own format version and the
 * cryptographic suite that minted it, and every field is sized by that suite.
 *
 * Every device carries **three** long-term keypairs: a signing key (membership-log signatures,
 * LAN challenges), an X25519 identity key (`ik`) used for the async invite's `dh1` identity
 * binding, and a KEM key that others encapsulate to when they need to hand this device a secret.
 * All are bound to the signing key at generation by one binding signature, so the parts cannot
 * be mixed and matched:
 *
 * ```
 * DeviceIdentity = framed( formatVersion(1)=0x02 ‖ suiteId(2 BE)
 *                          ‖ signing_pk ‖ x25519_ik_pk(32) ‖ kem_pk ‖ bindingSig )
 * bindingSig     = suite signing over framed("<vendor>/v4/device-identity"
 *                                            ‖ formatVersion ‖ suiteId
 *                                            ‖ signing_pk ‖ x25519_ik_pk ‖ kem_pk)
 * ```
 *
 * ### Why the binding message covers the signing key itself
 * The obvious version signs only `x25519_ik_pk`, and that is exactly where a hybrid identity fails
 * quietly. Picture an attacker who has broken Ed25519 but not ML-DSA. If the binding message omits
 * the signing key, they take an honest device's identity, splice in an ML-DSA public key of their
 * own, forge the classical leg of the binding signature, and produce the post-quantum leg
 * legitimately — because the substituted key is theirs. The tampered identity verifies, and the
 * post-quantum leg has protected nothing at all. Signing the complete key set closes it; the
 * format version and suite id are covered too, so none of them can be spliced either.
 *
 * ### Why the suite id is first-class
 * An identity is an artifact of the suite that minted it: [verifyBinding] verifies under the
 * identity's **own** suite, whatever era the carrying context is in. Adopting a new suite means
 * fresh suite-appropriate keys plus a [KeyTransition] for continuity — never a reinterpretation
 * of old bytes.
 *
 * This is *the* device certificate everywhere — pairing transcripts, membership entries
 * (genesis included), and async bundles — so all of them carry the same authenticated bytes.
 * The private halves live in [DeviceKeys]; only the public identity is ever serialised.
 */
class DeviceIdentity(
    val suiteId: SuiteId,
    signingPublicKey: ByteArray,
    x25519IdentityPublicKey: ByteArray,
    xWingPublicKey: ByteArray,
    bindingSignature: ByteArray,
) {
    // Copied on construction and on every read: an identity that has been verified cannot be
    // mutated afterwards, by the code that built it or the code that read it (LEP-09 retest 9.3).
    private val _signingPublicKey = signingPublicKey.copyOf()
    private val _x25519IdentityPublicKey = x25519IdentityPublicKey.copyOf()
    private val _xWingPublicKey = xWingPublicKey.copyOf()
    private val _bindingSignature = bindingSignature.copyOf()

    val signingPublicKey: ByteArray get() = _signingPublicKey.copyOf()
    val x25519IdentityPublicKey: ByteArray get() = _x25519IdentityPublicKey.copyOf()

    /** Others encapsulate to this to hand this device a secret, such as a rotated context key. */
    val xWingPublicKey: ByteArray get() = _xWingPublicKey.copyOf()
    val bindingSignature: ByteArray get() = _bindingSignature.copyOf()

    /** Canonical, length-framed serialisation — the exact bytes that appear on the wire and in logs. */
    fun serialise(): ByteArray = FrameWriter()
        .putBytes(byteArrayOf(FORMAT_VERSION.toByte()))
        .putBytes(suiteId.toWireBytes())
        .putBytes(_signingPublicKey)
        .putBytes(_x25519IdentityPublicKey)
        .putBytes(_xWingPublicKey)
        .putBytes(_bindingSignature)
        .toByteArray()

    /** Verifies the binding under the identity's own suite, requiring every signature leg to pass. */
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

        private const val BINDING_SUFFIX = ProtocolLabels.DEVICE_IDENTITY_SUITED
        private const val VERSION_BYTES = 1
        private const val SUITE_ID_BYTES = 2
        private const val X25519_KEY_SIZE = 32
        private const val LENGTH_PREFIX = 4

        /**
         * A generous carrier bound for one serialised identity blob: real sizes are a few
         * kilobytes per suite, and a variable-size field needs *some* pre-parse budget.
         */
        const val MAX_SERIALISED_BYTES = 64 * 1024

        /** The one legal serialised size for an identity of [suite] — every field is fixed-width. */
        fun serialisedSize(suite: ProtocolSuite): Int =
            LENGTH_PREFIX + VERSION_BYTES +
                LENGTH_PREFIX + SUITE_ID_BYTES +
                LENGTH_PREFIX + suite.signature.publicKeySize +
                LENGTH_PREFIX + X25519_KEY_SIZE +
                LENGTH_PREFIX + suite.kem.publicKeySize +
                LENGTH_PREFIX + suite.signature.signatureSize

        /**
         * Strict: the format version is gated first, then the suite must resolve (an identity
         * under a suite this build does not know is unreadable by design, never guessed at),
         * then every field at its exact per-suite size, then full consumption. Every failure is
         * an [IllegalArgumentException].
         */
        fun deserialise(bytes: ByteArray, resolver: SuiteResolver = SuiteRegistry): DeviceIdentity {
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
            return DeviceIdentity(suiteId, signingPublicKey, x25519IdentityPublicKey, xWingPublicKey, bindingSignature)
        }

        internal fun bindingMessage(
            suiteId: SuiteId,
            signingPublicKey: ByteArray,
            x25519IdentityPublicKey: ByteArray,
            xWingPublicKey: ByteArray,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): ByteArray = FrameWriter()
            .putBytes(namespace.label(BINDING_SUFFIX))
            .putBytes(byteArrayOf(FORMAT_VERSION.toByte()))
            .putBytes(suiteId.toWireBytes())
            .putBytes(signingPublicKey)
            .putBytes(x25519IdentityPublicKey)
            .putBytes(xWingPublicKey)
            .toByteArray()
    }
}

/**
 * A device's full identity — the public [DeviceIdentity] plus the private key halves needed to
 * sign and to run `dh1` (X25519). Never serialised; the private material stays on the device
 * (hardware-wrapped at rest per design §4.6, deferred).
 */
class DeviceKeys(
    val identity: DeviceIdentity,
    signingPrivateKey: ByteArray,
    x25519IdentityPrivateKey: ByteArray,
    xWingPrivateKey: ByteArray,
) {
    // Copied both ways, like the identity: callers get snapshots, never the live key arrays.
    private val _signingPrivateKey = signingPrivateKey.copyOf()
    private val _x25519IdentityPrivateKey = x25519IdentityPrivateKey.copyOf()
    private val _xWingPrivateKey = xWingPrivateKey.copyOf()

    private var destroyed = false

    val signingPrivateKey: ByteArray get() = guarded(_signingPrivateKey)
    val x25519IdentityPrivateKey: ByteArray get() = guarded(_x25519IdentityPrivateKey)

    /** Opens what others encapsulate to [DeviceIdentity.xWingPublicKey]. */
    val xWingPrivateKey: ByteArray get() = guarded(_xWingPrivateKey)

    /** The signing keypair, in the [KeyPair] shape the membership log expects. */
    val signingKeyPair: KeyPair get() = KeyPair(identity.signingPublicKey, guarded(_signingPrivateKey))

    /**
     * Zeroes the private keys and makes every later private-key read throw
     * [IllegalStateException] — explicit end-of-life for the one long-lived secret holder a
     * device keeps. Idempotent. The public [identity] stays readable; snapshots already handed
     * out, and transient provider buffers on a garbage-collected runtime, are necessarily beyond
     * this object's reach — best-effort, as all in-memory scrubbing is.
     */
    fun destroy() {
        destroyed = true
        _signingPrivateKey.fill(0)
        _x25519IdentityPrivateKey.fill(0)
        _xWingPrivateKey.fill(0)
    }

    private fun guarded(key: ByteArray): ByteArray {
        check(!destroyed) { "DeviceKeys has been destroyed" }
        return key.copyOf()
    }

    companion object {
        /**
         * Generates a fresh device identity under [suite]: suite-appropriate signing and KEM
         * keypairs plus the X25519 identity key, bound by one signature at generation.
         *
         * The binding signature is domain-separated by [namespace] (LEP-10): an identity generated
         * for one application does not verify under another's namespace, so identities cannot be
         * silently reused across deployments. Pass the same namespace everywhere — generation,
         * pairing, membership, invites — or verification will (correctly) fail.
         */
        fun generate(
            provider: CryptoProvider,
            suite: ProtocolSuite = Suite1,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): DeviceKeys {
            val signing = suite.signature.generateKeyPair(provider)
            val identityDh = provider.x25519GenerateKeyPair()
            val kem = suite.kem.generateKeyPair(provider)
            val bindingSignature = suite.signature.sign(
                provider,
                signing.privateKey,
                DeviceIdentity.bindingMessage(suite.id, signing.publicKey, identityDh.publicKey, kem.publicKey, namespace),
            )
            return DeviceKeys(
                identity = DeviceIdentity(
                    suiteId = suite.id,
                    signingPublicKey = signing.publicKey,
                    x25519IdentityPublicKey = identityDh.publicKey,
                    xWingPublicKey = kem.publicKey,
                    bindingSignature = bindingSignature,
                ),
                signingPrivateKey = signing.privateKey,
                x25519IdentityPrivateKey = identityDh.privateKey,
                xWingPrivateKey = kem.privateKey,
            )
        }
    }
}
