package org.layeredencryption.identity

import org.layeredencryption.ProtocolLabels
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.CryptoProvider
import org.layeredencryption.HybridSignature
import org.layeredencryption.KeyPair
import org.layeredencryption.XWing
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter

/**
 * A device's long-term identity (Async_Invites_Spec.md §3).
 *
 * Every device carries **three** long-term keypairs: a [HybridSignature] signing key (membership-log
 * signatures, LAN challenges), an X25519 identity key (`ik`) used for the async invite's `dh1`
 * identity binding, and an [XWing] key that others encapsulate to when they need to hand this
 * device a secret. All are bound to the signing key at generation by one binding signature, so the
 * parts cannot be mixed and matched:
 *
 * ```
 * DeviceIdentity = framed( signing_pk(1984) ‖ x25519_ik_pk(32) ‖ xwing_pk(1216) ‖ bindingSig(3373) )
 * bindingSig     = Hybrid_signing over framed("<vendor>/v3/device-identity"
 *                                             ‖ signing_pk ‖ x25519_ik_pk ‖ xwing_pk)
 * ```
 *
 * ### Why the binding message covers the signing key itself
 * The obvious version signs only `x25519_ik_pk`, and that is exactly where a hybrid identity fails
 * quietly. Picture an attacker who has broken Ed25519 but not ML-DSA. If the binding message omits
 * the signing key, they take an honest device's identity, splice in an ML-DSA public key of their
 * own, forge the classical leg of the binding signature, and produce the post-quantum leg
 * legitimately — because the substituted key is theirs. The tampered identity verifies, and the
 * post-quantum leg has protected nothing at all. Signing the complete key set closes it: the
 * binding attests that this exact `(signing_pk, x25519_ik_pk)` pair belongs together, so altering
 * either one invalidates it.
 *
 * ### Why an X-Wing key lives here
 * Rotating the context key requires handing the new one to every remaining member, and once pairing
 * is over there is no shared per-pair key left to wrap it with. A long-term KEM key in the identity
 * is what makes that possible, and making it hybrid is what stops a recorded rotation being the one
 * classical hole left in the protocol.
 *
 * This is *the* device certificate everywhere — live handshake transcripts, membership entries
 * (genesis included), and async bundles — so all of them carry the same authenticated bytes.
 *
 * The private halves live in [DeviceKeys]; only the public [DeviceIdentity] is ever serialised onto
 * the wire or into the log.
 */
class DeviceIdentity(
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
        .putBytes(_signingPublicKey)
        .putBytes(_x25519IdentityPublicKey)
        .putBytes(_xWingPublicKey)
        .putBytes(_bindingSignature)
        .toByteArray()

    /** Verifies the X25519↔signing-key binding, requiring both signature legs to pass. */
    fun verifyBinding(provider: CryptoProvider, namespace: ProtocolNamespace = ProtocolNamespace.Default): Boolean =
        HybridSignature.verify(
            provider,
            _signingPublicKey,
            bindingMessage(_signingPublicKey, _x25519IdentityPublicKey, _xWingPublicKey, namespace),
            _bindingSignature,
        )

    companion object {
        private const val BINDING_SUFFIX = ProtocolLabels.DEVICE_IDENTITY

        private const val X25519_KEY_SIZE = 32
        private const val LENGTH_PREFIX = 4

        /** The one legal serialised size: four length-prefixed fixed-width fields. */
        internal const val SERIALISED_SIZE =
            LENGTH_PREFIX + HybridSignature.PUBLIC_KEY_SIZE +
                LENGTH_PREFIX + X25519_KEY_SIZE +
                LENGTH_PREFIX + XWing.PUBLIC_KEY_SIZE +
                LENGTH_PREFIX + HybridSignature.SIGNATURE_SIZE

        /**
         * Strict: every field has exactly one legal length (the format has no variability at
         * all — see the class doc's byte layout), so the total is checked first, before any
         * copies, and the frame must be fully consumed.
         */
        fun deserialise(bytes: ByteArray): DeviceIdentity {
            require(bytes.size == SERIALISED_SIZE) { "A device identity is exactly $SERIALISED_SIZE bytes, was ${bytes.size}" }
            val reader = FrameReader(bytes)
            val identity = deserialise(reader)
            reader.expectEnd()
            return identity
        }

        internal fun deserialise(reader: FrameReader): DeviceIdentity {
            val signingPublicKey = reader.readBytes(HybridSignature.PUBLIC_KEY_SIZE)
            require(signingPublicKey.size == HybridSignature.PUBLIC_KEY_SIZE) { "Signing key has wrong size" }
            val x25519IdentityPublicKey = reader.readBytes(X25519_KEY_SIZE)
            require(x25519IdentityPublicKey.size == X25519_KEY_SIZE) { "X25519 identity key has wrong size" }
            val xWingPublicKey = reader.readBytes(XWing.PUBLIC_KEY_SIZE)
            require(xWingPublicKey.size == XWing.PUBLIC_KEY_SIZE) { "X-Wing key has wrong size" }
            val bindingSignature = reader.readBytes(HybridSignature.SIGNATURE_SIZE)
            require(bindingSignature.size == HybridSignature.SIGNATURE_SIZE) { "Binding signature has wrong size" }
            return DeviceIdentity(signingPublicKey, x25519IdentityPublicKey, xWingPublicKey, bindingSignature)
        }

        internal fun bindingMessage(
            signingPublicKey: ByteArray,
            x25519IdentityPublicKey: ByteArray,
            xWingPublicKey: ByteArray,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): ByteArray = FrameWriter()
            .putBytes(namespace.label(BINDING_SUFFIX))
            .putBytes(signingPublicKey)
            .putBytes(x25519IdentityPublicKey)
            .putBytes(xWingPublicKey)
            .toByteArray()
    }
}

/**
 * A device's full identity — the public [DeviceIdentity] plus the private key halves needed to sign
 * ([HybridSignature]) and to run `dh1` (X25519). Never serialised; the private material stays on the
 * device (hardware-wrapped at rest per design §4.6, deferred).
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

    /** The hybrid signing keypair, in the [KeyPair] shape the membership log expects. */
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
         * Generates a fresh device identity: hybrid signing + X25519 keypairs bound by a signature.
         *
         * The binding signature is domain-separated by [namespace] (LEP-10): an identity generated
         * for one application does not verify under another's namespace, so identities cannot be
         * silently reused across deployments. Pass the same namespace everywhere — generation,
         * pairing, membership, invites — or verification will (correctly) fail.
         */
        fun generate(
            provider: CryptoProvider,
            namespace: ProtocolNamespace = ProtocolNamespace.Default,
        ): DeviceKeys {
            val signing = HybridSignature.generateKeyPair(provider)
            val identityDh = provider.x25519GenerateKeyPair()
            val kem = XWing.generateKeyPair(provider)
            val bindingSignature = HybridSignature.sign(
                provider,
                signing.privateKey,
                DeviceIdentity.bindingMessage(signing.publicKey, identityDh.publicKey, kem.publicKey, namespace),
            )
            return DeviceKeys(
                identity = DeviceIdentity(
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
