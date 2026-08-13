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
    val signingPublicKey: ByteArray,
    val x25519IdentityPublicKey: ByteArray,
    /** Others encapsulate to this to hand this device a secret, such as a rotated context key. */
    val xWingPublicKey: ByteArray,
    val bindingSignature: ByteArray,
) {
    /** Canonical, length-framed serialisation — the exact bytes that appear on the wire and in logs. */
    fun serialise(): ByteArray = FrameWriter()
        .putBytes(signingPublicKey)
        .putBytes(x25519IdentityPublicKey)
        .putBytes(xWingPublicKey)
        .putBytes(bindingSignature)
        .toByteArray()

    /** Verifies the X25519↔signing-key binding, requiring both signature legs to pass. */
    fun verifyBinding(provider: CryptoProvider, namespace: ProtocolNamespace = ProtocolNamespace.Default): Boolean =
        HybridSignature.verify(
            provider,
            signingPublicKey,
            bindingMessage(signingPublicKey, x25519IdentityPublicKey, xWingPublicKey, namespace),
            bindingSignature,
        )

    companion object {
        private const val BINDING_SUFFIX = ProtocolLabels.DEVICE_IDENTITY

        fun deserialise(bytes: ByteArray): DeviceIdentity = deserialise(FrameReader(bytes))

        internal fun deserialise(reader: FrameReader): DeviceIdentity = DeviceIdentity(
            signingPublicKey = reader.readBytes(),
            x25519IdentityPublicKey = reader.readBytes(),
            xWingPublicKey = reader.readBytes(),
            bindingSignature = reader.readBytes(),
        )

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
    val signingPrivateKey: ByteArray,
    val x25519IdentityPrivateKey: ByteArray,
    /** Opens what others encapsulate to [DeviceIdentity.xWingPublicKey]. */
    val xWingPrivateKey: ByteArray,
) {
    /** The hybrid signing keypair, in the [KeyPair] shape the membership log expects. */
    val signingKeyPair: KeyPair get() = KeyPair(identity.signingPublicKey, signingPrivateKey)

    companion object {
        /** Generates a fresh device identity: hybrid signing + X25519 keypairs bound by a signature. */
        fun generate(provider: CryptoProvider): DeviceKeys {
            val signing = HybridSignature.generateKeyPair(provider)
            val identityDh = provider.x25519GenerateKeyPair()
            val kem = XWing.generateKeyPair(provider)
            val bindingSignature = HybridSignature.sign(
                provider,
                signing.privateKey,
                DeviceIdentity.bindingMessage(signing.publicKey, identityDh.publicKey, kem.publicKey),
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
