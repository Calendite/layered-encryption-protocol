package org.layeredencryption.identity

import org.layeredencryption.CryptoProvider
import org.layeredencryption.KeyPair
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter

/**
 * A device's long-term identity (Async_Invites_Spec.md §3).
 *
 * Every device carries **two** long-term keypairs: an Ed25519 signing key (membership-log signatures,
 * LAN challenges) and an X25519 identity key (`ik`) used for the async invite's `dh1` identity
 * binding. The X25519 key is bound to the Ed25519 key at generation by a binding signature, so the
 * two cannot be mixed and matched:
 *
 * ```
 * DeviceIdentity = framed( ed25519_pk(32) ‖ x25519_ik_pk(32) ‖ bindingSig(64) )
 * bindingSig     = Ed25519_ed over framed("calendite/v1/device-identity" ‖ x25519_ik_pk)
 * ```
 *
 * This is *the* device certificate everywhere — live handshake transcripts, membership entries
 * (genesis included), and async bundles — so all of them carry the same authenticated bytes.
 *
 * The private halves live in [DeviceKeys]; only the public [DeviceIdentity] is ever serialised onto
 * the wire or into the log.
 */
class DeviceIdentity(
    val ed25519PublicKey: ByteArray,
    val x25519IdentityPublicKey: ByteArray,
    val bindingSignature: ByteArray,
) {
    /** Canonical, length-framed serialisation — the exact bytes that appear on the wire and in logs. */
    fun serialise(): ByteArray = FrameWriter()
        .putBytes(ed25519PublicKey)
        .putBytes(x25519IdentityPublicKey)
        .putBytes(bindingSignature)
        .toByteArray()

    /** Verifies the X25519↔Ed25519 binding signature. */
    fun verifyBinding(provider: CryptoProvider): Boolean =
        provider.ed25519Verify(ed25519PublicKey, bindingMessage(x25519IdentityPublicKey), bindingSignature)

    companion object {
        private val BINDING_LABEL = "calendite/v1/device-identity".encodeToByteArray()

        fun deserialise(bytes: ByteArray): DeviceIdentity = deserialise(FrameReader(bytes))

        internal fun deserialise(reader: FrameReader): DeviceIdentity = DeviceIdentity(
            ed25519PublicKey = reader.readBytes(),
            x25519IdentityPublicKey = reader.readBytes(),
            bindingSignature = reader.readBytes(),
        )

        internal fun bindingMessage(x25519IdentityPublicKey: ByteArray): ByteArray =
            FrameWriter().putBytes(BINDING_LABEL).putBytes(x25519IdentityPublicKey).toByteArray()
    }
}

/**
 * A device's full identity — the public [DeviceIdentity] plus the private key halves needed to sign
 * (Ed25519) and to run `dh1` (X25519). Never serialised; the private material stays on the device
 * (hardware-wrapped at rest per design §4.6, deferred).
 */
class DeviceKeys(
    val identity: DeviceIdentity,
    val ed25519PrivateKey: ByteArray,
    val x25519IdentityPrivateKey: ByteArray,
) {
    /** The Ed25519 signing keypair, in the [KeyPair] shape the membership log expects. */
    val signingKeyPair: KeyPair get() = KeyPair(identity.ed25519PublicKey, ed25519PrivateKey)

    companion object {
        /** Generates a fresh device identity: Ed25519 + X25519 keypairs bound by a signature. */
        fun generate(provider: CryptoProvider): DeviceKeys {
            val signing = provider.ed25519GenerateKeyPair()
            val identityDh = provider.x25519GenerateKeyPair()
            val bindingSignature = provider.ed25519Sign(
                signing.privateKey,
                DeviceIdentity.bindingMessage(identityDh.publicKey),
            )
            return DeviceKeys(
                identity = DeviceIdentity(
                    ed25519PublicKey = signing.publicKey,
                    x25519IdentityPublicKey = identityDh.publicKey,
                    bindingSignature = bindingSignature,
                ),
                ed25519PrivateKey = signing.privateKey,
                x25519IdentityPrivateKey = identityDh.privateKey,
            )
        }
    }
}
