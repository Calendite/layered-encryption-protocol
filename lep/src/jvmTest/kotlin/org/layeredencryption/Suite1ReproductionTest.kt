package org.layeredencryption

import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.invite.AsyncRendezvous
import org.layeredencryption.invite.InviteBundle
import org.layeredencryption.invite.InviteLink
import org.layeredencryption.membership.MembershipLog
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * The deterministic half of the Suite 1 freeze (docs/POST_QUANTUM_HARDENING_AND_MIGRATION.md §1:
 * "where deterministic inputs are used, reproduces the same bytes"): every operation that is a
 * pure function of the fixture keys must still produce the committed bytes. Ed25519 signing is
 * deterministic by RFC 8032 and Bouncy Castle's ML-DSA-65 signer runs deterministically when no
 * explicit randomness is supplied, so a re-signed hybrid signature must match byte for byte —
 * which pins the signed payloads (labels, framing, field order) as a side effect.
 *
 * jvmTest rather than commonTest deliberately: reproduction is a property of the shipped signer
 * configuration, and the JVM provider is the reference implementation the fixtures were cut from.
 */
class Suite1ReproductionTest {

    private val provider = BouncyCastleCryptoProvider()

    @Test
    fun bindingSignature_reproducesByteExactly() {
        val identity = DeviceIdentity.deserialise(Suite1Fixtures.founderIdentity())
        val resigned = HybridSignature.sign(
            provider,
            Suite1Fixtures.founderSigningPrivateKey(),
            DeviceIdentity.bindingMessage(
                identity.suiteId, identity.signingPublicKey, identity.x25519IdentityPublicKey, identity.xWingPublicKey,
            ),
        )
        assertContentEquals(identity.bindingSignature, resigned)
    }

    @Test
    fun membershipEntrySignatures_reproduceByteExactly() {
        val log = MembershipLog.deserialise(Suite1Fixtures.membershipLog())
        // Every fixture entry is founder-signed; re-signing pins the unsignedBytes construction
        // (membership label, previous hash, op code, identity, wrapped keys, signer) end to end.
        log.entries.forEachIndexed { index, entry ->
            val resigned = HybridSignature.sign(
                provider, Suite1Fixtures.founderSigningPrivateKey(), entry.unsignedBytes(),
            )
            assertContentEquals(entry.signature, resigned, "entry $index signature")
        }
    }

    @Test
    fun inviteBundle_rebuildsByteExactly() {
        val rebuilt = InviteBundle.build(
            provider,
            inviteXWingPublicKey = Suite1Fixtures.inviteKemPublicKey(),
            deviceIdentityA = DeviceIdentity.deserialise(Suite1Fixtures.founderIdentity()),
            expiryEpochSeconds = Suite1Fixtures.inviteExpiryEpochSeconds,
            ridAsync = Suite1Fixtures.inviteRidAsync(),
            signer = KeyPair(
                DeviceIdentity.deserialise(Suite1Fixtures.founderIdentity()).signingPublicKey,
                Suite1Fixtures.founderSigningPrivateKey(),
            ),
        )
        assertContentEquals(Suite1Fixtures.inviteBundle(), rebuilt.serialise())
    }

    @Test
    fun inviteLinkAndRendezvous_rebuildByteExactly() {
        val link = InviteLink.create(
            provider, Suite1Fixtures.inviteSecret(), DeviceIdentity.deserialise(Suite1Fixtures.founderIdentity()),
        )
        assertEquals(Suite1Fixtures.inviteLinkUrl, link.url())
        assertContentEquals(Suite1Fixtures.inviteRidAsync(), AsyncRendezvous.id(provider, Suite1Fixtures.inviteSecret()))
    }

    @Test
    fun xwingComponents_splitAtTheFrozenOffsets() {
        val publicKey = Suite1Fixtures.inviteKemPublicKey()
        assertContentEquals(
            publicKey.copyOfRange(1184, 1216),
            XWing.x25519PublicComponent(publicKey),
            "the X25519 component is the trailing 32 bytes",
        )
        // The seed expansion must still land on the same X25519 scalar: its public key is the
        // public component of the fixture key pair generated from that seed.
        assertContentEquals(
            XWing.x25519PublicComponent(publicKey),
            provider.x25519PublicKey(XWing.x25519SecretComponent(provider, Suite1Fixtures.inviteKemPrivateKey())),
        )
    }
}
