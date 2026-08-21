package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.invite.InviteBundle
import org.layeredencryption.invite.InviteLink
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.membership.WrappedKeys
import org.layeredencryption.pairing.PairingWire
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The Suite 1 freeze, enforced (docs/POST_QUANTUM_HARDENING_AND_MIGRATION.md §1): every committed
 * [Suite1Fixtures] artifact must still parse, verify, decrypt, and re-serialise **byte for byte**
 * under the current implementation. These fixtures were produced by the shipped protocol before
 * any suite abstraction existed, so a red test here means the refactor changed protocol bytes —
 * which Phase 0 explicitly must not.
 *
 * Runs in commonTest so every platform provider (BouncyCastle on JVM/Android, Noble on wasmJs)
 * independently verifies the same frozen bytes; cryptographic assertions self-skip on a platform
 * without a provider (the [XWingKatTest] pattern), pure parse/re-encode assertions run everywhere.
 */
class Suite1CompatTest {

    private val provider: CryptoProvider? = runCatching { platformCryptoProvider() }.getOrNull()

    private fun founderKeys() = DeviceKeys(
        identity = DeviceIdentity.deserialise(Suite1Fixtures.founderIdentity()),
        signingPrivateKey = Suite1Fixtures.founderSigningPrivateKey(),
        x25519IdentityPrivateKey = Suite1Fixtures.founderX25519PrivateKey(),
        xWingPrivateKey = Suite1Fixtures.founderXWingPrivateKey(),
    )

    private fun memberKeys() = DeviceKeys(
        identity = DeviceIdentity.deserialise(Suite1Fixtures.memberIdentity()),
        signingPrivateKey = Suite1Fixtures.memberSigningPrivateKey(),
        x25519IdentityPrivateKey = Suite1Fixtures.memberX25519PrivateKey(),
        xWingPrivateKey = Suite1Fixtures.memberXWingPrivateKey(),
    )

    // ── Frozen constants ──────────────────────────────────────────────────────────────────────

    @Test
    fun suite1SizesAreFrozen() {
        assertEquals(32, XWing.SECRET_KEY_SIZE)
        assertEquals(1120, XWing.CIPHERTEXT_SIZE)
        assertEquals(1216, XWing.PUBLIC_KEY_SIZE)
        assertEquals(1984, HybridSignature.PUBLIC_KEY_SIZE)
        assertEquals(3373, HybridSignature.SIGNATURE_SIZE)
        assertEquals(6621, DeviceIdentity.SERIALISED_SIZE)
        assertEquals(11234, InviteBundle.SERIALISED_SIZE)
        assertEquals(2, LaneEnvelope.VERSION)
        assertEquals(1, PairingWire.TAG_INVITER_HELLO)
        assertEquals(2, PairingWire.TAG_JOINER_RESPONSE)
        assertEquals(3, PairingWire.TAG_INVITER_CONFIRM)
        assertEquals(4, PairingWire.TAG_SAS_CONFIRMED)
        assertEquals(5, PairingWire.TAG_INVITER_COMPLETE)
    }

    @Test
    fun protocolLabelsAreFrozen() {
        // The jvmTest freeze test already pins these; repeating the full set here guards the
        // platforms that only run commonTest (wasmJs, Android unit) too.
        assertEquals(
            setOf(
                "v1/layer-chacha", "v1/layer-aes", "v1/transcript", "v1/pairing", "v1/code-secret",
                "v2/sas-commitment", "v3/device-identity", "v1/member-key-wrap", "v2/membership",
                "v2/invite-bundle", "v1/transcript-async", "v1/pairing-async", "v1/async-link-auth",
                "rendezvous/v1", "rendezvous-async/v1", "context-id/v2",
            ),
            ProtocolLabels.ALL,
        )
    }

    // ── Device identity ───────────────────────────────────────────────────────────────────────

    @Test
    fun deviceIdentity_parsesVerifiesAndReserialisesByteExactly() {
        for (bytes in listOf(Suite1Fixtures.founderIdentity(), Suite1Fixtures.memberIdentity())) {
            assertEquals(DeviceIdentity.SERIALISED_SIZE, bytes.size)
            val identity = DeviceIdentity.deserialise(bytes)
            assertContentEquals(bytes, identity.serialise(), "identity must re-serialise byte-exactly")
            provider?.let { assertTrue(identity.verifyBinding(it), "binding signature must verify") }
        }
    }

    // ── Membership log ────────────────────────────────────────────────────────────────────────

    @Test
    fun membershipLog_parsesVerifiesAndReserialisesByteExactly() {
        val bytes = Suite1Fixtures.membershipLog()
        val log = MembershipLog.deserialise(bytes)
        assertContentEquals(bytes, log.serialise(), "log must re-serialise byte-exactly")

        assertEquals(
            listOf(MembershipOp.ADD, MembershipOp.ADD, MembershipOp.ROTATE, MembershipOp.REVOKE),
            log.entries.map { it.op },
        )
        val provider = provider ?: return
        val verification = log.verify(provider)
        assertIs<MembershipVerification.Valid>(verification, "the frozen chain must verify")
        assertEquals(
            setOf(founderKeys().identity.signingPublicKey.toHexString()),
            verification.activeMembers,
            "after REVOKE(member) only the founder remains",
        )
        val expectedHashes = listOf(
            Suite1Fixtures.membershipEntryHash0(), Suite1Fixtures.membershipEntryHash1(),
            Suite1Fixtures.membershipEntryHash2(), Suite1Fixtures.membershipEntryHash3(),
        )
        log.entries.forEachIndexed { index, entry ->
            assertContentEquals(expectedHashes[index], entry.hash(provider), "entry $index hash")
        }
    }

    @Test
    fun membershipLog_rotationKeysUnwrapForTheRightDevices() {
        val provider = provider ?: return
        val log = MembershipLog.deserialise(Suite1Fixtures.membershipLog())

        // The founder survives both rotations; the member was excluded by the REVOKE.
        val founderRotations = log.rotatedKeysFor(provider, founderKeys())
        assertEquals(2, founderRotations.size)
        assertContentEquals(Suite1Fixtures.membershipRotateKey(), founderRotations[0])
        assertContentEquals(Suite1Fixtures.membershipRevokeKey(), founderRotations[1])

        val memberRotations = log.rotatedKeysFor(provider, memberKeys())
        assertEquals(1, memberRotations.size)
        assertContentEquals(Suite1Fixtures.membershipRotateKey(), memberRotations[0])
    }

    // ── Wrapped keys ──────────────────────────────────────────────────────────────────────────

    @Test
    fun wrappedKeys_unwrapForBothRecipients() {
        val blob = Suite1Fixtures.wrappedKeysBlob()
        assertEquals(2 * 5188, blob.size, "two copies of the frozen 5188-byte layout")
        assertEquals(
            listOf(
                DeviceIdentity.deserialise(Suite1Fixtures.founderIdentity()).signingPublicKey.toHexString(),
                DeviceIdentity.deserialise(Suite1Fixtures.memberIdentity()).signingPublicKey.toHexString(),
            ),
            WrappedKeys.recipientsOf(blob),
        )
        val provider = provider ?: return
        assertContentEquals(Suite1Fixtures.wrappedMasterKey(), WrappedKeys.unwrapFor(provider, blob, founderKeys()))
        assertContentEquals(Suite1Fixtures.wrappedMasterKey(), WrappedKeys.unwrapFor(provider, blob, memberKeys()))
    }

    // ── Lane envelope + epoch keys ────────────────────────────────────────────────────────────

    @Test
    fun laneEnvelope_parsesOpensAndReserialisesByteExactly() {
        val bytes = Suite1Fixtures.envelopeBytes()
        val envelope = LaneEnvelope.deserialise(bytes)
        assertEquals(LaneEnvelope.VERSION, envelope.version)
        assertEquals(Suite1Fixtures.envelopeContextId, envelope.contextId)
        assertEquals(Suite1Fixtures.envelopeLane, envelope.lane)
        assertEquals(Suite1Fixtures.envelopeSeq, envelope.seq)
        assertEquals(0, envelope.epoch)
        assertContentEquals(bytes, envelope.serialise(), "envelope must re-serialise byte-exactly")

        val provider = provider ?: return
        val plaintext = envelope.openWithoutReplayProtection(
            provider, EpochKeys.of(mapOf(0 to Suite1Fixtures.envelopeKey())),
        )
        assertEquals(Suite1Fixtures.envelopePlaintext, plaintext.decodeToString())
    }

    @Test
    fun epochKeys_parseAndReserialiseByteExactly() {
        val bytes = Suite1Fixtures.epochKeysBytes()
        val keys = assertNotNull(EpochKeys.deserialise(bytes))
        assertEquals(listOf(0, 1), keys.epochs)
        assertContentEquals(Suite1Fixtures.epochKey0(), keys[0])
        assertContentEquals(Suite1Fixtures.epochKey1(), keys[1])
        assertContentEquals(bytes, keys.serialise(), "epoch keys must re-serialise byte-exactly")
    }

    // ── Async invite ──────────────────────────────────────────────────────────────────────────

    @Test
    fun inviteLink_parsesToTheFrozenSecretAndFingerprint() {
        val link = assertNotNull(InviteLink.parseUrl(Suite1Fixtures.inviteLinkUrl))
        assertContentEquals(Suite1Fixtures.inviteSecret(), link.secret)
        assertEquals(Suite1Fixtures.inviteLinkUrl, link.url(), "link must re-encode byte-exactly")
        provider?.let {
            assertContentEquals(
                InviteLink.fingerprintOf(it, DeviceIdentity.deserialise(Suite1Fixtures.founderIdentity())),
                link.fingerprint,
            )
        }
        assertNull(InviteLink.parse("A1.short.fp"), "legacy A1 links must stay rejected")
    }

    @Test
    fun inviteBundle_parsesVerifiesAndReserialisesByteExactly() {
        val bytes = Suite1Fixtures.inviteBundle()
        val bundle = InviteBundle.deserialise(bytes)
        assertEquals(Suite1Fixtures.inviteExpiryEpochSeconds, bundle.expiryEpochSeconds)
        assertContentEquals(Suite1Fixtures.inviteKemPublicKey(), bundle.inviteXWingPublicKey)
        assertContentEquals(Suite1Fixtures.founderIdentity(), bundle.deviceIdentityA.serialise())
        assertContentEquals(bytes, bundle.serialise(), "bundle must re-serialise byte-exactly")
        provider?.let {
            assertTrue(bundle.verifySignature(it, Suite1Fixtures.inviteRidAsync()), "bundle signature must verify")
        }
    }

    // ── Pairing wire ──────────────────────────────────────────────────────────────────────────

    @Test
    fun pairingFrames_decodeAndReencodeByteExactly() {
        val hello = Suite1Fixtures.pairingInviterHello()
        assertContentEquals(hello, PairingWire.encode(PairingWire.decodeInviterHello(hello)))
        assertEquals(PairingWire.TAG_INVITER_HELLO, hello[0].toInt())

        val response = Suite1Fixtures.pairingJoinerResponse()
        assertContentEquals(response, PairingWire.encode(PairingWire.decodeJoinerResponse(response)))
        assertEquals(PairingWire.TAG_JOINER_RESPONSE, response[0].toInt())

        val confirm = Suite1Fixtures.pairingInviterConfirm()
        assertContentEquals(confirm, PairingWire.encode(PairingWire.decodeInviterConfirm(confirm)))
        assertEquals(PairingWire.TAG_INVITER_CONFIRM, confirm[0].toInt())

        val sasConfirmed = Suite1Fixtures.pairingSasConfirmed()
        PairingWire.decodeSasConfirmed(sasConfirmed)
        assertContentEquals(sasConfirmed, PairingWire.encodeSasConfirmed())

        val complete = Suite1Fixtures.pairingInviterComplete()
        assertContentEquals(complete, PairingWire.encode(PairingWire.decodeInviterComplete(complete)))
        assertEquals(PairingWire.TAG_INVITER_COMPLETE, complete[0].toInt())
    }

    @Test
    fun pairingCompleteFrame_carriesAVerifiableCeremonyLog() {
        val provider = provider ?: return
        val complete = PairingWire.decodeInviterComplete(Suite1Fixtures.pairingInviterComplete())
        val log = MembershipLog.deserialise(complete.membershipLog)
        val verification = log.verify(provider)
        assertIs<MembershipVerification.Valid>(verification, "the ceremony's log must verify")
        assertEquals(2, verification.activeMembers.size, "founder plus the paired joiner")
        assertContentEquals(complete.membershipLog, log.serialise(), "ceremony log must re-serialise byte-exactly")
    }
}
