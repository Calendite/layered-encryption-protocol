package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.invite.AsyncInviter
import org.layeredencryption.invite.AsyncJoiner
import org.layeredencryption.invite.AsyncJoinerResponse
import org.layeredencryption.invite.InMemoryInviteStore
import org.layeredencryption.invite.InviteLink
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.invite.ResponseOutcome
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Protocol objects are snapshots, not windows (LEP-09 retest 9.3 / LEP-07 retest 7.4): mutating
 * a constructor input after construction, or a getter result after a read, must not change the
 * object — a verified identity, entry, bundle, or record cannot be edited into something else
 * after its check.
 */
class ImmutabilityTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()
    private val now = 1_000_000L
    private val expiry = now + 7 * 86_400L

    @Test
    fun deviceIdentity_ignoresMutationOfInputsAndReads() {
        val identity = DeviceKeys.generate(provider).identity
        val canonical = identity.serialise()

        // Getter results are copies.
        identity.signingPublicKey.fill(0)
        identity.bindingSignature.fill(0)
        assertContentEquals(canonical, identity.serialise())
        assertTrue(identity.verifyBinding(provider))

        // Constructor inputs are copied too.
        val signing = identity.signingPublicKey
        val x25519 = identity.x25519IdentityPublicKey
        val xwing = identity.xWingPublicKey
        val binding = identity.bindingSignature
        val rebuilt = DeviceIdentity(signing, x25519, xwing, binding)
        val rebuiltBytes = rebuilt.serialise()
        signing.fill(1); x25519.fill(1); xwing.fill(1); binding.fill(1)
        assertContentEquals(rebuiltBytes, rebuilt.serialise())
        assertTrue(rebuilt.verifyBinding(provider))
    }

    @Test
    fun membershipEntries_surviveMutationAfterVerification() {
        val founder = DeviceKeys.generate(provider)
        val member = DeviceKeys.generate(provider)
        val log = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
            .append(provider, MembershipOp.ADD, member.identity, wrappedKeys = null, signer = founder.signingKeyPair)

        log.entries.forEach { entry ->
            entry.previousHash.fill(9)
            entry.signature.fill(9)
            entry.signerPublicKey.fill(9)
        }
        assertIs<MembershipVerification.Valid>(log.verify(provider), "mutated reads must not corrupt the chain")
    }

    @Test
    fun membershipLog_entriesListIsAStructuralSnapshot() {
        val founder = DeviceKeys.generate(provider)
        val log = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
        val roundTripped = MembershipLog.deserialise(log.serialise())

        // Kotlin's List is read-only, not immutable: a hostile down-cast on the returned list
        // must either fail outright or reach a copy — never the verified log's backing
        // collection. Both defenses are acceptable; the log being unchanged is the invariant.
        val entries = roundTripped.entries
        runCatching {
            @Suppress("UNCHECKED_CAST")
            (entries as? MutableList<Any?>)?.clear()
        }

        assertTrue(roundTripped.entries.size == 1, "the log must be unchanged by the cast mutation")
        assertIs<MembershipVerification.Valid>(roundTripped.verify(provider))
    }

    @Test
    fun laneEnvelope_opensAfterItsCiphertextReadIsMutated() {
        val keys = EpochKeys.founding(provider.randomBytes(32))
        val plaintext = "op".encodeToByteArray()
        val envelope = LaneEnvelope.seal(provider, keys, "ctx", "lane", seq = 1, plaintext = plaintext)

        envelope.ciphertext.fill(0)
        assertContentEquals(plaintext, envelope.open(provider, keys))
    }

    @Test
    fun epochKeys_copyKeysBothWays() {
        val master = provider.randomBytes(32)
        val original = master.copyOf()
        val keys = EpochKeys.founding(master)

        master.fill(0) // the input was copied
        assertContentEquals(original, keys.currentKey)

        keys.currentKey.fill(0) // the read is a copy
        assertContentEquals(original, keys[0]!!)
    }

    @Test
    fun deviceKeys_privateKeyReadsAreSnapshots() {
        val device = DeviceKeys.generate(provider)
        val message = "sign me".encodeToByteArray()

        device.signingPrivateKey.fill(0)
        device.xWingPrivateKey.fill(0)

        val signature = HybridSignature.sign(provider, device.signingKeyPair.privateKey, message)
        assertTrue(HybridSignature.verify(provider, device.identity.signingPublicKey, message, signature))
    }

    @Test
    fun pendingInviteRecords_areSnapshotsNotWindows() {
        val store = InMemoryInviteStore()
        AsyncInviter.create(provider, DeviceKeys.generate(provider), nowEpochSeconds = now, expiryEpochSeconds = expiry, store = store)

        val record = store.all().single()
        val secret = record.secret
        val masterKey = record.masterKey

        // Mutating what the store handed out changes nothing durable.
        record.secret.fill(9)
        record.masterKey.fill(9)
        assertContentEquals(secret, store.all().single().secret)
        assertContentEquals(masterKey, store.all().single().masterKey)
    }

    @Test
    fun inviteLink_isTheApplicationsCopyNotTheInvitersArray() {
        val inviter = AsyncInviter.create(provider, DeviceKeys.generate(provider), nowEpochSeconds = now, expiryEpochSeconds = expiry)
        val link = inviter.link
        val fragment = link.fragment()

        // Mutating a read does not corrupt the link.
        link.secret.fill(0)
        link.fingerprint.fill(0)
        assertTrue(link.fragment() == fragment)
        assertContentEquals(InviteLink.parse(fragment)!!.secret, link.secret)
    }

    @Test
    fun wireMessages_getterResultsAreCopies() {
        val inviter = AsyncInviter.create(provider, DeviceKeys.generate(provider), nowEpochSeconds = now, expiryEpochSeconds = expiry)
        val joiner = AsyncJoiner(provider, DeviceKeys.generate(provider))
        val response = joiner.onBundle(inviter.link, inviter.bundle, now)

        // Async response: mutate every getter result, then verify the message still authenticates.
        response.kemCiphertext.fill(0)
        response.linkProofMac.fill(0)
        response.joinerMac.fill(0)
        val outcome = inviter.onResponse(response, now)
        assertTrue(outcome is ResponseOutcome.Claimed, "mutated reads must not have altered the message")

        // The Claimed outcome's fingerprint is a copy too.
        val fingerprint = outcome.joinerFingerprint
        outcome.joinerFingerprint.fill(0)
        assertContentEquals(fingerprint, outcome.joinerFingerprint)

        // Delivery: mutate reads, then the joiner still completes.
        val delivery = inviter.approve()
        delivery.inviterMac.fill(0)
        delivery.serialisedMembershipLog.fill(0)
        joiner.onDelivery(delivery)
        assertContentEquals(inviter.masterKey(), joiner.masterKey())

        // Live-pairing messages: encoding is stable under getter mutation.
        val hello = org.layeredencryption.pairing.InviterHello(
            provider.randomBytes(XWing.PUBLIC_KEY_SIZE), DeviceKeys.generate(provider).identity, provider.randomBytes(32),
        )
        val encoded = org.layeredencryption.pairing.PairingWire.encode(hello)
        hello.xWingPublicKey.fill(0)
        hello.sasCommitment.fill(0)
        assertContentEquals(encoded, org.layeredencryption.pairing.PairingWire.encode(hello))

        // The transcript that keys the MACs cannot be edited after the fact.
        val transcript = org.layeredencryption.pairing.PairingTranscript(
            provider.randomBytes(XWing.PUBLIC_KEY_SIZE), ByteArray(8), provider.randomBytes(XWing.CIPHERTEXT_SIZE), ByteArray(8), provider.randomBytes(32),
        )
        val canonical = transcript.bytes()
        transcript.inviterXWingPublicKey.fill(0)
        transcript.sasCommitment.fill(0)
        assertContentEquals(canonical, transcript.bytes())
    }

    @Test
    fun wireMessages_snapshotTheirInputs() {
        val inviter = AsyncInviter.create(provider, DeviceKeys.generate(provider), nowEpochSeconds = now, expiryEpochSeconds = expiry)
        val joiner = AsyncJoiner(provider, DeviceKeys.generate(provider))
        val genuine = joiner.onBundle(inviter.link, inviter.bundle, now)

        // Rebuild the response from arrays we keep, then mutate those arrays: the message must
        // have snapshotted them at construction, so the verified bytes are unchanged.
        val ct = genuine.kemCiphertext
        val proof = genuine.linkProofMac
        val mac = genuine.joinerMac
        val rebuilt = AsyncJoinerResponse(ct, genuine.deviceIdentityS, proof, mac)
        ct.fill(0); proof.fill(0); mac.fill(0)

        assertTrue(inviter.onResponse(rebuilt, now) is ResponseOutcome.Claimed)
    }
}
