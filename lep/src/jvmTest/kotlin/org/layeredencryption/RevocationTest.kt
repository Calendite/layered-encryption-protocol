package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Removing somebody, properly.
 *
 * The failure this guards against is a quiet one. A revoke entry alone ejects a device from the
 * log and changes nothing about what they can read: they keep the context key, and since the relay
 * slot is derived from that key they can carry on collecting the mailbox indefinitely. The
 * confirmation the user taps says "they stop seeing your events from now on", so the rotation is
 * what makes that sentence true rather than a hope.
 */
class RevocationTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    private class Calendar(
        val owner: DeviceKeys,
        val sarah: DeviceKeys,
        val mum: DeviceKeys,
        val log: MembershipLog,
        val keys: EpochKeys,
    )

    /** A three-person calendar: owner founded it, Sarah and Mum were added. */
    private fun threePeople(): Calendar {
        val owner = DeviceKeys.generate(provider)
        val sarah = DeviceKeys.generate(provider)
        val mum = DeviceKeys.generate(provider)
        val keys = EpochKeys.founding(provider.randomBytes(32))
        val log = MembershipLog.found(provider, owner.identity, owner.signingKeyPair)
            .append(provider, MembershipOp.ADD, sarah.identity, wrappedKeys = null, signer = owner.signingKeyPair)
            .append(provider, MembershipOp.ADD, mum.identity, wrappedKeys = null, signer = owner.signingKeyPair)
        return Calendar(owner, sarah, mum, log, keys)
    }

    @Test
    fun `revoking ejects the member and rotates the key to everyone else`() {
        val calendar = threePeople()
        val newKey = provider.randomBytes(32)

        val after = calendar.log.revoke(provider, calendar.sarah.identity, newKey, calendar.owner.signingKeyPair)

        val verification = after.verify(provider)
        assertTrue(verification is MembershipVerification.Valid, "actual: $verification")
        val members = (verification as MembershipVerification.Valid).activeMembers
        assertFalse(calendar.sarah.identity.signingPublicKey.toHexString() in members, "Sarah is out")
        assertTrue(calendar.mum.identity.signingPublicKey.toHexString() in members, "Mum stays")

        assertContentEquals(newKey, after.rotatedKeysFor(provider, calendar.mum).single())
        assertContentEquals(newKey, after.rotatedKeysFor(provider, calendar.owner).single())
    }

    /** The entry that ejects a device is also the entry that device cannot read. */
    @Test
    fun `the revoked member cannot recover the new key`() {
        val calendar = threePeople()
        val newKey = provider.randomBytes(32)

        val after = calendar.log.revoke(provider, calendar.sarah.identity, newKey, calendar.owner.signingKeyPair)

        assertEquals(emptyList(), after.rotatedKeysFor(provider, calendar.sarah))
    }

    /**
     * The point of keeping old epochs. Removing somebody must not take the shared past with it.
     */
    @Test
    fun `events written before the rotation stay readable afterwards`() {
        val calendar = threePeople()
        val before = LaneEnvelope.seal(
            provider, calendar.keys, "ctx", "device-00112233445566aa", 0, "dentist".encodeToByteArray(),
        )

        val newKey = provider.randomBytes(32)
        val after = calendar.log.revoke(provider, calendar.sarah.identity, newKey, calendar.owner.signingKeyPair)
        val mumKeys = calendar.keys.withNextEpoch(after.rotatedKeysFor(provider, calendar.mum).single())

        assertContentEquals("dentist".encodeToByteArray(), before.open(provider, mumKeys))
        assertEquals(0, before.epoch)

        val afterRotation = LaneEnvelope.seal(
            provider, mumKeys, "ctx", "device-00112233445566aa", 1, "yoga".encodeToByteArray(),
        )
        assertEquals(1, afterRotation.epoch, "new writes go under the rotated key")
    }

    /** What the removed device actually loses: everything written from the rotation onwards. */
    @Test
    fun `the revoked member cannot read anything written after the rotation`() {
        val calendar = threePeople()
        val newKey = provider.randomBytes(32)
        val after = calendar.log.revoke(provider, calendar.sarah.identity, newKey, calendar.owner.signingKeyPair)
        val remaining = calendar.keys.withNextEpoch(after.rotatedKeysFor(provider, calendar.mum).single())

        val fresh = LaneEnvelope.seal(
            provider, remaining, "ctx", "device-00112233445566aa", 5, "somewhere private".encodeToByteArray(),
        )

        // Sarah still holds every key she ever had, which is epoch 0 and nothing more.
        assertFailsWith<CryptoException> { fresh.open(provider, calendar.keys) }
    }

    @Test
    fun `two rotations line up with two epochs`() {
        val calendar = threePeople()
        val first = provider.randomBytes(32)
        val second = provider.randomBytes(32)

        val afterOne = calendar.log.revoke(provider, calendar.sarah.identity, first, calendar.owner.signingKeyPair)
        val afterTwo = afterOne.revoke(provider, calendar.mum.identity, second, calendar.owner.signingKeyPair)

        assertEquals(
            listOf(first.toHexString(), second.toHexString()),
            afterTwo.rotatedKeysFor(provider, calendar.owner).map { it.toHexString() },
            "oldest first, so the list indexes straight onto epochs 1 and 2",
        )
        assertEquals(
            listOf(first.toHexString()),
            afterTwo.rotatedKeysFor(provider, calendar.mum).map { it.toHexString() },
            "Mum was revoked by the second rotation and gets no copy of it",
        )
    }

    /**
     * Removing the only other person leaves a calendar of one, which is just your own calendar.
     * The log allows it, because whether that should be a dissolve instead is a product question.
     */
    @Test
    fun `revoking the only other member leaves a calendar of one`() {
        val owner = DeviceKeys.generate(provider)
        val sarah = DeviceKeys.generate(provider)
        val log = MembershipLog.found(provider, owner.identity, owner.signingKeyPair)
            .append(provider, MembershipOp.ADD, sarah.identity, wrappedKeys = null, signer = owner.signingKeyPair)
        val newKey = provider.randomBytes(32)

        val after = log.revoke(provider, sarah.identity, newKey, owner.signingKeyPair)

        val members = (after.verify(provider) as MembershipVerification.Valid).activeMembers
        assertEquals(setOf(owner.identity.signingPublicKey.toHexString()), members)
        assertContentEquals(newKey, after.rotatedKeysFor(provider, owner).single())
        assertEquals(emptyList(), after.rotatedKeysFor(provider, sarah))
    }

    @Test
    fun `a revoke that would empty the calendar is refused`() {
        val owner = DeviceKeys.generate(provider)
        val log = MembershipLog.found(provider, owner.identity, owner.signingKeyPair)

        assertFailsWith<IllegalArgumentException> {
            log.revoke(provider, owner.identity, provider.randomBytes(32), owner.signingKeyPair)
        }
    }

    @Test
    fun `an ordinary member may revoke, not only the founder`() {
        val calendar = threePeople()

        val after = calendar.log.revoke(
            provider, calendar.mum.identity, provider.randomBytes(32), calendar.sarah.signingKeyPair,
        )

        assertTrue(after.verify(provider) is MembershipVerification.Valid)
    }
}
