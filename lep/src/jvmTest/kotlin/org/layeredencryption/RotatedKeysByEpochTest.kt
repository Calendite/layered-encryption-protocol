package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * [MembershipLog.rotatedKeysByEpoch]: a rotation's key filed under the epoch it starts, counted by the
 * log, so a device that joined after earlier rotations files the next one correctly.
 */
class RotatedKeysByEpochTest {

    private val provider = BouncyCastleCryptoProvider()
    private val founder = DeviceKeys.generate(provider)
    private val bob = DeviceKeys.generate(provider)
    private val charlie = DeviceKeys.generate(provider)

    private val first = provider.randomBytes(32)
    private val second = provider.randomBytes(32)

    /** Bob in from the start, one rotation, Charlie joins, a second rotation. */
    private val log = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
        .append(provider, MembershipOp.ADD, bob.identity, wrappedKeys = null, signer = founder.signingKeyPair)
        .rotate(provider, first, founder)
        .append(provider, MembershipOp.ADD, charlie.identity, wrappedKeys = null, signer = founder.signingKeyPair)
        .rotate(provider, second, founder)

    @Test
    fun aMemberThroughoutGetsEveryRotationAtItsEpoch() {
        val keys = log.rotatedKeysByEpoch(provider, bob)
        assertEquals(setOf(1, 2), keys.keys)
        assertContentEquals(first, keys[1])
        assertContentEquals(second, keys[2])
    }

    @Test
    fun aLaterJoinerFilesTheNextRotationUnderItsRealEpoch() {
        val keys = log.rotatedKeysByEpoch(provider, charlie)
        assertEquals(setOf(2), keys.keys, "Charlie was not a recipient of epoch 1")
        assertContentEquals(second, keys[2])
        assertEquals(1, log.rotatedKeysFor(provider, charlie).size, "counting what he could open would have called it epoch 1")
    }
}
