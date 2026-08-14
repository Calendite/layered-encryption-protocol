package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.pairing.ExistingCalendar
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Sharing with more than one person.
 *
 * The trap here is quiet rather than loud: inviting a second person by founding a fresh calendar
 * would succeed at every step and still be a disaster, because the context id derives from the
 * master key, so a new key means every event already shared belongs to a calendar nothing can name
 * again. These tests pin the master key and the log across a second invite for that reason.
 */
class MultiMemberTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    /** Runs a full ceremony and returns the joiner, once paired. */
    private fun pair(inviter: Inviter, joiner: Joiner): Joiner {
        val response = joiner.onInviterHello(inviter.hello())
        joiner.onInviterConfirm(inviter.onJoinerResponse(response))
        joiner.onInviterComplete(inviter.complete(inviter.confirmSas()), joiner.confirmSas())
        return joiner
    }

    @Test
    fun `a second invite keeps the same master key`() {
        val owner = DeviceKeys.generate(provider)
        val code = PairingCode.generate(provider)

        val first = Inviter(provider, owner, code)
        val sarah = pair(first, Joiner(provider, DeviceKeys.generate(provider), code))

        val secondCode = PairingCode.generate(provider)
        val second = Inviter(
            provider, owner, secondCode,
            existing = ExistingCalendar(first.calendarKeys(), first.membershipLog()!!),
        )
        val mum = pair(second, Joiner(provider, DeviceKeys.generate(provider), secondCode))

        assertContentEquals(first.masterKey(), second.masterKey(), "the calendar must not be re-founded")
        assertContentEquals(first.masterKey(), sarah.masterKey())
        assertContentEquals(first.masterKey(), mum.masterKey(), "everyone ends up on one key")
    }

    @Test
    fun `a second invite extends the log rather than starting one`() {
        val owner = DeviceKeys.generate(provider)
        val code = PairingCode.generate(provider)
        val first = Inviter(provider, owner, code)
        pair(first, Joiner(provider, DeviceKeys.generate(provider), code))
        val afterFirst = first.membershipLog()!!

        val secondCode = PairingCode.generate(provider)
        val second = Inviter(provider, owner, secondCode, ExistingCalendar(first.calendarKeys(), afterFirst))
        pair(second, Joiner(provider, DeviceKeys.generate(provider), secondCode))
        val afterSecond = second.membershipLog()!!

        assertEquals(2, afterFirst.entries.size, "genesis plus the first ADD")
        assertEquals(3, afterSecond.entries.size, "and now the second ADD")
        assertTrue(afterFirst.isExtendedBy(afterSecond), "the longer log must build on the shorter")

        val verification = afterSecond.verify(provider)
        assertTrue(verification is MembershipVerification.Valid, "actual: $verification")
        assertEquals(3, (verification as MembershipVerification.Valid).activeMembers.size)
    }

    /**
     * Everyone must be able to reach the calendar, not just the last person added. A joiner reads
     * its own wrapped key out of whichever entry added it, so a longer log must not disturb an
     * earlier member.
     */
    @Test
    fun `an earlier member still opens the calendar after someone else joins`() {
        val owner = DeviceKeys.generate(provider)
        val code = PairingCode.generate(provider)
        val first = Inviter(provider, owner, code)
        val sarahKeys = DeviceKeys.generate(provider)
        val sarah = pair(first, Joiner(provider, sarahKeys, code))
        val sarahKey = sarah.masterKey()

        val secondCode = PairingCode.generate(provider)
        val second = Inviter(provider, owner, secondCode, ExistingCalendar(first.calendarKeys(), first.membershipLog()!!))
        pair(second, Joiner(provider, DeviceKeys.generate(provider), secondCode))

        // Sarah's ADD entry is still present and still hers in the grown log.
        val entry = second.membershipLog()!!.addEntryFor(sarahKeys.identity.signingPublicKey)
        assertTrue(entry != null, "Sarah must remain in the log after Mum is added")
        assertContentEquals(sarahKey, first.masterKey(), "and her key is still the calendar's key")
    }

    @Test
    fun `a member added by someone else is admitted, not treated as a stranger`() {
        val owner = DeviceKeys.generate(provider)
        val code = PairingCode.generate(provider)
        val first = Inviter(provider, owner, code)
        val sarahKeys = DeviceKeys.generate(provider)
        pair(first, Joiner(provider, sarahKeys, code))

        // Sarah, an ordinary member rather than the founder, adds Mum.
        val mumKeys = DeviceKeys.generate(provider)
        val grown = first.membershipLog()!!.append(
            provider, MembershipOp.ADD, mumKeys.identity,
            wrappedKeys = ByteArray(8), signer = sarahKeys.signingKeyPair,
        )

        val verification = grown.verify(provider)
        assertTrue(verification is MembershipVerification.Valid, "any active member may add: $verification")
        assertTrue(
            mumKeys.identity.signingPublicKey.toHexString() in
                (verification as MembershipVerification.Valid).activeMembers,
        )
    }

    // ── Propagating the log ───────────────────────────────────────────────────────────────────

    @Test
    fun `a log extends itself but not a fork`() {
        val owner = DeviceKeys.generate(provider)
        val code = PairingCode.generate(provider)
        val first = Inviter(provider, owner, code)
        pair(first, Joiner(provider, DeviceKeys.generate(provider), code))
        val base = first.membershipLog()!!

        val extended = base.append(
            provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity,
            wrappedKeys = null, signer = owner.signingKeyPair,
        )
        val fork = base.append(
            provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity,
            wrappedKeys = null, signer = owner.signingKeyPair,
        )

        assertTrue(base.isExtendedBy(extended))
        assertFalse(extended.isExtendedBy(base), "shorter is never an extension of longer")
        assertFalse(base.isExtendedBy(base), "equal length is not an extension")
        assertFalse(
            extended.isExtendedBy(fork),
            "two concurrent appends are a fork; picking one here would silently drop the other",
        )
    }

    @Test
    fun `an unrelated log is never an extension`() {
        val ownerA = DeviceKeys.generate(provider)
        val codeA = PairingCode.generate(provider)
        val a = Inviter(provider, ownerA, codeA)
        pair(a, Joiner(provider, DeviceKeys.generate(provider), codeA))

        val ownerB = DeviceKeys.generate(provider)
        val codeB = PairingCode.generate(provider)
        val b = Inviter(provider, ownerB, codeB)
        pair(b, Joiner(provider, DeviceKeys.generate(provider), codeB))
        val longerB = b.membershipLog()!!.append(
            provider, MembershipOp.ADD, DeviceKeys.generate(provider).identity,
            wrappedKeys = null, signer = ownerB.signingKeyPair,
        )

        assertFalse(a.membershipLog()!!.isExtendedBy(longerB), "a different calendar is not an extension")
    }
}
