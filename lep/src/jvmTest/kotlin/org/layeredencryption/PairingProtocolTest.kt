package org.layeredencryption

import org.layeredencryption.BouncyCastleCryptoProvider
import org.layeredencryption.Cascade
import org.layeredencryption.CryptoProvider
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.pairing.Handshake
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingException
import org.layeredencryption.pairing.PairingTranscript
import org.layeredencryption.pairing.Rendezvous
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PairingProtocolTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    // ── PairingCode (§6.1/§6.2) ───────────────────────────────────────────────────────────────

    @Test
    fun pairingCode_generatesSixCharsAndFormats() {
        val code = PairingCode.generate(provider)
        assertEquals(6, code.display.length)
        assertEquals(7, code.formatted.length) // 6 chars + 1 hyphen
        assertEquals('-', code.formatted[3])
    }

    @Test
    fun pairingCode_foldsOnlyTheZeroOhPair() {
        // O↔0 is the single forgiven confusable, and separators are ignored.
        assertEquals(PairingCode.canonicalise("OK2-M5X"), PairingCode.canonicalise("0k2 m5x"))
        assertEquals("0K2M5X", PairingCode.canonicalise("OK2-M5X"))
    }

    @Test
    fun pairingCode_keepsOneEyeAndElDistinct() {
        // Colour-coded uppercase Atkinson Mono disambiguates these on screen, so they stay distinct
        // characters — folding them would throw away entropy for no legibility gain.
        val one = PairingCode.canonicalise("1AAAAA")
        val eye = PairingCode.canonicalise("IAAAAA")
        val el = PairingCode.canonicalise("LAAAAA")

        assertEquals("1AAAAA", one)
        assertEquals("IAAAAA", eye)
        assertEquals("LAAAAA", el)
        assertEquals(3, setOf(one, eye, el).size, "1, I and L must not collapse together")
    }

    @Test
    fun pairingCode_rejectsWrongLength() {
        assertNull(PairingCode.canonicalise("ABC"))
        assertNull(PairingCode.canonicalise("ABCDEFG"))
        assertEquals("ABCDEF", PairingCode.canonicalise("abc-def"))
    }

    // ── Rendezvous (§6.3) ─────────────────────────────────────────────────────────────────────

    @Test
    fun rendezvous_isDeterministicPerCodeAnd32Bytes() {
        val id = Rendezvous.id(provider, "K7M0F2")
        assertEquals(32, id.size)
        assertContentEquals(id, Rendezvous.id(provider, "K7M0F2"))
        assertTrue(!id.contentEquals(Rendezvous.id(provider, "K7M0F3")))
    }

    // ── SAS (§4.5) ────────────────────────────────────────────────────────────────────────────

    @Test
    fun sas_isSixDigitsGroupedAndDeterministic() {
        val transcript = PairingTranscript(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), byteArrayOf(4))
        val secret = ByteArray(32) { it.toByte() }
        val sas = Handshake.shortAuthString(provider, secret, transcript)

        assertEquals(7, sas.length) // "ddd ddd"
        assertEquals(' ', sas[3])
        assertTrue(sas.filter { it != ' ' }.all { it.isDigit() })
        assertEquals(sas, Handshake.shortAuthString(provider, secret, transcript))
    }

    // ── MembershipLog (§4.7) ──────────────────────────────────────────────────────────────────

    @Test
    fun membershipLog_foundThenAddVerifiesWithBothMembers() {
        val founder = DeviceKeys.generate(provider)
        val joiner = DeviceKeys.generate(provider)
        val log = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
            .append(provider, MembershipOp.ADD, joiner.identity, wrappedKeys = null, signer = founder.signingKeyPair)

        val verification = log.verify(provider)
        assertTrue(verification is MembershipVerification.Valid)
        assertEquals(2, verification.activeMembers.size)
    }

    @Test
    fun membershipLog_rejectsEntrySignedByNonMember() {
        val founder = DeviceKeys.generate(provider)
        val outsider = DeviceKeys.generate(provider)
        val joiner = DeviceKeys.generate(provider)
        // An outsider (never added) signs the ADD — must be rejected.
        val log = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
            .append(provider, MembershipOp.ADD, joiner.identity, wrappedKeys = null, signer = outsider.signingKeyPair)

        val verification = log.verify(provider)
        assertTrue(verification is MembershipVerification.Invalid)
        assertEquals(1, verification.entryIndex)
    }

    @Test
    fun membershipLog_rejectsTamperedSignature() {
        val founder = DeviceKeys.generate(provider)
        val joiner = DeviceKeys.generate(provider)
        val serialised = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
            .append(provider, MembershipOp.ADD, joiner.identity, wrappedKeys = null, signer = founder.signingKeyPair)
            .serialise()
        // The last byte lands in the final entry's signature field; flipping it keeps framing intact.
        serialised[serialised.lastIndex] = (serialised[serialised.lastIndex] + 1).toByte()

        val verification = MembershipLog.deserialise(serialised).verify(provider)
        assertTrue(verification is MembershipVerification.Invalid)
    }

    // ── End-to-end pairing (§6.3) ─────────────────────────────────────────────────────────────

    @Test
    fun pairing_completesEndToEndWithSharedMasterKeyAndMatchingSas() {
        val code = PairingCode.generate(provider)
        val inviter = Inviter(provider, DeviceKeys.generate(provider), code)
        val joiner = Joiner(provider, DeviceKeys.generate(provider), code)

        val response = joiner.onInviterHello(inviter.hello())
        val confirm = inviter.onJoinerResponse(response)
        joiner.onInviterConfirm(confirm)

        // Both screens show the same SAS for the human comparison.
        assertEquals(inviter.shortAuthString, joiner.shortAuthString)

        // Humans confirm → keys are exchanged.
        joiner.onInviterComplete(inviter.complete())
        assertContentEquals(inviter.masterKey(), joiner.masterKey())

        // Proof the shared key actually works: seal on one side, open on the other.
        val blob = Cascade.seal(provider, inviter.masterKey(), "shared event".encodeToByteArray())
        assertContentEquals("shared event".encodeToByteArray(), Cascade.open(provider, joiner.masterKey(), blob))
    }

    @Test
    fun pairing_wrongCodeFailsAtTheMac() {
        val inviter = Inviter(provider, DeviceKeys.generate(provider), PairingCode.of("ABCDEF"))
        val joiner = Joiner(provider, DeviceKeys.generate(provider), PairingCode.of("ZZZZZZ"))

        val response = joiner.onInviterHello(inviter.hello())
        // The joiner never knew the real code: its MAC cannot match, so pairing aborts.
        assertFailsWith<PairingException> { inviter.onJoinerResponse(response) }
    }
}
