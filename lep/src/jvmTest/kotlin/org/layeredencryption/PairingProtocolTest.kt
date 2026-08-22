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
import org.layeredencryption.pairing.TestNegotiation
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

    private val negotiation = TestNegotiation.pair(provider)

    // ── PairingCode (§6.1/§6.2) ───────────────────────────────────────────────────────────────

    @Test
    fun pairingCode_generates24CharsAndFormats() {
        val code = PairingCode.generate(provider)
        assertEquals(24, code.display.length)
        assertEquals(29, code.formatted.length) // 24 chars + 5 hyphens
        assertEquals('-', code.formatted[4])
        assertEquals(listOf(14, 14), code.lines.map { it.length }, "two lines of three 4-char groups")
        assertEquals(code.display, code.lines.joinToString("").replace("-", ""))
    }

    /**
     * `O` must never be generated. Drawing from 36 symbols and folding `O` to `0` afterwards would
     * make `0` twice as likely as everything else, which quietly costs about six bits of
     * min-entropy against a guesser who starts with the most probable codes.
     */
    @Test
    fun pairingCode_isUniformOverThirtyFiveSymbols() {
        val counts = HashMap<Char, Int>()
        val samples = 2_000
        repeat(samples) { PairingCode.generate(provider).canonical.forEach { counts[it] = (counts[it] ?: 0) + 1 } }

        assertEquals(35, counts.size, "every canonical symbol should appear")
        assertTrue('O' !in counts, "O must never be generated; it is only forgiven on input")

        val total = samples * PairingCode.LENGTH
        val expected = total / 35.0
        val zero = counts['0']!!.toDouble()
        assertTrue(
            zero in (expected * 0.85)..(expected * 1.15),
            "0 appeared $zero times against an expected $expected: the draw is not uniform",
        )
    }

    @Test
    fun pairingCode_foldsOnlyTheZeroOhPair() {
        // O↔0 is the single forgiven confusable, and separators are ignored.
        val withOh = "OK2M-5XAB-CDEF-GHJK-LMNP-QRST"
        val withZero = "0k2m 5xab cdef ghjk lmnp qrst"
        assertEquals(PairingCode.canonicalise(withOh), PairingCode.canonicalise(withZero))
        assertEquals("0K2M5XABCDEFGHJKLMNPQRST", PairingCode.canonicalise(withOh))
    }

    @Test
    fun pairingCode_keepsOneEyeAndElDistinct() {
        // Colour-coded uppercase Atkinson Mono disambiguates these on screen, so they stay distinct
        // characters — folding them would throw away entropy for no legibility gain.
        val rest = "A".repeat(23)
        val one = PairingCode.canonicalise("1$rest")
        val eye = PairingCode.canonicalise("I$rest")
        val el = PairingCode.canonicalise("L$rest")

        assertEquals("1$rest", one)
        assertEquals("I$rest", eye)
        assertEquals("L$rest", el)
        assertEquals(3, setOf(one, eye, el).size, "1, I and L must not collapse together")
    }

    @Test
    fun pairingCode_rejectsWrongLength() {
        assertNull(PairingCode.canonicalise("ABC"))
        assertNull(PairingCode.canonicalise("A".repeat(23)))
        assertNull(PairingCode.canonicalise("A".repeat(25)))
        assertEquals("A".repeat(24), PairingCode.canonicalise("aaaa-aaaa-aaaa-aaaa-aaaa-aaaa"))
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
        val transcript = PairingTranscript(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), byteArrayOf(4), byteArrayOf(5), negotiated = negotiation.first)
        val secret = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(Handshake.SAS_NONCE_SIZE) { it.toByte() }
        val sas = Handshake.shortAuthString(provider, secret, transcript, nonce)

        assertEquals(7, sas.length) // "ddd ddd"
        assertEquals(' ', sas[3])
        assertTrue(sas.filter { it != ' ' }.all { it.isDigit() })
        assertEquals(sas, Handshake.shortAuthString(provider, secret, transcript, nonce))

        // A different nonce means different digits: this is what makes the SAS unpredictable to a
        // joiner that has not yet seen the opening.
        val otherNonce = ByteArray(Handshake.SAS_NONCE_SIZE) { (it + 1).toByte() }
        assertTrue(sas != Handshake.shortAuthString(provider, secret, transcript, otherNonce))
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
        val inviter = Inviter(provider, DeviceKeys.generate(provider), code, negotiated = negotiation.first)
        val joiner = Joiner(provider, DeviceKeys.generate(provider), code, negotiated = negotiation.second)

        val response = joiner.onInviterHello(inviter.hello())
        val confirm = inviter.onJoinerResponse(response)
        joiner.onInviterConfirm(confirm)

        // Both screens show the same SAS for the human comparison.
        assertEquals(inviter.shortAuthString, joiner.shortAuthString)

        // Humans confirm → keys are exchanged.
        joiner.onInviterComplete(inviter.complete(inviter.confirmSas()), joiner.confirmSas())
        assertContentEquals(inviter.masterKey(), joiner.masterKey())

        // Proof the shared key actually works: seal on one side, open on the other.
        val blob = Cascade.seal(provider, inviter.masterKey(), "shared event".encodeToByteArray())
        assertContentEquals("shared event".encodeToByteArray(), Cascade.open(provider, joiner.masterKey(), blob))
    }

    @Test
    fun pairing_wrongCodeFailsAtTheMac() {
        val inviter = Inviter(provider, DeviceKeys.generate(provider), PairingCode.of("A".repeat(24)), negotiated = negotiation.first)
        val joiner = Joiner(provider, DeviceKeys.generate(provider), PairingCode.of("Z".repeat(24)), negotiated = negotiation.second)

        val response = joiner.onInviterHello(inviter.hello())
        // The joiner never knew the real code: its MAC cannot match, so pairing aborts.
        assertFailsWith<PairingException> { inviter.onJoinerResponse(response) }
    }
}
