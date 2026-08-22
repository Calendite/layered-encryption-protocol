package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.invite.AsyncRendezvous
import org.layeredencryption.invite.InviteBundleV2
import org.layeredencryption.invite.InviteLink
import org.layeredencryption.suite.FakeSuites
import org.layeredencryption.suite.SuiteId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Versioned invitations (the migration brief §4): the `A3` link carries its suite out of band,
 * the v2 bundle is self-describing and suite-bound, `A2`/v1 stay byte-frozen, and the joiner's
 * downgrade guard is link-vs-bundle suite equality plus per-version parser assignment.
 */
class InviteV2Test {

    private val provider = BouncyCastleCryptoProvider()
    private val fake = FakeSuites.fakeSuite()
    private val resolver = FakeSuites.resolverWith(fake)

    private val inviterKeys = DeviceKeys.generate(provider, fake)
    private val secret = provider.randomBytes(InviteLink.SECRET_SIZE)
    private val ridAsync = AsyncRendezvous.id(provider, secret)

    private fun bundle() = InviteBundleV2.build(
        provider,
        inviteXWingPublicKey = fake.kem.generateKeyPair(provider).publicKey,
        deviceKeysA = inviterKeys,
        expiryEpochSeconds = 1_924_992_000L,
        ridAsync = ridAsync,
        resolver = resolver,
    )

    // ── A3 links ──────────────────────────────────────────────────────────────────────────────

    @Test
    fun a3Link_roundTripsWithItsSuiteHint() {
        val link = InviteLink.createSuited(provider, secret, inviterKeys.identity)
        assertEquals(FakeSuites.FAKE_ID, link.suiteId)
        assertTrue(link.url().contains("#A3.${FakeSuites.FAKE_ID.value}."), link.url())

        val parsed = assertNotNull(InviteLink.parseUrl(link.url()))
        assertEquals(FakeSuites.FAKE_ID, parsed.suiteId)
        assertContentEquals(secret, parsed.secret)
        assertContentEquals(InviteLink.fingerprintOf(provider, inviterKeys.identity), parsed.fingerprint)
        assertEquals(link.url(), parsed.url(), "the link must re-encode byte-exactly")
    }

    @Test
    fun a2Links_parseExactlyAsBefore() {
        val v1 = DeviceKeys.generate(provider)
        val legacy = InviteLink.create(provider, secret, v1.identity)
        val parsed = assertNotNull(InviteLink.parseUrl(legacy.url()))
        assertNull(parsed.suiteId, "an A2 link carries no suite hint")
        assertContentEquals(secret, parsed.secret)
    }

    @Test
    fun linkParsing_staysStrictAcrossVersions() {
        val a3 = InviteLink.createSuited(provider, secret, inviterKeys.identity).fragment()
        val parts = a3.split('.')

        // Field-count and tag mismatches between the versions never cross-parse.
        assertNull(InviteLink.parse("A3.${parts[2]}.${parts[3]}"), "A3 with a missing suite id")
        assertNull(InviteLink.parse("A2.${parts[1]}.${parts[2]}.${parts[3]}"), "A2 with four parts")
        assertNull(InviteLink.parse("A1.${parts[2]}.${parts[3]}"), "legacy A1 stays dead")

        // The suite id must be canonical decimal in range.
        fun withSid(sid: String) = "A3.$sid.${parts[2]}.${parts[3]}"
        assertNotNull(InviteLink.parse(withSid("1")))
        assertNull(InviteLink.parse(withSid("07")), "leading zero")
        assertNull(InviteLink.parse(withSid("+7")), "sign")
        assertNull(InviteLink.parse(withSid("65536")), "out of range")
        assertNull(InviteLink.parse(withSid("suite")), "not a number")
    }

    // ── Bundle v2 ─────────────────────────────────────────────────────────────────────────────

    @Test
    fun bundleV2_verifiesAndRoundTripsByteExactly() {
        val built = bundle()
        assertEquals(FakeSuites.FAKE_ID, built.suiteId)
        assertTrue(built.verifySignature(provider, ridAsync, resolver = resolver))

        val bytes = built.serialise()
        val decoded = InviteBundleV2.deserialise(bytes, resolver)
        assertContentEquals(bytes, decoded.serialise(), "must re-serialise byte-exactly")
        assertTrue(decoded.verifySignature(provider, ridAsync, resolver = resolver))
        assertTrue(decoded.deviceIdentityA.verifyBinding(provider, resolver = resolver))
    }

    @Test
    fun bundleV2_signatureCoversTheRecipientRelevantMaterial() {
        val built = bundle()
        // Wrong rendezvous: a bundle re-posted at a different slot must not verify.
        assertFalse(built.verifySignature(provider, provider.randomBytes(32), resolver = resolver))
        // Tampered expiry: rebuild with a different expiry under the same signature.
        val extended = InviteBundleV2(
            built.inviteXWingPublicKey, built.deviceIdentityA, built.expiryEpochSeconds + 1, built.signature,
        )
        assertFalse(extended.verifySignature(provider, ridAsync, resolver = resolver))
    }

    @Test
    fun bundleV2_failsClosedOnHostileBytes() {
        val bytes = bundle().serialise()

        assertFailsWith<IllegalArgumentException>("unknown suite under the production registry") {
            InviteBundleV2.deserialise(bytes)
        }
        assertFailsWith<IllegalArgumentException>("trailing byte") {
            InviteBundleV2.deserialise(bytes + 0, resolver)
        }
        val versioned = bytes.copyOf().also { it[4] = 3 }
        assertFailsWith<IllegalArgumentException>("unknown format version") {
            InviteBundleV2.deserialise(versioned, resolver)
        }
        // A v1 bundle is not an ambiguous fallback of the v2 parser, nor vice versa.
        val v1Keys = DeviceKeys.generate(provider)
        val v1 = org.layeredencryption.invite.InviteBundle.build(
            provider, XWing.generateKeyPair(provider).publicKey, v1Keys.identity,
            expiryEpochSeconds = 1_924_992_000L, ridAsync = ridAsync, signer = v1Keys.signingKeyPair,
        )
        assertFailsWith<IllegalArgumentException> { InviteBundleV2.deserialise(v1.serialise(), resolver) }
        assertFailsWith<IllegalArgumentException> {
            org.layeredencryption.invite.InviteBundle.deserialise(bytes)
        }
    }

    @Test
    fun joinerDowngradeGuard_linkAndBundleSuitesMustAgree() {
        // The A3 link travelled out of band; the bundle came from the relay. A relay that
        // downgrades the bundle's suite (here: an otherwise-valid bundle from a Suite 1 v2
        // identity) is caught by the equality check every A3 joiner performs.
        val link = InviteLink.createSuited(provider, secret, inviterKeys.identity)
        val suite1Inviter = DeviceKeys.generate(provider, org.layeredencryption.suite.Suite1)
        val downgraded = InviteBundleV2.build(
            provider, XWing.generateKeyPair(provider).publicKey, suite1Inviter,
            expiryEpochSeconds = 1_924_992_000L, ridAsync = ridAsync, resolver = resolver,
        )
        assertTrue(downgraded.verifySignature(provider, ridAsync, resolver = resolver), "valid in isolation")
        assertFalse(downgraded.suiteId == link.suiteId, "but it does not match the link — reject")
        assertEquals(SuiteId(1u), downgraded.suiteId)
    }
}
