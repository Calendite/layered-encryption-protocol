package org.layeredencryption

import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.membership.ForkResolution
import org.layeredencryption.membership.MembershipEntry
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipOp
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.membership.SuiteUpgradePayload
import org.layeredencryption.membership.WrappedKeys
import org.layeredencryption.suite.FakeSuites
import org.layeredencryption.suite.SuiteId
import org.layeredencryption.suite.SuiteRegistry
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The migration brief's required SUITE_UPGRADE security tests (§5): the transition is one atomic
 * signed entry binding old/new suite, transition epoch, and fresh keys for exactly the retained
 * members; historical entries verify under the suite active when they were made; downgrades and
 * truncations are rejected; and legacy readers fail closed on the new op code.
 */
class SuiteUpgradeTest {

    private val provider = BouncyCastleCryptoProvider()
    private val fake = FakeSuites.fakeSuite()
    private val resolver = FakeSuites.resolverWith(fake)

    private val founder = DeviceKeys.generate(provider)
    private val member = DeviceKeys.generate(provider)

    private fun foundedLog() = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
        .append(provider, MembershipOp.ADD, member.identity, wrappedKeys = null, signer = founder.signingKeyPair)

    private fun activeHexes(log: MembershipLog) =
        (log.verify(provider, resolver = resolver) as MembershipVerification.Valid).activeMembers

    /** Appends a hand-signed entry, bypassing the builders — for crafting invalid upgrades. */
    private fun MembershipLog.withRawEntry(
        op: MembershipOp,
        subject: DeviceIdentity,
        wrapped: ByteArray?,
        signer: DeviceKeys,
    ): MembershipLog {
        val head = head(provider)
        val unsigned = MembershipEntry(head, op, subject, wrapped, signer.identity.signingPublicKey, ByteArray(0))
        val entry = MembershipEntry(
            head, op, subject, wrapped, signer.identity.signingPublicKey,
            HybridSignature.sign(provider, signer.signingPrivateKey, unsigned.unsignedBytes()),
        )
        return MembershipLog.deserialise(serialise() + FrameWriter().putBytes(entry.serialise()).toByteArray(), resolver)
    }

    private fun wrappedForAll(log: MembershipLog, key: ByteArray) =
        WrappedKeys.wrapForEra(provider, fake, log.activeIdentities(provider), key)

    // ── The happy path ────────────────────────────────────────────────────────────────────────

    @Test
    fun upgrade_isAtomicVerifiableAndScheduled() {
        val masterKey = provider.randomBytes(32)
        val upgraded = foundedLog().upgradeSuite(provider, fake, masterKey, founder, resolver = resolver)

        assertEquals(
            setOf(founder, member).map { it.identity.signingPublicKey.toHexString() }.toSet(),
            activeHexes(upgraded),
            "an upgrade changes no memberships",
        )
        val schedule = assertNotNull(upgraded.suiteSchedule(provider, resolver = resolver))
        assertEquals(SuiteId.LEP_HYBRID_2026, schedule.suiteAt(0))
        assertEquals(FakeSuites.FAKE_ID, schedule.suiteAt(1))
        assertEquals(FakeSuites.FAKE_ID, schedule.current)

        // Both retained members recover the fresh key, wrapped under the NEW suite.
        assertContentEquals(masterKey, upgraded.rotatedKeysFor(provider, founder, resolver = resolver).single())
        assertContentEquals(masterKey, upgraded.rotatedKeysFor(provider, member, resolver = resolver).single())
    }

    @Test
    fun rotatedKeysAndSchedule_spanUpgradeEpochs() {
        val k1 = provider.randomBytes(32)
        val k2 = provider.randomBytes(32)
        val k3 = provider.randomBytes(32)
        val log = foundedLog()
            .rotate(provider, k1, founder)
            .upgradeSuite(provider, fake, k2, founder, resolver = resolver)
            .rotate(provider, k3, founder, resolver = resolver) // sealed under the NEW era

        assertIs<MembershipVerification.Valid>(log.verify(provider, resolver = resolver))
        // Epochs line up 1, 2, 3 for a founding member — pre-upgrade history stays recoverable.
        val keys = log.rotatedKeysFor(provider, founder, resolver = resolver)
        assertEquals(3, keys.size)
        assertContentEquals(k1, keys[0])
        assertContentEquals(k2, keys[1])
        assertContentEquals(k3, keys[2])

        val schedule = assertNotNull(log.suiteSchedule(provider, resolver = resolver))
        assertEquals(SuiteId.LEP_HYBRID_2026, schedule.suiteAt(1))
        assertEquals(FakeSuites.FAKE_ID, schedule.suiteAt(2))
        assertEquals(FakeSuites.FAKE_ID, schedule.suiteAt(3))
    }

    @Test
    fun keylessRevocationBatch_mayTerminateInAnUpgrade_butNotBeTruncatedBeforeIt() {
        // "Revoke the non-upgraded device, then upgrade" as one atomic epoch: the keyless REVOKE
        // is only valid because the SUITE_UPGRADE that excludes the removed member terminates it.
        val third = DeviceKeys.generate(provider)
        val log = foundedLog()
            .append(provider, MembershipOp.ADD, third.identity, wrappedKeys = null, signer = founder.signingKeyPair)
            .append(provider, MembershipOp.REVOKE, third.identity, wrappedKeys = null, signer = founder.signingKeyPair)
        val upgraded = log.upgradeSuite(provider, fake, provider.randomBytes(32), founder, resolver = resolver)

        assertIs<MembershipVerification.Valid>(upgraded.verify(provider, resolver = resolver))
        assertEquals(
            setOf(founder, member).map { it.identity.signingPublicKey.toHexString() }.toSet(),
            activeHexes(upgraded),
        )
        // The relay-truncation attack: dropping the upgrade leaves an unterminated keyless batch.
        val truncated = MembershipLog.deserialise(log.serialise())
        assertIs<MembershipVerification.Invalid>(truncated.verify(provider, resolver = resolver))
    }

    // ── Rejections ────────────────────────────────────────────────────────────────────────────

    @Test
    fun downgradeAndSameSuiteUpgrades_areRejected() {
        val base = foundedLog()
        val sameSuite = SuiteUpgradePayload(
            SuiteId.LEP_HYBRID_2026, SuiteId.LEP_HYBRID_2026, 1,
            WrappedKeys.wrapFor(provider, base.activeIdentities(provider), provider.randomBytes(32)),
        )
        val same = base.withRawEntry(MembershipOp.SUITE_UPGRADE, founder.identity, sameSuite.serialise(), founder)
        val sameResult = same.verify(provider, resolver = resolver)
        assertIs<MembershipVerification.Invalid>(sameResult)
        assertEquals(true, "monotonic" in sameResult.reason)

        // From an upgraded log, an entry pointing back to Suite 1 is the downgrade the brief
        // forbids as an ordinary operation.
        val upgraded = base.upgradeSuite(provider, fake, provider.randomBytes(32), founder, resolver = resolver)
        val downPayload = SuiteUpgradePayload(
            FakeSuites.FAKE_ID, SuiteId.LEP_HYBRID_2026, 2,
            WrappedKeys.wrapFor(provider, upgraded.activeIdentities(provider), provider.randomBytes(32)),
        )
        val downgraded = upgraded.withRawEntry(MembershipOp.SUITE_UPGRADE, founder.identity, downPayload.serialise(), founder)
        val result = downgraded.verify(provider, resolver = resolver)
        assertIs<MembershipVerification.Invalid>(result)
        assertEquals(true, "monotonic" in result.reason, result.reason)

        // The builder refuses locally too.
        assertFailsWith<IllegalArgumentException> {
            upgraded.upgradeSuite(provider, fake, provider.randomBytes(32), founder, resolver = resolver)
        }
    }

    @Test
    fun upgradeOmittingOrPaddingTheRetainedSet_isRejected() {
        val base = foundedLog()

        val omitting = SuiteUpgradePayload(
            SuiteId.LEP_HYBRID_2026, FakeSuites.FAKE_ID, 1,
            WrappedKeys.wrapForEra(provider, fake, listOf(founder.identity), provider.randomBytes(32)),
        )
        val omitted = base.withRawEntry(MembershipOp.SUITE_UPGRADE, founder.identity, omitting.serialise(), founder)
        val omittedResult = omitted.verify(provider, resolver = resolver)
        assertIs<MembershipVerification.Invalid>(omittedResult)
        assertEquals(true, "exactly the active members" in omittedResult.reason, omittedResult.reason)

        val stranger = DeviceKeys.generate(provider)
        val padding = SuiteUpgradePayload(
            SuiteId.LEP_HYBRID_2026, FakeSuites.FAKE_ID, 1,
            WrappedKeys.wrapForEra(
                provider, fake,
                listOf(founder.identity, member.identity, stranger.identity), provider.randomBytes(32),
            ),
        )
        val padded = base.withRawEntry(MembershipOp.SUITE_UPGRADE, founder.identity, padding.serialise(), founder)
        assertIs<MembershipVerification.Invalid>(padded.verify(provider, resolver = resolver))
    }

    @Test
    fun wrongTransitionEpochOrUnknownTargetSuite_isRejected() {
        val base = foundedLog()
        val wrappedKeys = wrappedForAll(base, provider.randomBytes(32))

        val wrongEpoch = SuiteUpgradePayload(SuiteId.LEP_HYBRID_2026, FakeSuites.FAKE_ID, 7, wrappedKeys)
        val epochResult = base.withRawEntry(MembershipOp.SUITE_UPGRADE, founder.identity, wrongEpoch.serialise(), founder)
            .verify(provider, resolver = resolver)
        assertIs<MembershipVerification.Invalid>(epochResult)
        assertEquals(true, "epoch" in epochResult.reason, epochResult.reason)

        // An unknown target suite now fails closed at *parse*: the structural era walk cannot
        // size anything under a suite it does not know, so the log is unreadable, not merely
        // invalid — the same stance as every other unknown-suite artifact.
        val unknown = SuiteUpgradePayload(SuiteId.LEP_HYBRID_2026, SuiteId(0x7777u), 1, wrappedKeys)
        assertFailsWith<IllegalArgumentException> {
            base.withRawEntry(MembershipOp.SUITE_UPGRADE, founder.identity, unknown.serialise(), founder)
        }
    }

    @Test
    fun upgradeAuthorisation_subjectMustBeItsActiveSigner() {
        val base = foundedLog()
        val payload = SuiteUpgradePayload(SuiteId.LEP_HYBRID_2026, FakeSuites.FAKE_ID, 1, wrappedForAll(base, provider.randomBytes(32)))

        // Subject ≠ signer: an upgrade speaks only for its signer.
        val wrongSubject = base.withRawEntry(MembershipOp.SUITE_UPGRADE, member.identity, payload.serialise(), founder)
        val subjectResult = wrongSubject.verify(provider, resolver = resolver)
        assertIs<MembershipVerification.Invalid>(subjectResult)
        assertEquals(true, "subject" in subjectResult.reason, subjectResult.reason)

        // A non-member cannot upgrade a context it is not in.
        val outsider = DeviceKeys.generate(provider)
        val unauthorised = base.withRawEntry(MembershipOp.SUITE_UPGRADE, outsider.identity, payload.serialise(), outsider)
        assertIs<MembershipVerification.Invalid>(unauthorised.verify(provider, resolver = resolver))
    }

    @Test
    fun malformedAndTruncatedPayloads_failClosedAtEveryLength() {
        val good = SuiteUpgradePayload(
            SuiteId.LEP_HYBRID_2026, FakeSuites.FAKE_ID, 1, wrappedForAll(foundedLog(), provider.randomBytes(32)),
        ).serialise()
        assertNotNull(SuiteUpgradePayload.parse(good), "the intact payload parses")

        // Truncation at every prefix length: null, never a throw, never a partial parse.
        for (length in 0 until good.size) {
            assertNull(SuiteUpgradePayload.parse(good.copyOf(length)), "truncated at $length bytes")
        }
        assertNull(SuiteUpgradePayload.parse(good + 0), "trailing byte")

        // Unknown payload version fails before any other field is believed.
        val versioned = good.copyOf().also { it[4] = 2 }
        assertNull(SuiteUpgradePayload.parse(versioned))

        // A non-empty keyTransitions field is invalid in v1: unverifiable transition blobs must
        // not ride along before the machinery that verifies them exists.
        val withTransitions = FrameWriter()
            .putBytes(byteArrayOf(1))
            .putBytes(SuiteId.LEP_HYBRID_2026.toWireBytes())
            .putBytes(FakeSuites.FAKE_ID.toWireBytes())
            .putBytes(intToBytes(1))
            .putBytes(ByteArray(0))
            .putBytes(byteArrayOf(0x41))
            .toByteArray()
        assertNull(SuiteUpgradePayload.parse(withTransitions))
    }

    // ── Mixed-suite era routing ───────────────────────────────────────────────────────────────

    @Test
    fun mixedSuiteLog_verifiesEachEraUnderItsOwnSuite() {
        // The domain-shifted suite signs a prefixed message: if post-upgrade entries were still
        // verified under Suite 1 (or pre-upgrade ones under the new suite), verification would
        // genuinely fail — this is what makes the routing test non-vacuous.
        val shifted = FakeSuites.domainShiftedFakeSuite()
        val shiftedResolver = FakeSuites.resolverWith(shifted)
        val log = MembershipLog.found(provider, founder.identity, founder.signingKeyPair)
            .append(provider, MembershipOp.ADD, member.identity, wrappedKeys = null, signer = founder.signingKeyPair)
            .upgradeSuite(provider, shifted, provider.randomBytes(32), founder, resolver = shiftedResolver)
            .rotate(provider, provider.randomBytes(32), founder, resolver = shiftedResolver)

        assertIs<MembershipVerification.Valid>(log.verify(provider, resolver = shiftedResolver))

        // A resolver that maps the same id to a NON-shifted suite mis-routes the post-upgrade
        // signatures — and the log must fail, proving each era really uses its own suite.
        val misrouted = FakeSuites.resolverWith(FakeSuites.fakeSuite(id = FakeSuites.SHIFTED_ID))
        val result = log.verify(provider, resolver = misrouted)
        assertIs<MembershipVerification.Invalid>(result)
        assertEquals("Invalid signature", result.reason)
    }

    @Test
    fun forkAcrossAnUpgrade_resolvesUnderTheActiveSuite() {
        val base = foundedLog().upgradeSuite(provider, fake, provider.randomBytes(32), founder, resolver = resolver)

        // Ours: two rotations. Theirs: an addition the resolution will drop — the dropped
        // key-holder forces the terminal rotate, which must seal under the upgraded era.
        val ours = base
            .rotate(provider, provider.randomBytes(32), founder, resolver = resolver)
            .rotate(provider, provider.randomBytes(32), founder, resolver = resolver)
        val third = DeviceKeys.generate(provider)
        val theirs = base.append(
            provider, MembershipOp.ADD, third.identity, wrappedKeys = null,
            signer = member.signingKeyPair, resolver = resolver,
        )

        val resolution = ours.resolveFork(provider, theirs, founder, suites = resolver)
        val resolved = assertIs<ForkResolution.Resolved>(resolution)
        assertNotNull(resolved.newMasterKey, "a dropped key-holder forces one rotation")
        assertIs<MembershipVerification.Valid>(resolved.log.verify(provider, resolver = resolver))
        assertEquals(FakeSuites.FAKE_ID, assertNotNull(resolved.log.suiteSchedule(provider, resolver = resolver)).current)
    }

    // ── Frozen op codes ───────────────────────────────────────────────────────────────────────

    @Test
    fun opCodes_areFrozenAndUnknownOnesFailClosed() {
        assertEquals(MembershipOp.ADD, MembershipOp.fromCode(1))
        assertEquals(MembershipOp.REVOKE, MembershipOp.fromCode(2))
        assertEquals(MembershipOp.ROTATE, MembershipOp.fromCode(3))
        assertEquals(MembershipOp.SUITE_UPGRADE, MembershipOp.fromCode(4))
        // The same gate that makes a pre-agility app reject op 4 — and its whole log — today.
        assertFailsWith<IllegalArgumentException> { MembershipOp.fromCode(5) }
        assertFailsWith<IllegalArgumentException> { MembershipOp.fromCode(0) }
    }

    @Test
    fun productionRegistry_doesNotKnowTheTestSuites() {
        assertEquals(false, SuiteRegistry.contains(FakeSuites.FAKE_ID))
        assertEquals(false, SuiteRegistry.contains(FakeSuites.SHIFTED_ID))
        // So an upgraded-with-a-fake log must fail closed under the production resolver.
        val upgraded = foundedLog().upgradeSuite(provider, fake, provider.randomBytes(32), founder, resolver = resolver)
        assertIs<MembershipVerification.Invalid>(upgraded.verify(provider))
    }
}
