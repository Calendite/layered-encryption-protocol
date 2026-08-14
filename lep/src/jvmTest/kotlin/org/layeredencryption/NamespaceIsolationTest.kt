package org.layeredencryption

import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.invite.AsyncInviter
import org.layeredencryption.invite.AsyncJoiner
import org.layeredencryption.invite.ResponseOutcome
import org.layeredencryption.membership.MembershipLog
import org.layeredencryption.membership.MembershipVerification
import org.layeredencryption.membership.Reconciliation
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * End-to-end namespace isolation (LEP-10): the namespace now propagates through *every* protocol
 * artifact — identity binding, membership signing and hashing, the live ceremony, and async
 * invites — not only the Cascade/envelope layer. Two applications built on this library cannot
 * verify or derive each other's artifacts, and a full ceremony under a custom namespace works
 * end to end, so the separation is usable, not just enforced.
 */
class NamespaceIsolationTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()
    private val appA = ProtocolNamespace("app-a")
    private val appB = ProtocolNamespace("app-b")

    @Test
    fun deviceIdentitiesDoNotVerifyAcrossNamespaces() {
        val device = DeviceKeys.generate(provider, appA)
        assertTrue(device.identity.verifyBinding(provider, appA), "an identity verifies under its own namespace")
        assertFalse(device.identity.verifyBinding(provider, appB), "and under nobody else's")
        assertFalse(device.identity.verifyBinding(provider), "including the default")
    }

    @Test
    fun membershipLogsDoNotVerifyAcrossNamespaces() {
        val owner = DeviceKeys.generate(provider, appA)
        val member = DeviceKeys.generate(provider, appA)
        val log = MembershipLog.found(provider, owner.identity, owner.signingKeyPair, namespace = appA)
            .append(provider, org.layeredencryption.membership.MembershipOp.ADD, member.identity, null, owner.signingKeyPair, appA)

        assertIs<MembershipVerification.Valid>(log.verify(provider, appA))
        assertIs<MembershipVerification.Invalid>(log.verify(provider, appB), "another app's log must not verify")
        assertIs<MembershipVerification.Invalid>(log.verify(provider), "nor under the default namespace")

        // Reconciliation refuses across namespaces too: the foreign log is InvalidBranch, never adopted.
        val foreign = MembershipLog.deserialise(log.serialise())
        assertIs<Reconciliation.InvalidBranch>(log.reconcile(provider, foreign, appB))
    }

    @Test
    fun livePairingFailsClosedAcrossNamespacesAndWorksWithinOne() {
        val code = PairingCode.generate(provider)

        // Cross-namespace: the joiner's code-keyed MAC is derived under different labels, so the
        // inviter rejects it exactly as it would a wrong code or a man-in-the-middle.
        val inviterA = Inviter(provider, DeviceKeys.generate(provider, appA), code, namespace = appA)
        val joinerB = Joiner(provider, DeviceKeys.generate(provider, appB), code, namespace = appB)
        assertFailsWith<PairingException> { inviterA.onJoinerResponse(joinerB.onInviterHello(inviterA.hello())) }

        // Same custom namespace end to end: the full ceremony completes and keys match.
        val inviter = Inviter(provider, DeviceKeys.generate(provider, appA), code, namespace = appA)
        val joiner = Joiner(provider, DeviceKeys.generate(provider, appA), code, namespace = appA)
        val response = joiner.onInviterHello(inviter.hello())
        joiner.onInviterConfirm(inviter.onJoinerResponse(response))
        joiner.onInviterComplete(inviter.complete(inviter.confirmSas()), joiner.confirmSas())
        assertContentEquals(inviter.masterKey(), joiner.masterKey())
    }

    @Test
    fun asyncInvitesFailClosedAcrossNamespacesAndWorkWithinOne() {
        val now = 1_000_000L
        val expiry = now + 86_400L

        // Cross-namespace: the joiner recomputes rid_async under its own labels, so the bundle
        // signature check fails before any key agreement begins.
        val inviterA = AsyncInviter.create(
            provider, DeviceKeys.generate(provider, appA), now, expiry, namespace = appA,
        )
        val joinerB = AsyncJoiner(provider, DeviceKeys.generate(provider, appB), appB)
        assertFailsWith<PairingException> { joinerB.onBundle(inviterA.link, inviterA.bundle, now) }

        // Same custom namespace end to end.
        val inviter = AsyncInviter.create(
            provider, DeviceKeys.generate(provider, appA), now, expiry, namespace = appA,
        )
        val joiner = AsyncJoiner(provider, DeviceKeys.generate(provider, appA), appA)
        val outcome = inviter.onResponse(joiner.onBundle(inviter.link, inviter.bundle, now), now)
        assertTrue(outcome is ResponseOutcome.Claimed)
        joiner.onDelivery(inviter.approve())
        assertContentEquals(inviter.masterKey(), joiner.masterKey())
    }
}
