package org.layeredencryption.pairing

import org.layeredencryption.CryptoProvider
import org.layeredencryption.suite.SuiteRegistry
import org.layeredencryption.suite.SuiteResolver

/**
 * Test scaffolding: a completed negotiation pair for driving [Inviter]/[Joiner] directly,
 * without a channel. The two contexts share the same offer/accept bytes — as they must, or the
 * ceremony's MACs (which bind those frames) could never agree.
 */
internal object TestNegotiation {

    /** (inviter context, joiner context) from one negotiation run under [resolver]. */
    fun pair(
        provider: CryptoProvider,
        resolver: SuiteResolver = SuiteRegistry,
        policy: PairingSuitePolicy = PairingSuitePolicy(),
    ): Pair<NegotiatedSuiteContext, NegotiatedSuiteContext> {
        val inviter = SuiteNegotiator.beginInviter(provider, resolver, policy)
        val joiner = SuiteNegotiator.respond(inviter.offerFrame, provider, resolver, policy)
        return inviter.onAccept(joiner.acceptFrame) to joiner.context
    }

    /** One context, for tests that drive a single session or transcript. */
    fun single(provider: CryptoProvider, resolver: SuiteResolver = SuiteRegistry): NegotiatedSuiteContext =
        pair(provider, resolver).first
}
