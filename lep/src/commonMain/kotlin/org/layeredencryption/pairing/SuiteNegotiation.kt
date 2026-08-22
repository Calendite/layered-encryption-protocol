package org.layeredencryption.pairing

import org.layeredencryption.CryptoProvider
import org.layeredencryption.HybridSignature
import org.layeredencryption.XWing
import org.layeredencryption.suite.ProtocolSuite
import org.layeredencryption.suite.SuiteId
import org.layeredencryption.suite.SuiteRegistry
import org.layeredencryption.suite.SuiteResolver

/**
 * Authenticated, downgrade-resistant suite negotiation for pairing (the migration brief, §3).
 *
 * The negotiated flow prefixes the classic five-message ceremony with one round trip:
 *
 * ```
 * inviter                       joiner
 *   send SuiteOffer  ─────────────▶ recv, select
 *   recv ◀───────────── send SuiteAccept
 *   [classic ceremony, suite-routed, transcript v2]
 * ```
 *
 * The security model is deliberately two-stage. The checks in [SuiteNegotiator] are
 * *provisional* — correctness and pre-authentication hygiene. The negotiation only becomes
 * **authenticated** when the ceremony's code-keyed MACs verify over a transcript that embeds the
 * raw offer and accept frames byte for byte ([PairingTranscript] v2): an attacker who strips a
 * suite from either list, reorders it, lowers a policy floor, or swaps the selection produces
 * disagreeing transcripts on the two ends, and both MACs fail before any key is released or any
 * human is shown a SAS on a false premise. There is no retry: a failed negotiation aborts the
 * ceremony, and nothing in this protocol ever falls back to the legacy flow on its own.
 *
 * The legacy five-message flow (no offer, tag 1 first) remains the explicit Suite 1 flow, byte
 * for byte; a session built for one flow rejects the other's first tag.
 */
object SuiteNegotiator {

    /**
     * Starts the inviting side: builds the capability offer from everything [resolver] knows,
     * strongest first. Throws [org.layeredencryption.suite.UnsupportedSuiteException] if the
     * policy floor names a suite this device does not have — a local misconfiguration, caught
     * before anything is sent.
     */
    fun beginInviter(
        provider: CryptoProvider,
        resolver: SuiteResolver = SuiteRegistry,
        policy: PairingSuitePolicy = PairingSuitePolicy(),
        supported: List<SuiteId> = preferenceOrder(resolver),
    ): InviterNegotiation {
        resolver.require(policy.minimumSuite)
        require(supported.isNotEmpty()) { "A device must support at least one suite" }
        supported.forEach { resolver.require(it) }
        val offer = SuiteOffer(provider.randomBytes(NONCE_SIZE), supported, policy.minimumSuite)
        return InviterNegotiation(resolver, policy, supported, PairingWire.encode(offer))
    }

    /**
     * Runs the responding side against a received offer frame: selects per the rule below, and
     * returns the accept frame to send plus the [NegotiatedSuiteContext] for the ceremony.
     * Throws [PairingException] on a malformed offer or when no suite is acceptable — the
     * negotiated flow never auto-detects or answers a legacy hello.
     */
    fun respond(
        offerFrame: ByteArray,
        provider: CryptoProvider,
        resolver: SuiteResolver = SuiteRegistry,
        policy: PairingSuitePolicy = PairingSuitePolicy(),
        supported: List<SuiteId> = preferenceOrder(resolver),
    ): JoinerNegotiation {
        resolver.require(policy.minimumSuite)
        require(supported.isNotEmpty()) { "A device must support at least one suite" }
        supported.forEach { resolver.require(it) }
        val offer = PairingWire.decodeSuiteOffer(offerFrame)
        val selected = select(resolver, supported, policy.minimumSuite, offer.supportedSuites, offer.minimumSuite)
            ?: throw PairingException("No mutually acceptable suite — refusing to pair")
        val accept = SuiteAccept(provider.randomBytes(NONCE_SIZE), supported, policy.minimumSuite, selected.id)
        val acceptFrame = PairingWire.encode(accept)
        return JoinerNegotiation(
            NegotiatedSuiteContext(selected, offerFrame, acceptFrame, offer.supportedSuites.toSet(), resolver),
            acceptFrame,
        )
    }

    /**
     * The selection rule, recomputed identically by both sides (the migration brief's
     * "strongest mutually supported suite permitted by both policies"):
     *
     * 1. Candidates: ids advertised by *both* parties that this resolver actually has.
     * 2. Pick the highest [ProtocolSuite.strength]; ties break to the higher id. Strength is a
     *    frozen curated rank, deliberately not the offer's list order (a buggy peer preference
     *    must not pick weaker) and not the raw id (ids are chronological, not strength-ordered).
     * 3. Policy floors only *remove* — if the maximum fails either floor the answer is null,
     *    never "the next weaker one". A peer floor this resolver cannot rank is skipped; the
     *    peer enforces its own policy on its own end.
     */
    internal fun select(
        resolver: SuiteResolver,
        ours: Collection<SuiteId>,
        ourMinimum: SuiteId,
        theirs: Collection<SuiteId>,
        theirMinimum: SuiteId,
    ): ProtocolSuite? {
        val candidates = ours.intersect(theirs.toSet()).filter { resolver.contains(it) }
        if (candidates.isEmpty()) return null
        val selected = candidates.map { resolver.require(it) }
            .maxWith(compareBy({ it.strength }, { it.id.value }))
        if (selected.strength < resolver.require(ourMinimum).strength) return null
        if (resolver.contains(theirMinimum) && selected.strength < resolver.require(theirMinimum).strength) return null
        return selected
    }

    /** Everything [resolver] knows, strongest first (ties to the higher id) — the offer order. */
    internal fun preferenceOrder(resolver: SuiteResolver): List<SuiteId> =
        resolver.known.sortedWith(
            compareByDescending<SuiteId> { resolver.require(it).strength }.thenByDescending { it.value },
        )

    internal const val NONCE_SIZE = 32
    internal const val MAX_SUITES = 32
}

/** The inviter's half-open negotiation: the offer to send, and the accept validation. */
class InviterNegotiation internal constructor(
    private val resolver: SuiteResolver,
    private val policy: PairingSuitePolicy,
    private val supported: List<SuiteId>,
    offerFrame: ByteArray,
) {
    private val _offerFrame = offerFrame.copyOf()

    /** The exact tag-6 bytes to send — the same bytes the transcript will bind. */
    val offerFrame: ByteArray get() = _offerFrame.copyOf()

    /**
     * Validates a received accept frame and mints the ceremony context. Every reject is a
     * [PairingException]; the ferry closes the channel and no session is ever constructed:
     * malformed frame or version; structurally invalid list; a selection this device did not
     * offer or does not know (unknown suites fail closed); a selection the responder does not
     * itself claim to support; or a selection that disagrees with this device's own
     * recomputation of [SuiteNegotiator.select] — which also enforces both policy floors.
     */
    fun onAccept(acceptFrame: ByteArray): NegotiatedSuiteContext {
        val accept = PairingWire.decodeSuiteAccept(acceptFrame)
        val selected = accept.selectedSuite
        if (selected !in supported) {
            throw PairingException("Responder selected suite ${selected.value}, which this device did not offer")
        }
        if (!resolver.contains(selected)) {
            throw PairingException("Responder selected unknown suite ${selected.value}")
        }
        if (selected !in accept.supportedSuites) {
            throw PairingException("Responder selected suite ${selected.value} it does not itself advertise")
        }
        val recomputed = SuiteNegotiator.select(
            resolver, supported, policy.minimumSuite, accept.supportedSuites, accept.minimumSuite,
        ) ?: throw PairingException("No mutually acceptable suite — refusing to pair")
        if (recomputed.id != selected) {
            throw PairingException(
                "Responder selected suite ${selected.value} where the negotiation rule requires ${recomputed.id.value}",
            )
        }
        return NegotiatedSuiteContext(recomputed, _offerFrame, acceptFrame, accept.supportedSuites.toSet(), resolver)
    }
}

/** The joiner's completed negotiation: the accept to send and the ceremony context. */
class JoinerNegotiation internal constructor(
    val context: NegotiatedSuiteContext,
    acceptFrame: ByteArray,
) {
    private val _acceptFrame = acceptFrame.copyOf()

    /** The exact tag-7 bytes to send — the same bytes the transcript will bind. */
    val acceptFrame: ByteArray get() = _acceptFrame.copyOf()
}

/**
 * A device's negotiation policy. [minimumSuite] is a floor by strength rank: anything ranked
 * below it is unacceptable for new pairings. Applications hardening over time raise the floor;
 * they can also persist the strongest suite a peer has ever advertised
 * ([NegotiatedSuiteContext.peerSupported]) and refuse a later weaker offer — the cross-ceremony
 * half of downgrade resistance, which necessarily lives above the protocol.
 */
class PairingSuitePolicy(val minimumSuite: SuiteId = SuiteId.LEP_HYBRID_2026)

/**
 * An accepted negotiation, minted only by [SuiteNegotiator] — the ceremony's proof that a suite
 * selection happened and what its exact wire bytes were. [PairingTranscript] binds
 * [offerFrame]/[acceptFrame] verbatim, so the MACs authenticate the negotiation retroactively.
 */
class NegotiatedSuiteContext internal constructor(
    val suite: ProtocolSuite,
    offerFrame: ByteArray,
    acceptFrame: ByteArray,
    /** Everything the peer advertised — persist the strongest for cross-ceremony pinning. */
    val peerSupported: Set<SuiteId>,
    /** The resolver the negotiation ran under; the ceremony's suite lookups use the same one. */
    internal val resolver: SuiteResolver,
) {
    private val _offerFrame = offerFrame.copyOf()
    private val _acceptFrame = acceptFrame.copyOf()

    internal val offerFrame: ByteArray get() = _offerFrame.copyOf()
    internal val acceptFrame: ByteArray get() = _acceptFrame.copyOf()

    init {
        // Phase 1 wire formats keep Suite 1's field sizes; the ceremony's fixed-width codecs
        // depend on it. A differently-sized suite needs the versioned message formats reserved
        // for the next migration phase — fail fast here rather than misparse later.
        require(
            suite.kem.publicKeySize == XWing.PUBLIC_KEY_SIZE &&
                suite.kem.ciphertextSize == XWing.CIPHERTEXT_SIZE &&
                suite.signature.publicKeySize == HybridSignature.PUBLIC_KEY_SIZE &&
                suite.signature.signatureSize == HybridSignature.SIGNATURE_SIZE,
        ) { "Suite ${suite.id.value} is not size-compatible with the current wire formats" }
    }
}

/** The negotiated flow's first frame: what the inviter can do, and its policy floor. */
class SuiteOffer(
    nonce: ByteArray,
    supportedSuites: List<SuiteId>,
    val minimumSuite: SuiteId,
) {
    private val _nonce = nonce.copyOf()
    private val _supportedSuites = supportedSuites.toList()

    val nonce: ByteArray get() = _nonce.copyOf()

    /** Sender preference order, strongest first. Authenticated via the transcript, non-semantic. */
    val supportedSuites: List<SuiteId> get() = _supportedSuites

    init {
        require(nonce.size == SuiteNegotiator.NONCE_SIZE) { "Negotiation nonce must be ${SuiteNegotiator.NONCE_SIZE} bytes" }
        require(supportedSuites.isNotEmpty()) { "A suite offer must name at least one suite" }
        require(supportedSuites.size <= SuiteNegotiator.MAX_SUITES) { "More than ${SuiteNegotiator.MAX_SUITES} suites offered" }
        require(supportedSuites.toSet().size == supportedSuites.size) { "Duplicate suite in offer" }
    }
}

/** The negotiated flow's second frame: the responder's capabilities, floor, and selection. */
class SuiteAccept(
    nonce: ByteArray,
    supportedSuites: List<SuiteId>,
    val minimumSuite: SuiteId,
    val selectedSuite: SuiteId,
) {
    private val _nonce = nonce.copyOf()
    private val _supportedSuites = supportedSuites.toList()

    val nonce: ByteArray get() = _nonce.copyOf()
    val supportedSuites: List<SuiteId> get() = _supportedSuites

    init {
        require(nonce.size == SuiteNegotiator.NONCE_SIZE) { "Negotiation nonce must be ${SuiteNegotiator.NONCE_SIZE} bytes" }
        require(supportedSuites.isNotEmpty()) { "A suite accept must name at least one suite" }
        require(supportedSuites.size <= SuiteNegotiator.MAX_SUITES) { "More than ${SuiteNegotiator.MAX_SUITES} suites advertised" }
        require(supportedSuites.toSet().size == supportedSuites.size) { "Duplicate suite in accept" }
    }
}

