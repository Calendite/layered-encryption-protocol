package org.layeredencryption

import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.InMemoryFreshnessStore
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingFerry
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotNull

/**
 * The README's code snippets, compiled and executed (LEP-08f/g): if the README names an API that
 * does not exist or whose signature drifted, this file stops compiling, so the documentation
 * cannot silently rot again — the assessment caught it advertising `PairingFerry.host/join` and a
 * `LaneEnvelope` overload that never existed.
 */
class ReadmeExamplesTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    @Test
    fun cascadeSnippet() {
        val masterKey = provider.randomBytes(32)
        val myBytes = "whatever the app means by this".encodeToByteArray()
        val context = "context".encodeToByteArray()

        val sealed = Cascade.seal(provider, masterKey, plaintext = myBytes, aad = context)
        val opened = Cascade.open(provider, masterKey, sealed, aad = context)
        assertContentEquals(myBytes, opened)
    }

    @Test
    fun envelopeSnippet() {
        val masterKey = provider.randomBytes(32)
        val myBytes = "an op".encodeToByteArray()

        val keys = EpochKeys.founding(masterKey)
        val freshness = InMemoryFreshnessStore()
        val envelope = LaneEnvelope.seal(provider, keys, "context-1", "lane-1", 1, plaintext = myBytes)
        val bytes = envelope.openAndValidate(provider, keys, "context-1", "lane-1", freshness) { it }
        assertContentEquals(myBytes, bytes)
    }

    @Test
    fun namespaceSnippet() {
        val namespace = ProtocolNamespace("mycoolapp")
        val key = provider.randomBytes(32)
        val plaintext = "ns".encodeToByteArray()
        val aad = ByteArray(0)

        val sealed = Cascade.seal(provider, key, plaintext, aad, namespace)
        assertContentEquals(plaintext, Cascade.open(provider, key, sealed, aad, namespace))
    }

    @Test
    fun pairingFerrySnippetNamesRealApis() {
        // Compile-time check that the exact entry points the README shows exist with the shown
        // shapes; the full ceremony over a channel is exercised by InspectorTest/ContextIdTest.
        // Every ceremony negotiates its suite first, so the ferry takes the device and code and
        // builds the sessions itself.
        val runInviter = PairingFerry::runInviter
        val runJoiner = PairingFerry::runJoiner
        assertNotNull(runInviter)
        assertNotNull(runJoiner)
    }
}
