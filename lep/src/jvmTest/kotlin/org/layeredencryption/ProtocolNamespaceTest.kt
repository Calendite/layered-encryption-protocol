package org.layeredencryption

import org.layeredencryption.pairing.ContextId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The namespace decides every HKDF label and transcript prefix, so two properties matter and
 * nothing else does: the default must reproduce the shipped bytes exactly, and a different vendor
 * must produce different keys.
 */
class ProtocolNamespaceTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    /**
     * The frozen labels, written out literally rather than built from the namespace.
     *
     * Devices already paired in the field derived their keys from these exact bytes. If this test
     * fails, the change under it does not "rename a label"; it orphans every existing pairing.
     *
     * The `v2` entries are two separate breaks. Membership entries and invite bundles moved from
     * Ed25519 alone to Ed25519 + ML-DSA-65. And `sas-commitment` is new: the inviter now commits to
     * a nonce before it can see the joiner's ciphertext, without which the SAS could be ground to
     * any chosen value.
     *
     * `v3/device-identity` and `v1/member-key-wrap` arrived together. The identity gained a
     * long-term X-Wing key so a rotated context key can be handed to each remaining member, which
     * is what makes removing somebody more than a gesture.
     */
    private val frozen = mapOf(
        "v1/layer-chacha" to "calendite/v1/layer-chacha",
        "v1/layer-aes" to "calendite/v1/layer-aes",
        "v1/transcript" to "calendite/v1/transcript",
        "v1/pairing" to "calendite/v1/pairing",
        "v1/code-secret" to "calendite/v1/code-secret",
        "v2/sas-commitment" to "calendite/v2/sas-commitment",
        "v3/device-identity" to "calendite/v3/device-identity",
        "v1/member-key-wrap" to "calendite/v1/member-key-wrap",
        "v2/membership" to "calendite/v2/membership",
        "v2/invite-bundle" to "calendite/v2/invite-bundle",
        "v1/transcript-async" to "calendite/v1/transcript-async",
        "v1/pairing-async" to "calendite/v1/pairing-async",
        // New with the A2 invite link (LEP-01): keys the cheap link-possession MAC the inviter
        // checks before doing any expensive cryptography on an async response.
        "v1/async-link-auth" to "calendite/v1/async-link-auth",
        "rendezvous/v1" to "calendite/rendezvous/v1",
        "rendezvous-async/v1" to "calendite/rendezvous-async/v1",
        // Was "calendar-id/v1" for a long time, and the odd spelling was kept deliberately: a
        // rename sweep had silently changed it once, and the first version of this test was
        // written from the renamed state, so it enshrined the drift instead of catching it.
        // v2 changes the derivation itself (genesis hash rather than master key), which orphans
        // pairings regardless, so the spelling finally comes along for the ride.
        "context-id/v2" to "calendite/context-id/v2",
    )

    @Test
    fun `the default namespace reproduces every shipped label byte for byte`() {
        for ((suffix, expected) in frozen) {
            assertContentEquals(
                expected.encodeToByteArray(),
                ProtocolNamespace.Default.label(suffix),
                "label $suffix drifted, which would invalidate existing pairings",
            )
        }
    }

    /**
     * The expectations above are hand-written, so on their own they only prove that
     * [ProtocolNamespace.label] still concatenates. This is the half with teeth: it checks the
     * literal list against the labels the protocol actually uses, so a label that is added,
     * removed or edited in [ProtocolLabels] fails here until someone updates this list on purpose.
     *
     * Without it the freeze is theatre. That is not hypothetical — an earlier version of this test
     * kept its own copy of the list and could not tell when the code moved out from under it.
     */
    @Test
    fun `the literal list covers exactly the labels the protocol uses`() {
        assertEquals(
            ProtocolLabels.ALL,
            frozen.keys,
            "the frozen list and the labels in use have diverged; reconcile them deliberately, " +
                "remembering that editing a shipped label orphans existing pairings",
        )
    }

    @Test
    fun `a different vendor derives different keys from the same secret`() {
        val masterKey = provider.randomBytes(32)
        val plaintext = "the same bytes".encodeToByteArray()

        val ours = Cascade.seal(provider, masterKey, plaintext, namespace = ProtocolNamespace.Default)
        val theirs = Cascade.seal(provider, masterKey, plaintext, namespace = ProtocolNamespace("someoneelse"))

        // Not merely different ciphertext (nonces differ anyway) — the other deployment's keys
        // cannot open ours at all. Two applications sharing this library must not share a key
        // space, even by accident.
        assertFailsWith<CryptoException> {
            Cascade.open(provider, masterKey, theirs, namespace = ProtocolNamespace.Default)
        }
        assertFailsWith<CryptoException> {
            Cascade.open(provider, masterKey, ours, namespace = ProtocolNamespace("someoneelse"))
        }
    }

    @Test
    fun `a namespace round-trips its own data`() {
        val namespace = ProtocolNamespace("mycoolapp")
        val masterKey = provider.randomBytes(32)
        val plaintext = "hello from another app".encodeToByteArray()

        val sealed = Cascade.seal(provider, masterKey, plaintext, namespace = namespace)

        assertContentEquals(plaintext, Cascade.open(provider, masterKey, sealed, namespace = namespace))
    }

    @Test
    fun `derived identifiers are namespace-separated too`() {
        val masterKey = provider.randomBytes(32)

        val ours = ContextId.derive(provider, masterKey)
        val theirs = ContextId.derive(provider, masterKey, ProtocolNamespace("someoneelse"))

        assertNotEquals(ours, theirs, "the same secret must not name the same context in two deployments")
        assertEquals(ours, ContextId.derive(provider, masterKey), "and derivation stays deterministic")
    }

    @Test
    fun `a vendor token must be one usable path segment`() {
        assertFailsWith<IllegalArgumentException> { ProtocolNamespace("") }
        assertFailsWith<IllegalArgumentException> { ProtocolNamespace("   ") }
        // A slash would silently reshape every label into a different path.
        assertFailsWith<IllegalArgumentException> { ProtocolNamespace("my/app") }
        assertTrue(ProtocolNamespace("my-app_2").vendor == "my-app_2")
    }
}
