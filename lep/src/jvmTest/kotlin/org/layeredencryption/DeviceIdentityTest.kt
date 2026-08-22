package org.layeredencryption

import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.suite.FakeSuites
import org.layeredencryption.suite.Suite1
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Versioned device identities (the migration brief §2): self-describing, suite-sized, bound
 * under the identity's own suite, and fail-closed on anything this build does not know.
 */
class DeviceIdentityTest {

    private val provider = BouncyCastleCryptoProvider()
    private val fake = FakeSuites.fakeSuite()
    private val resolver = FakeSuites.resolverWith(fake)

    @Test
    fun generatedIdentity_roundTripsAndVerifiesUnderItsSuite() {
        val keys = DeviceKeys.generate(provider, fake)
        val bytes = keys.identity.serialise()

        assertEquals(FakeSuites.FAKE_ID, keys.identity.suiteId)
        val decoded = DeviceIdentity.deserialise(bytes, resolver)
        assertEquals(FakeSuites.FAKE_ID, decoded.suiteId)
        assertContentEquals(bytes, decoded.serialise(), "must re-serialise byte-exactly")
        assertTrue(decoded.verifyBinding(provider, resolver = resolver))
    }

    @Test
    fun serialisedSize_isFrozenForSuite1() {
        // 6 length-prefixed fields: version(1), suiteId(2), signing(1984), x25519(32),
        // kem(1216), signature(3373) — 11 bytes more than a v1 identity's 6621.
        assertEquals(6632, DeviceIdentity.serialisedSize(Suite1))
        assertEquals(6632, DeviceKeys.generate(provider, Suite1).identity.serialise().size)
    }

    @Test
    fun binding_genuinelyUsesTheIdentitysOwnSuite() {
        // The domain-shifted suite signs a prefixed message: an identity minted under it must
        // verify with the shifted resolver and FAIL with a resolver that maps the same id to
        // plain delegation — proving the binding routes through the suite, not just the label.
        val shifted = FakeSuites.domainShiftedFakeSuite()
        val shiftedResolver = FakeSuites.resolverWith(shifted)
        val identity = DeviceKeys.generate(provider, shifted).identity

        assertTrue(identity.verifyBinding(provider, resolver = shiftedResolver))
        val misrouted = FakeSuites.resolverWith(FakeSuites.fakeSuite(id = FakeSuites.SHIFTED_ID))
        assertFalse(identity.verifyBinding(provider, resolver = misrouted))
    }

    @Test
    fun hostileBytes_failClosed() {
        val good = DeviceKeys.generate(provider, fake).identity.serialise()

        assertFailsWith<IllegalArgumentException>("trailing byte") {
            DeviceIdentity.deserialise(good + 0, resolver)
        }
        val versioned = good.copyOf().also { it[4] = 3 } // the framed formatVersion byte
        assertFailsWith<IllegalArgumentException>("unknown format version") {
            DeviceIdentity.deserialise(versioned, resolver)
        }
        // The production registry does not know the test suite: unknown suites die before any
        // key material is believed.
        assertFailsWith<IllegalArgumentException>("unknown suite") {
            DeviceIdentity.deserialise(good)
        }
    }
}
