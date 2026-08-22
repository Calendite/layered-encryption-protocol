package org.layeredencryption

import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.identity.KeyTransition
import org.layeredencryption.suite.FakeSuites
import org.layeredencryption.suite.Suite1
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * KeyTransition (the migration brief §2): the dual-signed continuity proof between a legacy
 * identity and its suited successor. Every partial proof — a missing signature leg, a swapped
 * identity, a broken binding — must fail, because each is exactly the splice the artifact
 * exists to prevent.
 */
class KeyTransitionTest {

    private val provider = BouncyCastleCryptoProvider()
    private val fake = FakeSuites.fakeSuite()
    private val resolver = FakeSuites.resolverWith(fake)

    private val oldKeys = DeviceKeys.generate(provider)
    private val newKeys = DeviceKeys.generate(provider, fake)

    @Test
    fun transition_verifiesAndRoundTripsByteExactly() {
        val transition = KeyTransition.create(provider, oldKeys, newKeys, resolver = resolver)
        assertTrue(transition.verify(provider, resolver = resolver))

        val bytes = transition.serialise()
        val decoded = KeyTransition.deserialise(bytes, resolver)
        assertContentEquals(bytes, decoded.serialise(), "must re-serialise byte-exactly")
        assertTrue(decoded.verify(provider, resolver = resolver))
    }

    @Test
    fun sameSuiteTransition_isIdentityRekeying() {
        // A fresh successor under the same suite: continuity for identity re-keying, provable
        // with the production registry alone.
        val successor = DeviceKeys.generate(provider)
        val transition = KeyTransition.create(provider, oldKeys, successor)
        assertTrue(transition.verify(provider))
    }

    @Test
    fun swappedSuccessorIdentity_failsBothWays() {
        val transition = KeyTransition.create(provider, oldKeys, newKeys, resolver = resolver)
        val impostor = DeviceKeys.generate(provider, fake)

        // Splicing a different successor under the honest signatures: the signed message names
        // the real successor, so both legs fail over the spliced one.
        val spliced = KeyTransition(
            oldKeys.identity, impostor.identity, transition.signatureByOld, transition.signatureByNew,
        )
        assertFalse(spliced.verify(provider, resolver = resolver))

        // And a transition the impostor mints itself lacks the old key's attestation.
        val selfMade = KeyTransition(
            oldKeys.identity, impostor.identity,
            Suite1.signature.sign(
                provider, impostor.signingPrivateKey,
                KeyTransition.transitionMessage(oldKeys.identity, impostor.identity),
            ),
            fake.signature.sign(
                provider, impostor.signingPrivateKey,
                KeyTransition.transitionMessage(oldKeys.identity, impostor.identity),
            ),
        )
        assertFalse(selfMade.verify(provider, resolver = resolver))
    }

    @Test
    fun missingEitherSignatureLeg_fails() {
        val message = KeyTransition.transitionMessage(oldKeys.identity, newKeys.identity)
        val byOld = Suite1.signature.sign(provider, oldKeys.signingPrivateKey, message)
        val byNew = fake.signature.sign(provider, newKeys.signingPrivateKey, message)
        val stranger = DeviceKeys.generate(provider)

        val forgedOld = KeyTransition(
            oldKeys.identity, newKeys.identity,
            Suite1.signature.sign(provider, stranger.signingPrivateKey, message), byNew,
        )
        assertFalse(forgedOld.verify(provider, resolver = resolver), "the old key must attest")

        val forgedNew = KeyTransition(
            oldKeys.identity, newKeys.identity,
            byOld, fake.signature.sign(provider, stranger.signingPrivateKey, message),
        )
        assertFalse(forgedNew.verify(provider, resolver = resolver), "the new key must attest")
    }

    @Test
    fun brokenSuccessorBinding_fails() {
        // A successor whose own binding does not verify is rejected before the transition
        // signatures are even considered.
        val tamperedIdentity = DeviceIdentity(
            newKeys.identity.suiteId,
            newKeys.identity.signingPublicKey,
            newKeys.identity.x25519IdentityPublicKey,
            newKeys.identity.xWingPublicKey,
            newKeys.identity.bindingSignature.also { it[0] = (it[0].toInt() xor 1).toByte() },
        )
        val message = KeyTransition.transitionMessage(oldKeys.identity, tamperedIdentity)
        val transition = KeyTransition(
            oldKeys.identity, tamperedIdentity,
            Suite1.signature.sign(provider, oldKeys.signingPrivateKey, message),
            fake.signature.sign(provider, newKeys.signingPrivateKey, message),
        )
        assertFalse(transition.verify(provider, resolver = resolver))
    }

    @Test
    fun hostileBytes_failClosed() {
        val good = KeyTransition.create(provider, oldKeys, newKeys, resolver = resolver).serialise()

        assertFailsWith<IllegalArgumentException>("trailing byte") {
            KeyTransition.deserialise(good + 0, resolver)
        }
        val versioned = good.copyOf().also { it[4] = 2 }
        assertFailsWith<IllegalArgumentException>("unknown format version") {
            KeyTransition.deserialise(versioned, resolver)
        }
        // The embedded successor names the test suite: the production registry fails closed.
        assertFailsWith<IllegalArgumentException>("unknown successor suite") {
            KeyTransition.deserialise(good)
        }
    }
}
