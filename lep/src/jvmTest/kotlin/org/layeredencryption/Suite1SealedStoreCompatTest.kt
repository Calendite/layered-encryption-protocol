package org.layeredencryption

import org.layeredencryption.invite.AsyncInviteState
import org.layeredencryption.storage.FileBackedFreshnessStore
import org.layeredencryption.storage.FileBackedInviteStore
import org.layeredencryption.storage.StoreCorruptionException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The sealed-state-file half of the Suite 1 freeze: files written by the shipped
 * `lep-sealed-store/v1` format must still load, authenticate, and decrypt to the same state.
 *
 * These are the one artifact family that is *not* byte-reproducible — every commit draws fresh
 * cascade nonces and bumps the revision — so the fixtures prove parse + header/AAD binding +
 * decryption, not re-encoding (docs/POST_QUANTUM_HARDENING_AND_MIGRATION.md §8). jvmTest because
 * the storage layer lives in jvmCommonMain.
 */
class Suite1SealedStoreCompatTest {

    private val provider = BouncyCastleCryptoProvider()

    private fun materialise(bytes: ByteArray): Path {
        val dir = Files.createTempDirectory("suite1-store-compat")
        dir.toFile().deleteOnExit()
        return dir.resolve("fixture.store").also { Files.write(it, bytes) }
    }

    @Test
    fun sealedStoreMagic_isFrozen() {
        assertContentEquals("lep-sealed-store/v1".encodeToByteArray(), org.layeredencryption.storage.SealedStateFile.MAGIC)
    }

    @Test
    fun inviteStoreFile_loadsDecryptsAndMatchesTheFrozenRecord() {
        val store = FileBackedInviteStore.withoutRollbackDetection(
            materialise(Suite1Fixtures.sealedInviteStoreFile()), provider, Suite1Fixtures.sealedStoreKey(),
        )
        val record = store.all().single()
        assertContentEquals(Suite1Fixtures.inviteRidAsync(), record.ridAsync)
        assertContentEquals(Suite1Fixtures.inviteSecret(), record.secret)
        assertContentEquals(Suite1Fixtures.inviteKemPublicKey(), record.inviteXWingPublicKey)
        assertContentEquals(Suite1Fixtures.inviteKemPrivateKey(), record.inviteXWingPrivateKey)
        assertContentEquals(Suite1Fixtures.sealedStoreMasterKey(), record.masterKey)
        assertEquals(Suite1Fixtures.inviteExpiryEpochSeconds, record.expiryEpochSeconds)
        assertEquals(AsyncInviteState.PENDING, record.state)
    }

    @Test
    fun freshnessStoreFile_loadsDecryptsAndEnforcesTheFrozenWatermark() {
        val store = FileBackedFreshnessStore.withoutRollbackDetection(
            materialise(Suite1Fixtures.sealedFreshnessStoreFile()), provider, Suite1Fixtures.sealedStoreKey(),
        )
        val context = Suite1Fixtures.envelopeContextId
        val lane = Suite1Fixtures.envelopeLane
        // The fixture accepted seq=7, epoch=1: the watermark must have survived the round trip.
        assertFalse(store.wouldAccept(context, lane, seq = 7, epoch = 1), "the accepted sequence is not fresh")
        assertFalse(store.wouldAccept(context, lane, seq = 8, epoch = 0), "a retired epoch is not fresh")
        assertTrue(store.wouldAccept(context, lane, seq = 8, epoch = 1), "the next sequence is fresh")
        assertTrue(store.wouldAccept("another-context", lane, seq = 1, epoch = 0), "other lanes are unaffected")
    }

    @Test
    fun tamperedHeader_failsAuthentication() {
        // The cleartext header is bound as cascade AAD; flipping its revision byte parses fine
        // (magic and kind untouched) but must fail authentication when the cascade opens.
        val tampered = Suite1Fixtures.sealedFreshnessStoreFile()
        val lastHeaderByte = 4 + bytesToInt(tampered, 0) - 1 // the revision's low byte
        tampered[lastHeaderByte] = (tampered[lastHeaderByte].toInt() xor 0x01).toByte()
        val store = FileBackedFreshnessStore.withoutRollbackDetection(
            materialise(tampered), provider, Suite1Fixtures.sealedStoreKey(),
        )
        assertFailsWith<StoreCorruptionException> {
            store.wouldAccept(Suite1Fixtures.envelopeContextId, Suite1Fixtures.envelopeLane, 8, 1)
        }
    }
}
