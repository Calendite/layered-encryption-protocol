package org.layeredencryption

import org.layeredencryption.invite.AsyncInviteState
import org.layeredencryption.invite.PendingInvite
import org.layeredencryption.storage.FileBackedFreshnessStore
import org.layeredencryption.storage.FileBackedInviteStore
import org.layeredencryption.storage.FileRevisionWitness
import org.layeredencryption.storage.StoreCorruptionException
import org.layeredencryption.storage.StoreRollbackException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.concurrent.CyclicBarrier
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * RT-02/RT-03: what the sealed-file stores must survive that the in-memory references cannot —
 * restarts, torn writes, corruption, wrong keys, restored stale snapshots, and instance races
 * over one file.
 */
class SealedFileStoreDurabilityTest {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()
    private val key = provider.randomBytes(32)

    private fun tempDir(): Path = Files.createTempDirectory("lep-sealed-store")

    private fun invite(seed: Int): PendingInvite = PendingInvite(
        ridAsync = ByteArray(32) { (seed + it).toByte() },
        secret = ByteArray(32) { (seed * 2 + it).toByte() },
        inviteXWingPublicKey = ByteArray(1216),
        inviteXWingPrivateKey = ByteArray(32) { (seed * 3 + it).toByte() },
        masterKey = ByteArray(32) { (seed * 5 + it).toByte() },
        expiryEpochSeconds = 1_000_000L,
        state = AsyncInviteState.PENDING,
        suiteId = org.layeredencryption.suite.SuiteId(1u),
    )

    // ── Restart survival ─────────────────────────────────────────────────────────────────────

    @Test
    fun inviteRecordsAndTombstonesSurviveARestart() {
        val file = tempDir().resolve("invites.sealed")
        val stored = invite(1)

        val before = FileBackedInviteStore.withoutRollbackDetection(file, provider, key)
        before.put(stored)
        before.put(invite(9))
        assertTrue(before.consume(invite(9).ridAsyncHex))

        // "Restart": a brand-new instance over the same file.
        val after = FileBackedInviteStore.withoutRollbackDetection(file, provider, key)
        val loaded = after.get(stored.ridAsyncHex) ?: error("a pending record must survive restart")
        assertContentEquals(stored.secret, loaded.secret)
        assertContentEquals(stored.masterKey, loaded.masterKey)

        // The tombstone survived too: the consumed id can be neither re-put nor re-consumed.
        assertFailsWith<IllegalStateException> { after.put(invite(9)) }
        assertFalse(after.consume(invite(9).ridAsyncHex))
        assertNull(after.get(invite(9).ridAsyncHex))
    }

    @Test
    fun freshnessWatermarksSurviveARestart() {
        val file = tempDir().resolve("freshness.sealed")

        val before = FileBackedFreshnessStore.withoutRollbackDetection(file, provider, key)
        assertTrue(before.accept("ctx", "lane", seq = 5, epoch = 2))

        val after = FileBackedFreshnessStore.withoutRollbackDetection(file, provider, key)
        assertFalse(after.accept("ctx", "lane", seq = 5, epoch = 2), "a replay must stay refused across restart")
        assertFalse(after.accept("ctx", "lane", seq = 4, epoch = 2), "a regressed sequence must stay refused")
        assertFalse(after.accept("ctx", "lane", seq = 6, epoch = 1), "a regressed epoch must stay refused")
        assertFalse(after.wouldAccept("ctx", "lane", seq = 5, epoch = 2))
        assertTrue(after.accept("ctx", "lane", seq = 6, epoch = 2))
    }

    // ── Torn writes, corruption, wrong keys ──────────────────────────────────────────────────

    @Test
    fun aLeftoverTempFileFromACrashIsIgnoredAndCleaned() {
        val file = tempDir().resolve("invites.sealed")
        val store = FileBackedInviteStore.withoutRollbackDetection(file, provider, key)
        store.put(invite(1))

        // Simulate dying mid-write: garbage staged where the next commit would rename from.
        val temp = file.resolveSibling(file.fileName.toString() + ".tmp")
        Files.write(temp, ByteArray(100) { 0x41 })

        val reopened = FileBackedInviteStore.withoutRollbackDetection(file, provider, key)
        assertEquals(1, reopened.all().size, "the last committed state is intact")
        assertFalse(Files.exists(temp), "the torn staging file is deleted, not trusted")
    }

    @Test
    fun aFlippedByteFailsClosed() {
        val file = tempDir().resolve("freshness.sealed")
        val store = FileBackedFreshnessStore.withoutRollbackDetection(file, provider, key)
        assertTrue(store.accept("ctx", "lane", 1, 0))

        val bytes = Files.readAllBytes(file)
        bytes[bytes.size / 2] = (bytes[bytes.size / 2].toInt() xor 1).toByte()
        Files.write(file, bytes)

        assertFailsWith<StoreCorruptionException> { store.accept("ctx", "lane", 2, 0) }
        assertFailsWith<StoreCorruptionException> { store.wouldAccept("ctx", "lane", 2, 0) }
    }

    @Test
    fun theWrongKeyFailsClosed() {
        val file = tempDir().resolve("invites.sealed")
        FileBackedInviteStore.withoutRollbackDetection(file, provider, key).put(invite(1))

        val wrongKey = FileBackedInviteStore.withoutRollbackDetection(file, provider, provider.randomBytes(32))
        assertFailsWith<StoreCorruptionException> { wrongKey.all() }
    }

    @Test
    fun truncationTrailingBytesAndOversizeAllFailClosed() {
        val file = tempDir().resolve("freshness.sealed")
        val store = FileBackedFreshnessStore.withoutRollbackDetection(file, provider, key)
        assertTrue(store.accept("ctx", "lane", 1, 0))
        val intact = Files.readAllBytes(file)

        Files.write(file, intact.copyOf(intact.size - 3))
        assertFailsWith<StoreCorruptionException> { store.wouldAccept("ctx", "lane", 2, 0) }

        Files.write(file, intact + ByteArray(5))
        assertFailsWith<StoreCorruptionException> { store.wouldAccept("ctx", "lane", 2, 0) }

        Files.write(file, ByteArray(17 * 1024 * 1024))
        assertFailsWith<StoreCorruptionException> { store.wouldAccept("ctx", "lane", 2, 0) }

        // The checks reject broken bytes, not the store: the intact bytes still work.
        Files.write(file, intact)
        assertFalse(store.wouldAccept("ctx", "lane", 1, 0))
        assertTrue(store.wouldAccept("ctx", "lane", 2, 0))
    }

    @Test
    fun aWrongLengthAtRestKeyIsRefusedAtConstruction() {
        assertFailsWith<IllegalArgumentException> {
            FileBackedFreshnessStore.withoutRollbackDetection(tempDir().resolve("f.sealed"), provider, provider.randomBytes(16))
        }
    }

    // ── Rollback evidence ────────────────────────────────────────────────────────────────────

    @Test
    fun aRestoredStaleSnapshotIsDetected() {
        val directory = tempDir()
        val file = directory.resolve("freshness.sealed")
        val witness = FileRevisionWitness(directory.resolve("witness"), provider, key)

        val store = FileBackedFreshnessStore(file, provider, key, witness)
        assertTrue(store.accept("ctx", "lane", 1, 0))
        val staleSnapshot = Files.readAllBytes(file)
        assertTrue(store.accept("ctx", "lane", 2, 0))

        // The attack: restore the snapshot taken before seq=2 was accepted, which would silently
        // re-enable its replay. The witness makes it loud instead.
        Files.write(file, staleSnapshot)
        assertFailsWith<StoreRollbackException> { store.accept("ctx", "lane", 2, 0) }
    }

    @Test
    fun aDeletedStoreWithAWitnessFloorIsDetected() {
        val directory = tempDir()
        val file = directory.resolve("invites.sealed")
        val witness = FileRevisionWitness(directory.resolve("witness"), provider, key)

        val store = FileBackedInviteStore(file, provider, key, witness)
        store.put(invite(1))
        Files.delete(file)

        assertFailsWith<StoreRollbackException> { store.all() }
    }

    @Test
    fun aRestoredSnapshotOfInvitesCannotResurrectAConsumedInvite() {
        val directory = tempDir()
        val file = directory.resolve("invites.sealed")
        val witness = FileRevisionWitness(directory.resolve("witness"), provider, key)

        val store = FileBackedInviteStore(file, provider, key, witness)
        store.put(invite(1))
        val pendingSnapshot = Files.readAllBytes(file)
        assertTrue(store.consume(invite(1).ridAsyncHex))

        Files.write(file, pendingSnapshot)
        assertFailsWith<StoreRollbackException> { store.get(invite(1).ridAsyncHex) }
    }

    // ── Instance races over one file ─────────────────────────────────────────────────────────

    @Test
    fun consumeIsSingleWinnerAcrossInstancesSharingTheFile() {
        val file = tempDir().resolve("invites.sealed")
        FileBackedInviteStore.withoutRollbackDetection(file, provider, key).put(invite(1))
        val ridHex = invite(1).ridAsyncHex

        val instances = List(4) { FileBackedInviteStore.withoutRollbackDetection(file, provider, key) }
        val barrier = CyclicBarrier(instances.size)
        val wins = instances.map { store ->
            var won = false
            thread { barrier.await(); won = store.consume(ridHex) } to { won }
        }
        wins.forEach { (t, _) -> t.join() }
        assertEquals(1, wins.count { (_, won) -> won() }, "exactly one instance may win the claim gate")
    }

    /**
     * The delivery-ordering contract (6ddd7e4 retest, finding 2), across store *instances*: two
     * different sequences racing `deliverIfFresh` over one file may end 1-then-2, or 2 with 1
     * refused — never 1 delivered after 2. The OS file lock is what serializes the decision.
     */
    @Test
    fun aStaleSequenceIsNeverDeliveredAfterANewerOneAcrossInstances() {
        repeat(10) {
            val file = tempDir().resolve("freshness.sealed")
            val instances = List(2) { FileBackedFreshnessStore.withoutRollbackDetection(file, provider, key) }
            val delivered = java.util.Collections.synchronizedList(mutableListOf<Int>())
            val barrier = CyclicBarrier(2)
            instances.mapIndexed { index, store ->
                val seq = index + 1
                thread {
                    barrier.await()
                    store.deliverIfFresh("ctx", "lane", seq, 0) { delivered += seq }
                }
            }.forEach { it.join() }

            assertTrue(
                delivered == listOf(1, 2) || delivered == listOf(2),
                "sequence 1 must never be delivered after sequence 2, got $delivered",
            )
        }
    }

    @Test
    fun aFailedDeliveryTransactionRecordsNothingDurably() {
        val file = tempDir().resolve("freshness.sealed")
        val store = FileBackedFreshnessStore.withoutRollbackDetection(file, provider, key)

        assertFailsWith<IllegalStateException> {
            store.deliverIfFresh("ctx", "lane", 1, 0) { error("the application died mid-delivery") }
        }

        // Nothing was committed: the same sequence delivers on the re-send, even after a restart.
        val reopened = FileBackedFreshnessStore.withoutRollbackDetection(file, provider, key)
        assertTrue(reopened.deliverIfFresh("ctx", "lane", 1, 0) { })
    }

    @Test
    fun acceptIsSingleWinnerAcrossInstancesSharingTheFile() {
        val file = tempDir().resolve("freshness.sealed")
        val instances = List(4) { FileBackedFreshnessStore.withoutRollbackDetection(file, provider, key) }
        val barrier = CyclicBarrier(instances.size)
        val wins = instances.map { store ->
            var won = false
            thread { barrier.await(); won = store.accept("ctx", "lane", 1, 0) } to { won }
        }
        wins.forEach { (t, _) -> t.join() }
        assertEquals(1, wins.count { (_, won) -> won() }, "exactly one instance may accept a given sequence")
    }
}
