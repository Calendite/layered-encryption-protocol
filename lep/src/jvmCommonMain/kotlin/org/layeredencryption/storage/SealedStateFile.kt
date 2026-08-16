package org.layeredencryption.storage

import dev.diagnostics.Diagnostics
import org.layeredencryption.Cascade
import org.layeredencryption.LepTag
import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameReader
import org.layeredencryption.FrameWriter
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.pairing.constantTimeEquals
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * The store on disk failed to parse or authenticate. Fail closed: no partial state is ever
 * returned. Recovery — deleting the file — is deliberately a manual operator action, because its
 * consequences differ by store: burned invites are the safe direction, a reset freshness store
 * re-opens replay acceptance.
 */
class StoreCorruptionException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * The store on disk is *older* than the [RevisionWitness]'s floor: somebody restored a stale
 * snapshot — the exact move that resurrects consumed invites and re-enables refused replays.
 * Fail closed until an operator decides what happened.
 */
class StoreRollbackException(message: String) : Exception(message)

/**
 * Where a store's latest committed revision is remembered, *outside* the store file, so a
 * restored stale snapshot is evident on the next load.
 *
 * The witness is evidence, not magic: place it where backups and restores do not reach (on
 * Android, keep store and witness under `noBackupFilesDir`, or split them across locations no
 * single restore covers). A restore that rolls back store and witness together is undetectable
 * from inside the filesystem — that limit is fundamental, and pretending otherwise would be
 * worse than stating it.
 */
interface RevisionWitness {
    /** The highest revision ever recorded, or null if nothing was recorded yet. */
    fun latest(): Long?

    /** Records [revision] as committed. MUST never lower the stored floor. */
    fun record(revision: Long)
}

/**
 * The default [RevisionWitness]: an 8-byte revision plus a MAC under the store key, written with
 * the same fsync-then-atomic-rename discipline as the store itself. A corrupt or forged witness
 * fails closed as [StoreCorruptionException].
 */
class FileRevisionWitness(
    private val file: Path,
    private val provider: CryptoProvider,
    key: ByteArray,
) : RevisionWitness {
    private val key = key.copyOf()

    override fun latest(): Long? {
        if (!Files.exists(file)) return null
        if (Files.size(file) > MAX_WITNESS_BYTES) {
            throw StoreCorruptionException("Revision witness at $file is implausibly large")
        }
        val bytes = Files.readAllBytes(file)
        try {
            val reader = FrameReader(bytes)
            val revisionBytes = reader.readBytes(8)
            val mac = reader.readBytes(64)
            require(!reader.hasRemaining()) { "Trailing bytes after the witness MAC" }
            if (!provider.hmacSha256(key, WITNESS_LABEL + revisionBytes).constantTimeEquals(mac)) {
                throw StoreCorruptionException("Revision witness MAC failed: $file")
            }
            return u64FromBytes(revisionBytes)
        } catch (e: StoreCorruptionException) {
            throw e
        } catch (e: Exception) {
            throw StoreCorruptionException("Revision witness unreadable: $file", e)
        }
    }

    override fun record(revision: Long) {
        val floor = latest() ?: 0L
        val target = maxOf(revision, floor)
        val revisionBytes = u64ToBytes(target)
        val bytes = FrameWriter()
            .putBytes(revisionBytes)
            .putBytes(provider.hmacSha256(key, WITNESS_LABEL + revisionBytes))
            .toByteArray()
        atomicWrite(file, bytes)
    }

    private companion object {
        val WITNESS_LABEL = "lep/storage/revision-witness/v1".encodeToByteArray()
        const val MAX_WITNESS_BYTES = 4096L
    }
}

/**
 * One durable, sealed, rollback-evident state blob: the engine under the file-backed stores
 * (RT-02/RT-03).
 *
 * - **Sealed at rest** with the library's own [Cascade] under an application-supplied key —
 *   from the platform keystore in production. The cleartext header (format, store kind,
 *   revision) is bound as AAD, so a spliced header fails authentication.
 * - **Crash-safe**: temp file → fsync → atomic rename → directory fsync. A crash leaves the old
 *   state or the new state, never a torn one; a leftover temp is deleted unread on next load.
 * - **Atomic across processes and instances**: every operation holds an OS [java.nio.channels.FileLock]
 *   on a sidecar lock file, plus a per-path in-process mutex (JVM file locks do not nest within
 *   one process). The single-winner guarantees the store interfaces demand live *here*, in the
 *   storage layer, not in callers.
 * - **Rollback-evident**: the revision is monotonic, sealed into the AAD, and mirrored to the
 *   [RevisionWitness] after each commit; a load below the witness floor throws
 *   [StoreRollbackException].
 */
internal class SealedStateFile(
    private val file: Path,
    private val provider: CryptoProvider,
    key: ByteArray,
    private val storeKind: String,
    private val witness: RevisionWitness?,
    private val namespace: ProtocolNamespace,
) {
    init {
        require(key.size == AT_REST_KEY_BYTES) {
            "The at-rest key must be $AT_REST_KEY_BYTES bytes, was ${key.size}"
        }
    }

    private val key = key.copyOf()
    private val lockFile = file.resolveSibling(file.fileName.toString() + ".lock")
    private val tempFile = file.resolveSibling(file.fileName.toString() + ".tmp")
    private val processLock =
        processLocks.computeIfAbsent(file.toAbsolutePath().normalize().toString()) { ReentrantLock() }

    internal class Loaded(val revision: Long, val state: ByteArray?)

    /**
     * Runs [block] holding both the in-process mutex and the OS file lock, handing it the loaded
     * state (null when the store has never been written). If [block] returns non-null, that state
     * is committed durably — fsync'd, renamed, witness advanced — before this returns.
     */
    internal fun <T> transact(block: (Loaded, commit: (ByteArray) -> Unit) -> T): T = processLock.withLock {
        Files.createDirectories(file.parent ?: file.toAbsolutePath().parent)
        FileChannel.open(
            lockFile,
            StandardOpenOption.CREATE, StandardOpenOption.WRITE,
        ).use { lockChannel ->
            lockChannel.lock().use {
                val loaded = load()
                try {
                    block(loaded) { newState -> commit(newState, loaded.revision + 1) }
                } finally {
                    loaded.state?.fill(0)
                }
            }
        }
    }

    private fun load(): Loaded {
        Files.deleteIfExists(tempFile) // an incomplete write that never became current
        val floor = witness?.latest()
        if (!Files.exists(file)) {
            if (floor != null && floor > 0L) {
                Diagnostics.error(LepTag.STORAGE) { "$storeKind store is missing but its witness has seen revision $floor — rollback or deletion" }
                throw StoreRollbackException(
                    "$storeKind store at $file is missing but its witness has seen revision $floor",
                )
            }
            return Loaded(0L, null)
        }

        val size = Files.size(file)
        if (size > MAX_STORE_BYTES) {
            throw StoreCorruptionException("$storeKind store at $file is $size bytes; the cap is $MAX_STORE_BYTES")
        }
        val bytes = Files.readAllBytes(file)
        val header: ByteArray
        val sealed: ByteArray
        val revision: Long
        try {
            val reader = FrameReader(bytes)
            header = reader.readBytes(MAX_HEADER_BYTES)
            sealed = reader.readBytes(Int.MAX_VALUE)
            require(!reader.hasRemaining()) { "Trailing bytes after the sealed state" }
            val headerReader = FrameReader(header)
            val magic = headerReader.readBytes(MAGIC.size)
            require(magic.contentEquals(MAGIC)) { "Bad magic" }
            val kind = headerReader.readBytes(MAX_KIND_BYTES).decodeToString()
            require(kind == storeKind) { "Store kind is '$kind', expected '$storeKind'" }
            revision = u64FromBytes(headerReader.readBytes(8))
            require(!headerReader.hasRemaining()) { "Trailing bytes after the header" }
        } catch (e: Exception) {
            // Frame-parser messages can embed bytes decoded from the file, so the exception rides
            // the unsafe slot: dropped unless the sink opted in at install time.
            Diagnostics.error(LepTag.STORAGE, unsafeThrowable = e) { "$storeKind store is unreadable — corruption" }
            throw StoreCorruptionException("$storeKind store at $file is unreadable", e)
        }

        val state = try {
            Cascade.open(provider, key, sealed, aad = header, namespace = namespace)
        } catch (e: Exception) {
            Diagnostics.error(LepTag.STORAGE, unsafeThrowable = e) { "$storeKind store failed authentication — corruption or the wrong at-rest key" }
            throw StoreCorruptionException("$storeKind store at $file failed authentication", e)
        }
        if (floor != null && revision < floor) {
            state.fill(0)
            Diagnostics.error(LepTag.STORAGE) { "$storeKind store is at revision $revision but its witness has seen $floor — a restored stale snapshot" }
            throw StoreRollbackException(
                "$storeKind store at $file is at revision $revision but its witness has seen $floor",
            )
        }
        return Loaded(revision, state)
    }

    private fun commit(state: ByteArray, revision: Long) {
        val header = FrameWriter()
            .putBytes(MAGIC)
            .putBytes(storeKind.encodeToByteArray())
            .putBytes(u64ToBytes(revision))
            .toByteArray()
        val sealed = Cascade.seal(provider, key, state, aad = header, namespace = namespace)
        state.fill(0)
        atomicWrite(tempFile, FrameWriter().putBytes(header).putBytes(sealed).toByteArray(), file)
        witness?.record(revision)
    }

    internal companion object {
        val MAGIC = "lep-sealed-store/v1".encodeToByteArray()
        const val MAX_HEADER_BYTES = 256
        const val MAX_KIND_BYTES = 64
        const val AT_REST_KEY_BYTES = 32

        /**
         * Far above any real store (invites and watermarks are kilobytes), far below anything
         * that could hurt to read: a corrupt or locally manipulated file fails on size before a
         * byte of it is loaded.
         */
        const val MAX_STORE_BYTES = 16L * 1024 * 1024

        val processLocks = ConcurrentHashMap<String, ReentrantLock>()
    }
}

/** fsync-then-atomic-rename write; when [renameTo] is given, [target] is the temp staging path. */
private fun atomicWrite(target: Path, bytes: ByteArray, renameTo: Path? = null) {
    val stage = if (renameTo != null) target else target.resolveSibling(target.fileName.toString() + ".tmp")
    val destination = renameTo ?: target
    FileChannel.open(
        stage,
        StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING,
    ).use { channel ->
        // The API permits short writes; a single unlooped write could stage a truncated store.
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) channel.write(buffer)
        channel.force(true)
    }
    Files.move(stage, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    fsyncDirectory(destination.toAbsolutePath().parent)
}

/** Directory fsync makes the rename itself durable; unsupported filesystems degrade gracefully. */
private fun fsyncDirectory(directory: Path?) {
    if (directory == null) return
    try {
        FileChannel.open(directory, StandardOpenOption.READ).use { it.force(true) }
    } catch (_: Exception) {
        // Some platforms cannot open a directory channel; the rename is still atomic there.
    }
}

internal fun u64ToBytes(value: Long): ByteArray =
    ByteArray(8) { i -> ((value ushr (56 - 8 * i)) and 0xFF).toByte() }

internal fun u64FromBytes(bytes: ByteArray): Long {
    require(bytes.size == 8) { "Expected 8 bytes, got ${bytes.size}" }
    var value = 0L
    for (byte in bytes) value = (value shl 8) or (byte.toLong() and 0xFF)
    return value
}

internal fun u32ToBytes(value: Int): ByteArray =
    ByteArray(4) { i -> ((value ushr (24 - 8 * i)) and 0xFF).toByte() }

internal fun u32FromBytes(bytes: ByteArray): Int {
    require(bytes.size == 4) { "Expected 4 bytes, got ${bytes.size}" }
    var value = 0
    for (byte in bytes) value = (value shl 8) or (byte.toInt() and 0xFF)
    return value
}
