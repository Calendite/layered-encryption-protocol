package org.layeredencryption

import org.layeredencryption.invite.InviteStore
import org.layeredencryption.storage.FileBackedInviteStore
import java.nio.file.Files

/**
 * The file-backed production store passes the exact contract suite the in-memory reference
 * passes — single-winner consume, tombstoned resurrection attempts, idempotent removal — with
 * real files underneath.
 */
class FileBackedInviteStoreConformanceTest : InviteStoreConformanceTest() {

    private val provider: CryptoProvider = BouncyCastleCryptoProvider()

    override fun createStore(): InviteStore {
        val directory = Files.createTempDirectory("lep-invite-store")
        return FileBackedInviteStore.withoutRollbackDetection(directory.resolve("invites.sealed"), provider, provider.randomBytes(32))
    }
}
