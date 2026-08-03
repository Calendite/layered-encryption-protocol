package org.layeredencryption

import java.util.concurrent.locks.ReentrantLock

actual class ProtocolLock {
    private val lock = ReentrantLock()

    actual fun <T> withLock(block: () -> T): T {
        lock.lock()
        return try {
            block()
        } finally {
            lock.unlock()
        }
    }
}
