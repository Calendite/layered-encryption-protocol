package org.layeredencryption

import platform.Foundation.NSRecursiveLock

actual class ProtocolLock {
    private val lock = NSRecursiveLock()

    actual fun <T> withLock(block: () -> T): T {
        lock.lock()
        return try {
            block()
        } finally {
            lock.unlock()
        }
    }
}
